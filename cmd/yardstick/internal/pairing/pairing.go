// Package pairing binds labels to a subject and pairs them with what each setup reported. A label
// pairs a match when their vulnerabilities share an alias group and every field the label's purl
// states equals the match package's. A label on an advisory id pairs only a match grype reported
// under exactly that id or one of the label's aliases, and decides it over labels on the CVEs the advisory names. Candidate and reference matches are one match when they are
// on the same package and alias group. The gate's vulnerabilities filter is the one thing to
// configure: what it drops is never paired.
package pairing

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

// Package is a package of the subject's scanned SBOM.
type Package = subject.Package

// Identity is what makes a candidate match and a reference match the same match.
type Identity struct {
	PackageID string
	Group     string
}

// Match is one package and alias group some setup reported on the subject.
type Match struct {
	Identity
	// Vulnerability is the id grype reported: the candidate's, else the reference's.
	Vulnerability string
	// Addresses are the alias groups the match pairs labels in: its own, or for an advisory
	// each CVE it names. A label on the advisory itself pairs a match reporting exactly that id.
	Addresses []string
	Package   Package
	// MatchType is how grype found the match: the vulnerability's namespace and the match
	// details' types, as the first setup to report it gives them.
	MatchType string
	// Matcher is the grype matcher that made the match, e.g. "go-module-matcher", and Location the
	// file the package was found in; both as the first setup to report it gives them. Location is
	// what tells apart two packages with one purl, such as the same stdlib in two binaries.
	Matcher  string
	Location string
	// Aliases are every id either setup reported for the match, its related ids included.
	Aliases []string
	// Details are what each setup's grype said about the match, from its first row.
	Details map[string]*Detail
	// Rows are the indexes of the setup's grype matches that are this match.
	Rows map[string][]int
	// Paired are the labels pairing the match; Label is the most specific of them.
	Paired []*Bound
	Label  *Bound
	// Verdict is tp or fp, or empty when the match is unlabeled: no label, only unclear, or labels
	// that give different verdicts.
	Verdict claimsv1.Verdict

	pkg purl.Fields
	// reported are the ids grype gave as the match's vulnerability in any of its rows
	reported []string
}

// In says whether a setup reported the match.
func (m *Match) In(setup string) bool {
	return len(m.Rows[setup]) > 0
}

// Unlabeled says whether the match counts toward no TP or FP.
func (m *Match) Unlabeled() bool {
	return m.Verdict == ""
}

// Bound is a label that applies to the subject.
type Bound struct {
	claims.Label
	// Fields are what the label's purl states; zero for a label with no package.
	Fields purl.Fields
	// Present says whether a package of the subject has the fields the label states; a label
	// with no package is present.
	Present bool
	// Matches are the matches the label pairs.
	Matches []*Match
}

// Specificity orders labels pairing one match: subject files over global/, then more stated
// purl fields.
func (b *Bound) Specificity() int {
	n := len(b.Fields.Stated())
	if !b.Global {
		n += 1000
	}
	return n
}

// PairedIn says whether a match the setup reported pairs the label.
func (b *Bound) PairedIn(setup string) bool {
	for _, m := range b.Matches {
		if m.In(setup) {
			return true
		}
	}
	return false
}

// Subject is what pairing reads for one subject.
type Subject struct {
	Name     string
	Packages []Package
	// Filtered is set for a subject with packages.keepTypes: only labels on its packages apply.
	Filtered bool
	Labels   []claims.Label
	// Scans are each setup's grype output; a gate with no reference has no reference scan.
	Scans map[string]*models.Document
	// Vulnerabilities is the gate's filter, nil for none: the matches and labels it drops are left
	// out, and a match keeps its rows' indexes into the scans.
	Vulnerabilities *gatefile.Vulnerabilities
}

// Result is a subject's matches across both setups and the labels that apply to it.
type Result struct {
	Matches  []*Match
	Labels   []*Bound
	Packages []Package
	// Skipped says what did not apply and why, for the report.
	Skipped  []string
	Warnings []string

	aliases *Aliases
	pkgs    []purl.Fields
	filter  *gatefile.Vulnerabilities
	// years are each alias group's CVE year, from every reported match, for the filter
	years   map[string]int
	dropped int
}

// Pair binds the subject's labels and pairs them with both setups' matches. The aliases must
// already hold every id of the gate's scans and labels.
func Pair(a *Aliases, s Subject) *Result {
	defer log.Timed("pairing %s", s.Name)()
	r := &Result{aliases: a, Packages: s.Packages, filter: s.Vulnerabilities, years: map[string]int{}}
	for _, p := range s.Packages {
		r.pkgs = append(r.pkgs, purl.Package(p.PURL, p.Version))
	}
	// matches first: a label with no year of its own takes its year from the matches
	r.matches(s)
	r.bind(s)
	for _, m := range r.Matches {
		r.pair(m)
	}
	r.log(s.Name)
	return r
}

// log reports how the subject's labels and matches paired.
func (r *Result) log(name string) {
	paired, unlabeled, unseen := 0, 0, 0
	for _, m := range r.Matches {
		if m.Unlabeled() {
			unlabeled++
		}
		if len(m.Paired) > 0 {
			paired++
		}
	}
	for _, b := range r.Labels {
		if !b.Present {
			unseen++
		}
		log.Tracef("subject %s: label %s (%s) paired %d matches", name, b.Key(), b.Verdict, len(b.Matches))
	}
	log.Debugf("subject %s: %d matches, %d paired with a label, %d unlabeled; %d labels, %d not seen in its packages; the vulnerabilities filter dropped %d rows and labels", name, len(r.Matches), paired, unlabeled, len(r.Labels), unseen, r.dropped)
}

// bind decides which labels apply: a subject's own labels, except on a filtered subject where only
// labels on a package it kept do, and a global label when the subject has its package.
func (r *Result) bind(s Subject) {
	noPackage := 0
	for _, l := range s.Labels {
		if !r.keepsLabel(l) {
			r.dropped++
			continue
		}
		b := &Bound{Label: l, Present: true}
		if l.Package != "" {
			f, err := purl.Label(l.Package)
			if err != nil {
				r.Warnings = append(r.Warnings, fmt.Sprintf("subject %s: %s: label %s has a package that is not a purl: %v", s.Name, l.File, l.Key(), err))
				continue
			}
			b.Fields, b.Present = f, r.present(f)
		}
		switch {
		case s.Filtered && l.Package == "":
			noPackage++
			continue
		case (s.Filtered || l.Global) && !b.Present:
			continue
		}
		r.Labels = append(r.Labels, b)
	}
	if noPackage > 0 {
		r.Skipped = append(r.Skipped, fmt.Sprintf("subject %s filters its packages, so its %d image-level label(s) do not apply", s.Name, noPackage))
	}
}

func (r *Result) present(f purl.Fields) bool {
	for _, p := range r.pkgs {
		if f.Matches(p) {
			return true
		}
	}
	return false
}

// matches merges both setups' grype matches into matches by identity.
func (r *Result) matches(s Subject) {
	byID := map[Identity]*Match{}
	for _, setup := range []string{gatefile.Candidate, gatefile.Reference} {
		doc := s.Scans[setup]
		if doc == nil {
			continue
		}
		for i, gm := range doc.Matches {
			r.noteYears(gm)
			if !r.keeps(gm) {
				r.dropped++
				continue
			}
			addresses := r.addresses(gm)
			group := gm.Vulnerability.ID
			if len(addresses) == 1 {
				group = addresses[0]
			}
			id := Identity{PackageID: gm.Artifact.ID, Group: group}
			m, ok := byID[id]
			if !ok {
				m = &Match{Identity: id, Vulnerability: gm.Vulnerability.ID, Rows: map[string][]int{}, Details: map[string]*Detail{}, MatchType: matchType(gm),
					Matcher: matcher(gm), Location: location(gm.Artifact),
					Package: Package{ID: gm.Artifact.ID, Name: gm.Artifact.Name, Version: gm.Artifact.Version, Type: string(gm.Artifact.Type), PURL: gm.Artifact.PURL},
					pkg:     purl.Package(gm.Artifact.PURL, gm.Artifact.Version)}
				byID[id] = m
				r.Matches = append(r.Matches, m)
			}
			if !m.In(setup) {
				m.Details[setup] = detail(gm, doc)
			}
			m.Rows[setup] = append(m.Rows[setup], i)
			m.Addresses = union(m.Addresses, addresses...)
			m.reported = union(m.reported, gm.Vulnerability.ID)
			aliases := []string{gm.Vulnerability.ID}
			for _, rel := range gm.RelatedVulnerabilities {
				aliases = append(aliases, rel.ID)
			}
			m.Aliases = union(m.Aliases, aliases...)
		}
	}
	for _, m := range r.Matches {
		if len(m.Addresses) > 1 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("subject %s: %s on %s addresses %d CVEs (%s); it pairs a label on any of them", s.Name, m.Vulnerability, m.Package.Name+"@"+m.Package.Version, len(m.Addresses), strings.Join(m.Addresses, ", ")))
		}
	}
	sort.SliceStable(r.Matches, func(i, j int) bool {
		a, b := r.Matches[i], r.Matches[j]
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		return a.PackageID < b.PackageID
	})
}

// matchType is a grype match's namespace and its distinct match types, e.g. "nvd:cpe cpe-match".
func matchType(gm models.Match) string {
	var types []string
	for _, d := range gm.MatchDetails {
		if !slices.Contains(types, d.Type) {
			types = append(types, d.Type)
		}
	}
	return strings.TrimSpace(gm.Vulnerability.Namespace + " " + strings.Join(types, "+"))
}

// matcher is a grype match's distinct matchers, e.g. "go-module-matcher".
func matcher(gm models.Match) string {
	var out []string
	for _, d := range gm.MatchDetails {
		if !slices.Contains(out, d.Matcher) {
			out = append(out, d.Matcher)
		}
	}
	return strings.Join(out, "+")
}

// location is the path of a package's primary evidence, else of its first location.
func location(p models.Package) string {
	for _, l := range p.Locations {
		if l.Annotations[pkg.EvidenceAnnotationKey] == pkg.PrimaryEvidenceAnnotation {
			return l.RealPath
		}
	}
	if len(p.Locations) > 0 {
		return p.Locations[0].RealPath
	}
	return ""
}

// addresses are the alias groups a reported match pairs labels in: its vulnerability's group, or
// for an advisory, the group of each id the reporting setup relates to it.
func (r *Result) addresses(gm models.Match) []string {
	if g := r.aliases.Group(gm.Vulnerability.ID); g != "" {
		return []string{g}
	}
	var groups []string
	for _, rel := range gm.RelatedVulnerabilities {
		if g := r.aliases.Group(rel.ID); g != "" {
			groups = append(groups, g)
		}
	}
	out := union(nil, groups...)
	if len(out) == 0 {
		// an advisory naming nothing a label can be about is its own group, and pairs nothing
		return []string{gm.Vulnerability.ID}
	}
	return out
}

// pair finds the labels pairing a match and decides its verdict from the most specific. A label on
// the advisory the match reported judges exactly that match, so when one pairs, only advisory
// labels decide; labels on the CVEs it names still pair, and decide only when no advisory label does.
func (r *Result) pair(m *Match) {
	var exact []*Bound
	for _, b := range r.Labels {
		if !r.pairs(b, b.Fields, m) {
			continue
		}
		m.Paired = append(m.Paired, b)
		b.Matches = append(b.Matches, m)
		if r.aliases.advisory(b.Vulnerability) {
			exact = append(exact, b)
		}
	}
	if len(m.Paired) == 0 {
		return
	}
	deciding := m.Paired
	if len(exact) > 0 {
		deciding = exact
	}
	best := deciding[0]
	verdicts := map[claimsv1.Verdict]bool{}
	for _, b := range deciding {
		if b.Specificity() > best.Specificity() {
			best = b
		}
	}
	for _, b := range deciding {
		if b.Specificity() == best.Specificity() {
			verdicts[b.Verdict] = true
		}
	}
	m.Label = best
	if len(verdicts) == 1 && best.Verdict != claimsv1.Unclear {
		m.Verdict = best.Verdict
	}
}

// pairs says whether a label, stating fields f, pairs a match.
func (r *Result) pairs(b *Bound, f purl.Fields, m *Match) bool {
	if r.aliases.advisory(b.Vulnerability) {
		// an advisory has no alias group: its label pairs a match reporting exactly that id, or
		// exactly one of its aliases (the CVE --by-cve reports it as)
		if !f.Matches(m.pkg) {
			return false
		}
		if slices.Contains(m.reported, b.Vulnerability) {
			return true
		}
		for _, a := range b.Aliases {
			if slices.Contains(m.reported, a) {
				return true
			}
		}
		return false
	}
	g := r.aliases.Group(b.Vulnerability)
	shared := false
	for _, a := range m.Addresses {
		if a == g {
			shared = true
			break
		}
	}
	return shared && f.Matches(m.pkg)
}

// Relaxed pairs a label with one stated field dropped: the near-miss probe. It returns the first
// match, in match order, that the relaxed label pairs and the setup reported.
func (r *Result) Relaxed(b *Bound, field, setup string) *Match {
	f := b.Fields.Without(field)
	for _, m := range r.Matches {
		if m.In(setup) && r.pairs(b, f, m) {
			return m
		}
	}
	return nil
}

// RelatedIDs is each id the matches report with every id reported beside it, their aliases, as
// Vocabulary.CheckScanned reads them.
func RelatedIDs(ms []*Match) map[string][]string {
	out := map[string][]string{}
	for _, m := range ms {
		out[m.Vulnerability] = union(out[m.Vulnerability], m.Aliases...)
	}
	return out
}

// union adds what b has that a doesn't to a, sorted. a has no duplicates (it is union's own output).
func union(a []string, b ...string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			a = append(a, v)
		}
	}
	sort.Strings(a)
	return a
}
