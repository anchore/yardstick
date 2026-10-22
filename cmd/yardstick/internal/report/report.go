// Package report builds a run's verdict set and renders it. The set is computed once, from the
// scans, the labels and the check evaluation; renderers only read it, so no renderer, flag or
// details level changes a state, a count or the exit code.
package report

import (
	"fmt"
	"slices"
	"sort"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/lookup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
)

// Set is a run's verdict set: every gate, check, row and cause.
type Set struct {
	Gates   []Gate  `json:"gates"`
	Summary Summary `json:"summary"`
	// Focus is set when the gates' rows were narrowed to it, so a narrowed document always says so.
	Focus *Focus `json:"focus,omitempty"`
}

// Summary is the run's last line and exit code.
type Summary struct {
	Total    int    `json:"total"`
	Failed   int    `json:"failed"`
	Line     string `json:"line"`
	ExitCode int    `json:"exitCode"`
}

// Gate is one gate's verdict.
type Gate struct {
	Name    string         `json:"name"`
	Path    string         `json:"path"`
	Outcome analysis.State `json:"outcome"`
	// Undecided is the gate's policy, and Passed whether the gate passes under it: what CI reads.
	Undecided string `json:"undecided"`
	Passed    bool   `json:"passed"`
	// Message explains an outcome no check gave, such as scans made for another gate file.
	Message  string            `json:"message,omitempty"`
	Header   Header            `json:"header"`
	Warnings []string          `json:"warnings,omitempty"`
	Checks   []analysis.Check  `json:"checks"`
	Effects  []analysis.Effect `json:"effects,omitempty"`
	Subjects []Subject         `json:"subjects"`
}

// Subject is one subject's counts and rows.
type Subject struct {
	Name   string            `json:"name"`
	Frozen bool              `json:"frozen,omitempty"`
	Counts map[string]Counts `json:"counts"`
	// Matches are every match either setup reported, by id.
	Matches []Match `json:"matches"`
	// Misses are the tp labels no candidate match pairs, each with one cause.
	Misses []Miss `json:"misses,omitempty"`
	// Loose are fp labels that leave out a field their matches differ in.
	Loose []Loose `json:"loose,omitempty"`
}

// Counts are one setup's counts on a subject, unlabeled matches left out of all three ratios.
type Counts struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	Unlabeled int     `json:"unlabeled"`
	Labels    int     `json:"tpLabels"`
	Satisfied int     `json:"tpLabelsPaired"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// Match is one match row.
type Match struct {
	ID string `json:"id"`
	// Row names the match across the gate, stable across re-scoring the same scans: what the
	// label UI, claims agent propose and research jobs refer to it by.
	Row           string `json:"row"`
	Vulnerability string `json:"vulnerability"`
	// Group is the alias group the match is on, and Aliases every id either setup reported for it.
	Group   string   `json:"group"`
	Aliases []string `json:"aliases,omitempty"`
	Package string   `json:"package"`
	// SourcePackage is the package the fix ships in, e.g. glibc for libc6.
	SourcePackage string `json:"sourcePackage"`
	// MatchType is how grype found the match, e.g. "nvd:cpe cpe-match".
	MatchType string `json:"matchType,omitempty"`
	// Matcher is the grype matcher that made the match, e.g. "go-module-matcher".
	Matcher string `json:"matcher,omitempty"`
	// Location is the file the package was found in. It tells apart two packages with one purl,
	// such as the same stdlib in two binaries.
	Location    string `json:"location,omitempty"`
	InCandidate bool   `json:"inCandidate"`
	InReference bool   `json:"inReference"`
	// Verdict is tp or fp, empty when the match is unlabeled.
	Verdict claimsv1.Verdict `json:"verdict,omitempty"`
	Label   *LabelRef        `json:"label,omitempty"`
	// Direction is fixed, introduced or review for a match one setup reports; empty for one both
	// report. Renderers print it only under checks that read the reference.
	Direction string `json:"direction,omitempty"`
	// Candidate and Reference are the record each setup's grype matched, for the setups that
	// reported the match.
	Candidate *pairing.Detail `json:"candidate,omitempty"`
	Reference *pairing.Detail `json:"reference,omitempty"`
	// CandidateStatus and ReferenceStatus are each DB's record status for the vulnerability
	// (active, rejected, not-in-db), and NewInCandidate says the reference DB has no record of it
	// under any id; set only for a match one setup reported, when the DBs were looked up.
	CandidateStatus string `json:"candidateStatus,omitempty"`
	ReferenceStatus string `json:"referenceStatus,omitempty"`
	NewInCandidate  bool   `json:"newInCandidate,omitempty"`
	// CandidateRecords and ReferenceRecords are what the DB of the setup that did not report the
	// match has for its ids and package.
	CandidateRecords []lookup.Affected `json:"candidateRecords,omitempty"`
	ReferenceRecords []lookup.Affected `json:"referenceRecords,omitempty"`
	// Why is the computed reason the setups disagree, for a match one setup reported in a gate
	// with a reference.
	Why *Why `json:"why,omitempty"`
}

// Directions of a delta.
const (
	Fixed      = "fixed"
	Introduced = "introduced"
	Review     = "review"
)

// LabelRef is the label deciding a match, or the one a row is about.
type LabelRef struct {
	Package       string           `json:"package,omitempty"`
	Vulnerability string           `json:"vulnerability"`
	Verdict       claimsv1.Verdict `json:"verdict"`
	File          string           `json:"file"`
	Sources       []string         `json:"sources"`
}

// Causes of a miss, in the order they are tried.
const (
	NearMiss        = "NEAR MISS"
	MatchingFailure = "MATCHING FAILURE"
	MissingPackage  = "MISSING PACKAGE"
	NoCause         = "NO CAUSE"
	LooseClaim      = "LOOSE CLAIM"
)

// Miss is a tp label no candidate match pairs.
type Miss struct {
	Label LabelRef `json:"label"`
	// InReference says the reference pairs it: a new false negative.
	InReference bool   `json:"inReference"`
	Cause       string `json:"cause"`
	Where       string `json:"where"`
	// NearMiss is every one-field relaxation of the label that pairs a candidate match.
	NearMiss []Relaxation `json:"nearMiss,omitempty"`
}

// Relaxation is a label with one stated field dropped, and the match it then pairs.
type Relaxation struct {
	Field string `json:"field"`
	Match string `json:"match"`
	// Package is the paired match's package purl.
	Package string `json:"package"`
}

// Loose is an fp label that leaves out a field its matches carry different values of.
type Loose struct {
	Label   LabelRef `json:"label"`
	Field   string   `json:"field"`
	Matches []string `json:"matches"`
}

// where to look for each cause
var where = map[string]string{
	NearMiss:        "the label or the scanner's purl",
	MatchingFailure: "the matcher or the DB",
	MissingPackage:  "syft or the SBOM",
	NoCause:         "",
}

// fields a probe drops or a loose fp label may leave out
const (
	fieldVersion = "version"
	fieldDistro  = "qualifier:distro"
)

// the fields the near-miss probe drops, one at a time
var probed = []string{"type", "namespace", "name", fieldVersion, fieldDistro}

// SubjectInput is one subject's pairing, for its rows.
type SubjectInput struct {
	Name   string
	Frozen bool
	Result *pairing.Result
	// Lookups are the gate's DB lookups by the setup whose DB was searched; nil for a run made
	// before them.
	Lookups map[string]*lookup.File
}

// Build makes a gate's verdict from its evaluation and pairing.
func Build(g *gatefile.Gate, header Header, eval analysis.Gate, subjects []SubjectInput, warnings []string) Gate {
	out := Gate{Name: g.Name, Path: g.Path, Outcome: eval.Outcome, Undecided: g.Undecided, Header: header,
		Warnings: warnings, Checks: eval.Checks, Effects: eval.Effects}
	out.Passed = passes(out.Outcome, g.Undecided)
	for _, s := range subjects {
		out.Subjects = append(out.Subjects, subjectRows(s, g.Reference != nil))
	}
	return out
}

// Stale is a gate whose scans were made for another version of its file: failing until it is run
// again, with no check computed. It fails under either undecided policy, since that policy is for
// checks unlabeled deltas leave open, and these scans do not belong to the gate at all.
func Stale(g *gatefile.Gate, header Header, message string) Gate {
	return Gate{Name: g.Name, Path: g.Path, Outcome: analysis.Fail, Undecided: g.Undecided, Header: header, Message: message}
}

func passes(o analysis.State, policy string) bool {
	return o == analysis.Pass || (o == analysis.Undecided && policy == gatefile.UndecidedPass)
}

// Summarize is the run's summary line and exit code: 0 when every gate passes under its policy,
// 1 otherwise. Load and input errors exit 2 before any of this.
func Summarize(gates []Gate) Set {
	s := Set{Gates: gates, Summary: Summary{Total: len(gates)}}
	for _, g := range gates {
		if !g.Passed {
			s.Summary.Failed++
		}
	}
	if s.Summary.Failed == 0 {
		s.Summary.Line = fmt.Sprintf("PASSED %d of %d gates", s.Summary.Total, s.Summary.Total)
	} else {
		s.Summary.Line = fmt.Sprintf("FAILED %d of %d gates", s.Summary.Failed, s.Summary.Total)
		s.Summary.ExitCode = 1
	}
	return s
}

func subjectRows(s SubjectInput, compared bool) Subject {
	r := s.Result
	out := Subject{Name: s.Name, Frozen: s.Frozen, Counts: map[string]Counts{}}
	for _, setup := range []string{gatefile.Candidate, gatefile.Reference} {
		st := analysis.Counts(r, setup)
		out.Counts[setup] = Counts{TP: st.TP, FP: st.FP, Unlabeled: st.Unlabeled, Labels: st.Labels, Satisfied: st.Satisfied,
			Precision: st.Precision(), Recall: st.Recall(), F1: st.F1()}
	}
	for _, m := range r.Matches {
		id := analysis.MatchID(m)
		row := Match{ID: id, Row: pairing.RowID(s.Name, id), Vulnerability: m.Vulnerability, Group: m.Group, Aliases: m.Aliases, Package: pkgName(m.Package),
			SourcePackage: m.SourcePackage(), MatchType: m.MatchType, Matcher: m.Matcher, Location: m.Location, InCandidate: m.In(gatefile.Candidate),
			InReference: m.In(gatefile.Reference), Verdict: m.Verdict, Direction: direction(m),
			Candidate: m.Details[gatefile.Candidate], Reference: m.Details[gatefile.Reference]}
		if m.Label != nil {
			ref := labelRef(m.Label)
			row.Label = &ref
		}
		if compared && row.InCandidate != row.InReference {
			explain(&row, m, s.Lookups)
		}
		out.Matches = append(out.Matches, row)
	}
	out.Misses = misses(r)
	out.Loose = loose(r)
	return out
}

func pkgName(p pairing.Package) string {
	if p.PURL != "" {
		return p.PURL
	}
	return p.Name + "@" + p.Version
}

// direction is fixed for a candidate-added tp or a candidate-dropped fp, introduced for a
// candidate-added fp or a candidate-dropped tp, and review for an unlabeled delta.
func direction(m *pairing.Match) string {
	cand, ref := m.In(gatefile.Candidate), m.In(gatefile.Reference)
	if cand == ref {
		return ""
	}
	switch {
	case m.Unlabeled():
		return Review
	case (m.Verdict == claimsv1.TP) == cand:
		return Fixed
	}
	return Introduced
}

func labelRef(b *pairing.Bound) LabelRef {
	ref := LabelRef{Package: b.Package, Vulnerability: b.Vulnerability, Verdict: b.Verdict, File: b.File}
	for _, h := range b.Held {
		ref.Sources = append(ref.Sources, h.Source+": "+string(h.Verdict))
	}
	return ref
}

// misses are the tp labels no candidate match pairs, each with its cause. The probe only reports:
// it never pairs a label it relaxed.
func misses(r *pairing.Result) []Miss {
	var out []Miss
	for _, b := range r.Labels {
		if b.Verdict != claimsv1.TP || b.PairedIn(gatefile.Candidate) {
			continue
		}
		miss := Miss{Label: labelRef(b), InReference: b.PairedIn(gatefile.Reference)}
		for _, field := range b.Fields.Stated() {
			if !slices.Contains(probed, field) {
				continue
			}
			if m := r.Relaxed(b, field, gatefile.Candidate); m != nil {
				miss.NearMiss = append(miss.NearMiss, Relaxation{Field: field, Match: analysis.MatchID(m), Package: pkgName(m.Package)})
			}
		}
		switch {
		case len(miss.NearMiss) > 0:
			miss.Cause = NearMiss
		case b.Package == "" || (b.Present && !matchedOn(r, b)):
			miss.Cause = MatchingFailure
		case !b.Present:
			miss.Cause = MissingPackage
		default:
			miss.Cause = NoCause
		}
		miss.Where = where[miss.Cause]
		out = append(out, miss)
	}
	return out
}

// matchedOn says whether the candidate reported any match on a package the label states.
func matchedOn(r *pairing.Result, b *pairing.Bound) bool {
	for _, m := range r.Matches {
		if m.In(gatefile.Candidate) && b.Fields.Matches(purl.Package(m.Package.PURL, m.Package.Version)) {
			return true
		}
	}
	return false
}

// loose finds fp labels that leave out a field (version or distro) their matches carry more than
// one value of: the label suppresses matches across versions it may not have meant to.
func loose(r *pairing.Result) []Loose {
	var out []Loose
	for _, b := range r.Labels {
		if b.Verdict != claimsv1.FP || len(b.Matches) < 2 {
			continue
		}
		for _, field := range []string{fieldVersion, fieldDistro} {
			if slices.Contains(b.Fields.Stated(), field) {
				continue
			}
			values := map[string]bool{}
			var ids []string
			for _, m := range b.Matches {
				f := purl.Package(m.Package.PURL, m.Package.Version)
				v := f.Version
				if field != fieldVersion {
					v = f.Qualifiers["distro"]
				}
				values[v] = true
				ids = append(ids, analysis.MatchID(m))
			}
			if len(values) > 1 {
				sort.Strings(ids)
				out = append(out, Loose{Label: labelRef(b), Field: field, Matches: ids})
			}
		}
	}
	return out
}
