// Package migrate converts anchore/vulnerability-match-labels into a claims corpus. Each label's
// package type comes from the image's SBOM, which must already be in the corpus; an advisory id
// becomes the CVEs grype's DB says it names. Every input label is reported with the corpus file and
// key it became, or why it was not converted.
package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// Justifications migration writes. vulnerability-match-labels never recorded why a call was made.
const (
	NotRecorded      = "not-recorded"
	LabelersDisagree = "labelers-disagree"
	NotAssessed      = "not-assessed"
)

// Outcome is what became of one input label.
type Outcome string

const (
	Migrated  Outcome = "migrated"            // written on the id it named
	Carried   Outcome = "advisory-carried"    // an advisory naming one CVE, written on that CVE
	FannedOut Outcome = "advisory-fanned-out" // an advisory naming several CVEs, unclear on each

	// not converted: no package type can be found for the label
	NoPackage  Outcome = "no-package"          // matched by fullentry_fields, with no package
	NoSBOM     Outcome = "no-sbom"             // the corpus holds no SBOM for the image
	NotInSBOM  Outcome = "package-not-in-sbom" // no artifact with the label's name and version
	NoPURL     Outcome = "package-has-no-purl" // the artifacts found carry no purl to label
	NoCVE      Outcome = "advisory-names-no-cve"
	Refused    Outcome = "refused" // the label writer refuses it
	Unreadable Outcome = "unreadable"
)

// Converted says whether labels were written for the input label.
func (o Outcome) Converted() bool {
	return o == Migrated || o == Carried || o == FannedOut
}

// Lookup says which ids each advisory names, by advisory id. An advisory it does not know is
// absent from the answer.
type Lookup func(ctx context.Context, advisories []string) (map[string][]string, error)

// ParseGrypeSearch reads `grype db search vuln <id>... -o json` as a Lookup's answer: each id
// with the union of its records' aliases.
func ParseGrypeSearch(data []byte) (map[string][]string, error) {
	var records []struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
	}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("unexpected grype db search output: %w", err)
	}
	out := map[string][]string{}
	for _, r := range records {
		out[r.ID] = append(out[r.ID], r.Aliases...)
	}
	return out, nil
}

// Entry is one input label in the report.
type Entry struct {
	Source        string   `json:"source"` // the file it was read from, relative to the labels root
	ID            string   `json:"id"`
	Image         string   `json:"image"`
	Package       string   `json:"package,omitempty"` // name@version
	Vulnerability string   `json:"vulnerability"`
	Verdict       string   `json:"verdict"`
	Outcome       Outcome  `json:"outcome"`
	Reason        string   `json:"reason,omitempty"`
	Became        []Output `json:"became,omitempty"`
}

// Output is a corpus label an input label contributed to, as it was written.
type Output struct {
	File          string         `json:"file"`
	Package       string         `json:"package"`
	Vulnerability string         `json:"vulnerability"`
	Verdict       labels.Verdict `json:"verdict"`
}

// Result is a migration: the labels to write and the report.
type Result struct {
	Placed  []labels.Placed
	Entries []Entry
}

// Counts is the number of input labels per outcome.
func (r *Result) Counts() map[Outcome]int {
	out := map[Outcome]int{}
	for _, e := range r.Entries {
		out[e.Outcome]++
	}
	return out
}

// Unconverted are the input labels nothing was written for.
func (r *Result) Unconverted() []Entry {
	var out []Entry
	for _, e := range r.Entries {
		if !e.Outcome.Converted() {
			out = append(out, e)
		}
	}
	return out
}

// Run reads every label under vmlDir and builds the corpus labels for the corpus at corpus, which
// must hold vocabulary.yaml and the SBOM of each image to migrate. Nothing is written: the caller
// writes Placed with the label writer, so a rerun over its own output is a no-op.
func Run(ctx context.Context, vmlDir, corpus string, lookup Lookup) (*Result, error) {
	log.Infof("migrating labels from %s into corpus %s", vmlDir, corpus)
	defer log.Timed("migrating labels from %s", vmlDir)()
	vocab, err := labels.FindVocabulary(os.DirFS(corpus))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", corpus, err)
	}
	records, err := readDir(vmlDir)
	if err != nil {
		return nil, err
	}
	m := &migration{corpus: corpus, vocab: vocab, sboms: map[string]*sbomIndex{}}
	res, err := m.run(ctx, records, lookup)
	if err != nil {
		return nil, err
	}
	log.Infof("migrated %d input labels into %d corpus labels, %d not converted", len(res.Entries), len(res.Placed), len(res.Unconverted()))
	for o, n := range res.Counts() {
		log.Debugf("migration outcome %s: %d labels", o, n)
	}
	for _, e := range res.Entries {
		log.Tracef("%s (%s %s on %s): %s %s", e.Source, e.Verdict, e.Vulnerability, e.Package, e.Outcome, e.Reason)
	}
	return res, nil
}

type migration struct {
	corpus string
	vocab  *labels.Vocabulary
	sboms  map[string]*sbomIndex // by image directory
}

// input is one readable record with what was resolved for it.
type input struct {
	entry    int
	verdict  labels.Verdict
	at       time.Time
	author   string
	note     string
	grype    string // the tool the call was made against, when it was grype
	image    ref.Ref
	platform string
	packages []pkgRef
}

// pkgRef is a package a label is about: its type file and the purl the label names.
type pkgRef struct {
	Type, PURL string
}

// contribution is one input label's call on one corpus key.
type contribution struct {
	in     *input
	direct bool   // the input named this id, or an advisory naming only this id
	via    string // the advisory, when the id came from one
	cves   int    // how many ids that advisory names
}

type key struct {
	file, purl, vuln string
}

func (m *migration) run(ctx context.Context, records []record, lookup Lookup) (*Result, error) {
	res := &Result{}
	inputs, advisories := m.read(res, records)
	names := map[string][]string{}
	if len(advisories) > 0 {
		log.Debugf("looking up the CVEs %d advisories name", len(advisories))
		got, err := lookup(ctx, advisories)
		if err != nil {
			return nil, fmt.Errorf("unable to find the CVEs %d advisories name: %w", len(advisories), err)
		}
		for _, a := range advisories {
			names[a] = m.disclosures(got[a])
		}
	}
	m.place(res, m.contributions(res, inputs, names))
	return res, nil
}

// read reports every record and resolves the ones that can be migrated, listing the advisory ids
// they name.
func (m *migration) read(res *Result, records []record) ([]*input, []string) {
	var inputs []*input
	var advisories []string
	seen := map[string]bool{}
	for _, r := range records {
		e := Entry{Source: r.Source, ID: r.ID, Image: r.Image.Exact, Vulnerability: r.Vulnerability, Verdict: r.Label}
		if r.Package != nil && r.Package.Name != "" {
			e.Package = r.Package.Name + "@" + r.Package.Version
		}
		in, outcome, reason := m.resolve(r)
		e.Outcome, e.Reason = outcome, reason
		res.Entries = append(res.Entries, e)
		if in == nil {
			continue
		}
		in.entry = len(res.Entries) - 1
		inputs = append(inputs, in)
		if m.vocab.IsAdvisory(r.Vulnerability) && !seen[r.Vulnerability] {
			seen[r.Vulnerability] = true
			advisories = append(advisories, r.Vulnerability)
		}
	}
	sort.Strings(advisories)
	return inputs, advisories
}

// contributions are each input's calls by corpus key: on the id it names, or on each CVE the
// advisory it names names.
func (m *migration) contributions(res *Result, inputs []*input, names map[string][]string) map[key][]contribution {
	byKey := map[key][]contribution{}
	for _, in := range inputs {
		e := &res.Entries[in.entry]
		ids := []string{e.Vulnerability}
		via := ""
		if m.vocab.IsAdvisory(e.Vulnerability) {
			via, ids = e.Vulnerability, names[e.Vulnerability]
			switch len(ids) {
			case 0:
				e.Outcome, e.Reason = NoCVE, "grype's DB names no CVE for "+via
				continue
			case 1:
				e.Outcome = Carried
			default:
				e.Outcome = FannedOut
			}
		}
		for _, p := range in.packages {
			for _, id := range ids {
				k := key{file: labels.TypeFile(labels.ImageDir(in.image), p.Type), purl: p.PURL, vuln: id}
				byKey[k] = append(byKey[k], contribution{in: in, direct: len(ids) == 1, via: via, cves: len(ids)})
			}
		}
	}
	return byKey
}

// place makes one label per key, in file and key order, and records what each input became. A
// label the writer would refuse is left out and its inputs report why.
func (m *migration) place(res *Result, byKey map[key][]contribution) {
	keys := make([]key, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.file != b.file {
			return a.file < b.file
		}
		return labels.Key{Package: a.purl, Vulnerability: a.vuln}.Less(labels.Key{Package: b.purl, Vulnerability: b.vuln})
	})
	w := labels.Writer{Dir: m.corpus, Vocab: m.vocab}
	refused := map[int][]string{}
	for _, k := range keys {
		cs := byKey[k]
		in := cs[0].in
		p := labels.Placed{
			File: k.file,
			// one image can be labeled under several tags; its files name it by digest alone
			Subject: &labels.Subject{Image: in.image.Name() + "@" + in.image.Digest, Platform: in.platform},
			Label:   merge(k, cs),
		}
		if err := w.Check(p); err != nil {
			for _, c := range cs {
				refused[c.in.entry] = append(refused[c.in.entry], err.Error())
			}
			continue
		}
		res.Placed = append(res.Placed, p)
		out := Output{File: k.file, Package: k.purl, Vulnerability: k.vuln, Verdict: p.Label.Verdict}
		for _, c := range cs {
			res.Entries[c.in.entry].Became = append(res.Entries[c.in.entry].Became, out)
		}
	}
	for i, reasons := range refused {
		if e := &res.Entries[i]; len(e.Became) == 0 {
			e.Outcome, e.Reason = Refused, strings.Join(reasons, "; ")
		}
	}
}

// disclosures are the ids an advisory names that a label may be about: not advisories, and in an
// accepted namespace.
func (m *migration) disclosures(aliases []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range aliases {
		if !seen[a] && m.vocab.CheckVulnerability(a) == nil {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// resolve checks a record and finds the packages it is about in the image's SBOM, or says why it
// cannot be migrated.
func (m *migration) resolve(r record) (*input, Outcome, string) {
	in := &input{author: r.User, note: r.Note}
	// kept verbatim (git-describe suffixes, yardstick's [db] and +profile markers included), since
	// nothing reads seenIn.grype back and each form says something about what the labeler saw.
	// Other tools (anchorectl) are not grype, so they have no place in seenIn.
	if r.Tool == "grype" || strings.HasPrefix(r.Tool, "grype@") || strings.HasPrefix(r.Tool, "grype[") {
		in.grype = r.Tool
	}
	if in.author == "" {
		// a few old labels have no user
		in.author = "unknown"
	}
	switch strings.ToUpper(r.Label) {
	case "TP":
		in.verdict = labels.TP
	case "FP":
		in.verdict = labels.FP
	case "??", "UNCLEAR":
		in.verdict = labels.Unclear
	default:
		return nil, Unreadable, fmt.Sprintf("label %q is not TP, FP or ??", r.Label)
	}
	if r.Vulnerability == "" || r.Image.Exact == "" {
		return nil, Unreadable, "a label needs a vulnerability_id and an image"
	}
	var err error
	if in.at, err = parseNaiveTime(r.Timestamp); err != nil {
		return nil, Unreadable, err.Error()
	}
	if in.image, err = ref.Parse("oci:" + r.Image.Exact); err != nil {
		return nil, Unreadable, err.Error()
	}
	if r.Package == nil || r.Package.Name == "" {
		return nil, NoPackage, "no package: vulnerability-match-labels matched it by fullentry_fields, which a label cannot express"
	}
	idx, err := m.sbom(in.image)
	if err != nil {
		return nil, Unreadable, err.Error()
	}
	if idx == nil {
		return nil, NoSBOM, fmt.Sprintf("the corpus holds no %s for the image, so its package type is unknown", labels.ImageSBOMFile)
	}
	in.platform = idx.platform
	found := idx.byNameVersion[r.Package.Name+"@"+r.Package.Version]
	if len(found) == 0 {
		// newer syft normalizes some names (pyOpenSSL is pyopenssl in a python SBOM), so a
		// name that differs only in case still finds its package at the same version
		found = idx.byFoldedName[strings.ToLower(r.Package.Name)+"@"+r.Package.Version]
	}
	if len(found) == 0 {
		return nil, NotInSBOM, fmt.Sprintf("no package %s at version %s in the image's SBOM", r.Package.Name, r.Package.Version)
	}
	for _, p := range found {
		if p.PURL != "" {
			in.packages = append(in.packages, p)
		}
	}
	if len(in.packages) == 0 {
		return nil, NoPURL, fmt.Sprintf("the image's SBOM has %s at %s with no purl to name it by", r.Package.Name, r.Package.Version)
	}
	return in, Migrated, ""
}

// sbomIndex is an image SBOM's packages by name and version, and the platform it cataloged when
// the image's digest is an index.
type sbomIndex struct {
	byNameVersion map[string][]pkgRef
	byFoldedName  map[string][]pkgRef // the same, by lowercased name
	platform      string
}

// syftDoc is the part of a syft-json document migration reads. It is decoded by hand rather than
// with syft's decoder so SBOMs from any syft version since 2023 read the same way.
type syftDoc struct {
	Artifacts []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
		PURL    string `json:"purl"`
	} `json:"artifacts"`
	Source struct {
		Metadata struct {
			ManifestDigest string `json:"manifestDigest"`
			OS             string `json:"os"`
			Architecture   string `json:"architecture"`
			Variant        string `json:"variant"`
		} `json:"metadata"`
	} `json:"source"`
}

func (m *migration) sbom(image ref.Ref) (*sbomIndex, error) {
	dir := labels.ImageDir(image)
	if idx, ok := m.sboms[dir]; ok {
		return idx, nil
	}
	data, err := os.ReadFile(filepath.Join(m.corpus, filepath.FromSlash(dir), labels.ImageSBOMFile))
	if errors.Is(err, os.ErrNotExist) {
		m.sboms[dir] = nil
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc syftDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s/%s: %w", dir, labels.ImageSBOMFile, err)
	}
	idx := &sbomIndex{byNameVersion: map[string][]pkgRef{}, byFoldedName: map[string][]pkgRef{}}
	if md := doc.Source.Metadata; md.ManifestDigest != "" && md.ManifestDigest != image.Digest && md.OS != "" {
		idx.platform = md.OS + "/" + md.Architecture
		if md.Variant != "" {
			idx.platform += "/" + md.Variant
		}
	}
	// one package found at several locations is one label
	seen := map[[2]string]bool{}
	for _, a := range doc.Artifacts {
		p := pkgRef{Type: a.Type, PURL: labelPURL(a.PURL)}
		k := a.Name + "@" + a.Version
		if seen[[2]string{k, p.Type + " " + p.PURL}] {
			continue
		}
		seen[[2]string{k, p.Type + " " + p.PURL}] = true
		idx.byNameVersion[k] = append(idx.byNameVersion[k], p)
		folded := strings.ToLower(a.Name) + "@" + a.Version
		idx.byFoldedName[folded] = append(idx.byFoldedName[folded], p)
	}
	m.sboms[dir] = idx
	return idx, nil
}

// labelPURL is the purl a migrated label names: type, namespace, name and version, plus the epoch
// qualifier, since the version vulnerability-match-labels recorded carries the epoch. Other
// qualifiers (arch, distro, upstream) are dropped so the label still pairs after an SBOM rebuild.
func labelPURL(s string) string {
	if s == "" {
		return ""
	}
	p, err := packageurl.FromString(s)
	if err != nil {
		return ""
	}
	var keep packageurl.Qualifiers
	for _, q := range p.Qualifiers {
		if q.Key == "epoch" {
			keep = append(keep, q)
		}
	}
	return packageurl.NewPackageURL(p.Type, p.Namespace, p.Name, p.Version, keep, "").ToString()
}

// merge makes the one corpus label for a key from every input label's call on it. Direct calls
// win over calls fanned out from a multi-CVE advisory; direct calls that disagree become one
// unclear label.
func merge(k key, cs []contribution) labels.Label {
	var direct []contribution
	for _, c := range cs {
		if c.direct {
			direct = append(direct, c)
		}
	}
	use := direct
	if len(use) == 0 {
		use = cs
	}
	l := labels.Label{Package: k.purl, Vulnerability: k.vuln}
	verdicts := map[labels.Verdict]bool{}
	var authors, notes, calls []string
	first, last := use[0].in.at, use[0].in.at
	var seen *input // the latest call naming the grype it was made against
	for _, c := range use {
		e := c.in
		if e.grype != "" && (seen == nil || e.at.After(seen.at)) {
			seen = e
		}
		verdicts[e.verdict] = true
		if e.at.Before(first) {
			first = e.at
		}
		if e.at.After(last) {
			last = e.at
		}
		author := e.author
		authors = append(authors, author)
		calls = append(calls, author+": "+string(e.verdict))
		switch {
		case c.via != "" && c.direct:
			notes = append(notes, fmt.Sprintf("labeled %s on %s, which names only %s", e.verdict, c.via, k.vuln))
		case c.via != "":
			notes = append(notes, fmt.Sprintf("labeled %s on %s, which names %d CVEs; not assessed for this one", e.verdict, c.via, c.cves))
		}
	}
	switch {
	case len(direct) == 0:
		l.Verdict, l.Justification = labels.Unclear, NotAssessed
	case len(verdicts) > 1:
		l.Verdict, l.Justification = labels.Unclear, LabelersDisagree
		notes = append(notes, "labelers disagree: "+strings.Join(uniqueSorted(calls), ", "))
	default:
		l.Verdict = use[0].in.verdict
		if l.Verdict != labels.TP {
			l.Justification = NotRecorded
		}
	}
	l.Author = strings.Join(uniqueSorted(authors), ", ")
	if seen != nil {
		l.SeenIn = &labels.SeenIn{Grype: seen.grype}
	}
	l.FirstIssued = first.Format(time.RFC3339)
	l.LastUpdated = last.Format(time.RFC3339)
	l.Note = strings.Join(append(uniqueSorted(notes), uniqueSorted(vmlNotes(use))...), "\n")
	return l
}

func vmlNotes(cs []contribution) []string {
	var out []string
	for _, c := range cs {
		if c.in.note != "" {
			out = append(out, c.in.note)
		}
	}
	return out
}

func uniqueSorted(s []string) []string {
	sort.Strings(s)
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// Report files, written beside nothing in the corpus.
const (
	ReportFile  = "report.json"  // every input label and what it became
	UnknownFile = "unknown.json" // the input labels nothing was written for, with why
)

// WriteReport writes the verification report into dir.
func (r *Result) WriteReport(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, entries := range map[string][]Entry{ReportFile: r.Entries, UnknownFile: r.Unconverted()} {
		if entries == nil {
			entries = []Entry{}
		}
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0o600); err != nil {
			return err
		}
	}
	return nil
}
