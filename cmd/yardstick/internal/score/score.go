// Package score scores a gate's last scans against the current labels of its claims sources:
// read the labels the scans' subjects need, pair them, evaluate the checks, and build the gate's
// verdict. It runs no tool, so yardstick score and a gate run share it.
package score

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/collect"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/lookup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

// Stale is the gate reported undecided when the current gate file would not scan what its last
// scans did, nil when they still apply. The setups and subjects are compared through the
// fingerprint. Each subject is then resolved again under the current claims sources and catalog,
// without building, and must reach the SBOM it was scanned from: another claims source changes
// the labels, not the scans, unless it holds a subject's SBOM.
func Stale(ctx context.Context, run string, g *gatefile.Gate, rec *runrecord.Record, set *claims.Set) *report.Gate {
	stale := func(why string) *report.Gate {
		v := report.Stale(g, report.NewHeader(rec, set.Sources), fmt.Sprintf("%s; run %s", why, runrecord.Rerun(run, g.Path)))
		return &v
	}
	if rec.Gate.Fingerprint != g.Fingerprint() {
		log.Debugf("gate %s: scans are stale, their fingerprint %s is not the gate file's %s", g.Name, rec.Gate.Fingerprint, g.Fingerprint())
		return stale(fmt.Sprintf("its scans were made for another version of %s (its setups or subjects changed)", g.Path))
	}
	resolver := &subject.Resolver{Sources: set.Sources, Catalog: g.Catalog, Rebuild: rec.RebuildSBOMs, NoBuild: true}
	// the record keeps no subject's parsed ref, and the fingerprint says the gate's subjects are
	// the ones scanned, so they are resolved from the gate
	current := map[string]gatefile.Subject{}
	for _, s := range g.Subjects {
		current[s.Name] = s
	}
	for _, s := range rec.Subjects {
		res, err := resolver.Resolve(ctx, current[s.Name])
		if err != nil {
			log.Debugf("gate %s: subject %s no longer resolves without a build: %v", g.Name, s.Name, err)
			return stale(fmt.Sprintf("subject %s was scanned from SBOM %s, and now %v", s.Name, s.Digest, errors.Unwrap(err)))
		}
		if res.Digest != s.Digest {
			log.Debugf("gate %s: subject %s now resolves to %s from %s, and was scanned from %s", g.Name, s.Name, res.Digest, res.From, s.Digest)
			return stale(fmt.Sprintf("subject %s was scanned from SBOM %s, and now resolves to %s (%s)", s.Name, s.Digest, res.Digest, res.From))
		}
	}
	log.Debugf("gate %s: scans match the gate file's fingerprint %s and every subject's SBOM", g.Name, g.Fingerprint())
	return nil
}

// Gate scores one gate's scans under a run name against the current labels, and narrows the
// verdict's rows to a focus, which may be nil. Whether the scans still apply is Stale's question,
// asked first by anything scoring scans it did not just make.
func Gate(run string, g *gatefile.Gate, rec *runrecord.Record, set *claims.Set, focus *report.Focus) (report.Gate, error) {
	p, err := Pair(run, g, rec, set)
	if err != nil {
		return report.Gate{}, err
	}
	return p.Verdict(focus), nil
}

// Paired is a gate's scans paired with the current labels, before its checks are evaluated: what
// the label server keeps to work out what labels it has not written yet would do.
type Paired struct {
	Gate     *gatefile.Gate
	Header   report.Header
	Subjects []analysis.Subject
	Inputs   []report.SubjectInput
	Warnings []string
	Aliases  *pairing.Aliases
}

// Pair reads a gate's scans under a run name and the labels its subjects need, and pairs them.
func Pair(run string, g *gatefile.Gate, rec *runrecord.Record, set *claims.Set) (*Paired, error) {
	log.Infof("scoring %s with its existing scans from %s", g.Name, rec.Created)
	isAdvisory := func(string) bool { return false }
	if v := set.Vocabulary(); v != nil {
		isAdvisory = v.IsAdvisory
	}
	aliases := pairing.NewAliases(isAdvisory)
	warnings := append([]string(nil), rec.Warnings...)

	type read struct {
		scans  map[string]*models.Document
		labels *claims.Labels
	}
	reads := make([]read, len(rec.Subjects))
	for i, s := range rec.Subjects {
		scans, err := loadScans(run, g.Name, s)
		if err != nil {
			return nil, err
		}
		reads[i].scans = scans
		for _, doc := range scans {
			aliases.AddScan(doc)
		}
		ls, err := set.Read(claims.Subject{Name: s.Name, Dir: s.Dir, Types: s.Types()})
		if err != nil {
			return nil, err
		}
		reads[i].labels = ls
		aliases.AddLabels(ls.Labels)
		warnings = append(warnings, ls.Warnings...)
		warnings = append(warnings, s.PlatformWarnings(ls.Platforms)...)
	}

	lookups := map[string]*lookup.File{}
	for setup, rel := range rec.Lookups {
		f, err := lookup.Load(filepath.Join(runrecord.Dir(run, g.Name), rel))
		if err != nil {
			return nil, fmt.Errorf("%s DB lookups: %w", setup, err)
		}
		lookups[setup] = f
	}

	p := &Paired{Gate: g, Header: report.NewHeader(rec, set.Sources), Aliases: aliases}
	for i, s := range rec.Subjects {
		r := pairing.Pair(aliases, pairing.Subject{Name: s.Name, Packages: s.Packages, Filtered: len(s.KeepTypes) > 0, Labels: reads[i].labels.Labels, Scans: reads[i].scans,
			Vulnerabilities: g.Vulnerabilities})
		warnings = append(warnings, r.Warnings...)
		warnings = append(warnings, r.Skipped...)
		for _, b := range r.Labels {
			if b.SeenIn != nil && b.SeenIn.SBOM != "" && b.SeenIn.SBOM != s.UnfilteredDigest {
				warnings = append(warnings, fmt.Sprintf("subject %s: label %s in %s was written against SBOM %s, and this run scanned %s", s.Name, b.Key(), b.File, b.SeenIn.SBOM, s.UnfilteredDigest))
			}
		}
		p.Subjects = append(p.Subjects, analysis.Subject{Name: s.Name, Result: r})
		p.Inputs = append(p.Inputs, report.SubjectInput{Name: s.Name, Frozen: s.Frozen, Result: r, Lookups: lookups})
	}
	p.Warnings = warnings
	return p, nil
}

// Verdict evaluates the checks and builds the gate's verdict, narrowed to a focus, which may be nil.
func (p *Paired) Verdict(focus *report.Focus) report.Gate {
	eval := analysis.Evaluate(p.Gate.Checks, p.Subjects)
	// the focus narrows the built verdict, never what is evaluated, so it cannot move a check
	return focus.Narrow(report.Build(p.Gate, p.Header, eval, p.Inputs, p.Warnings), p.Aliases)
}

// Row is the match a row id names in a gate's scans.
type Row struct {
	ID      string
	Subject *runrecord.Subject
	Match   *pairing.Match
}

// ResolveRow finds the match a row id names in a gate's scans under a run name, pairing the scans
// with no labels: a row id is the same whatever the labels say. isAdvisory is the claims
// vocabulary's, as scoring uses it, and may be nil.
func ResolveRow(run string, rec *runrecord.Record, isAdvisory func(string) bool, id string) (*Row, error) {
	rows, err := Rows(run, rec, isAdvisory)
	if err != nil {
		return nil, err
	}
	if r, ok := rows[id]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("no row %s in the scans of gate %s under run %s", id, rec.Gate.Name, run)
}

// Rows is every row of a gate's scans under a run name, by id, as ResolveRow pairs them: for
// resolving many ids with one read of the scans.
func Rows(run string, rec *runrecord.Record, isAdvisory func(string) bool) (map[string]*Row, error) {
	subjects := make([]pairing.Subject, len(rec.Subjects))
	for i, s := range rec.Subjects {
		scans, err := loadScans(run, rec.Gate.Name, s)
		if err != nil {
			return nil, err
		}
		subjects[i] = pairing.Subject{Name: s.Name, Packages: s.Packages, Scans: scans}
	}
	out := map[string]*Row{}
	for i, r := range pairing.Scanned(subjects, isAdvisory) {
		for _, m := range r.Matches {
			id := pairing.RowID(subjects[i].Name, analysis.MatchID(m))
			out[id] = &Row{ID: id, Subject: &rec.Subjects[i], Match: m}
		}
	}
	return out, nil
}

// loadScans reads each setup's scan of a subject.
func loadScans(run, gate string, s runrecord.Subject) (map[string]*models.Document, error) {
	out := map[string]*models.Document{}
	for setup, rel := range s.Scans {
		doc, err := load(filepath.Join(runrecord.Dir(run, gate), rel))
		if err != nil {
			return nil, fmt.Errorf("subject %s, %s scan: %w", s.Name, setup, err)
		}
		out[setup] = doc
		log.Debugf("subject %s: %s scan %s has %d matches", s.Name, setup, rel, len(doc.Matches))
	}
	return out, nil
}

func load(path string) (*models.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, err := collect.Decode(data)
	return &doc, err
}
