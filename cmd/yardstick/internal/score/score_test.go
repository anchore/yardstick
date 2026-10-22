package score

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/lookup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

const vocabYAML = `justifications:
  fp: {fix-installed: Installed version has the fix}
  tp: {no-fix: No fix}
  unclear: {not-assessed: Nobody has assessed this version}
fact-sources: [nvd]
advisory-ids: [ELSA]
vulnerability-namespaces: [CVE, GHSA]
`

var debRef, _ = ref.Parse("oci:docker.io/anchore/yardstick-fixture-deb@sha256:617d48dd2601779266746a9a382bfb9f3fee2744fba698733b320366f41718b0")

// newCorpus is a claims source with one label file for the deb image.
func newCorpus(t *testing.T, platform string, ls ...claimsv1.Label) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, claimsv1.VocabularyFile), []byte(vocabYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &claimsv1.File{Schema: claimsv1.Version, Subject: &claimsv1.Subject{Image: debRef.Image(), Platform: platform}, Labels: ls}
	data, _ := claimsv1.Marshal(f)
	p := filepath.Join(dir, filepath.FromSlash(corpus.TypeFile(corpus.ImageDir(debRef), "deb")))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func label(pkg, vuln string, v claimsv1.Verdict) claimsv1.Label {
	l := claimsv1.Label{Package: pkg, Vulnerability: vuln, Verdict: v, Author: "test", FirstIssued: "2026-10-14T10:00:00Z", LastUpdated: "2026-10-14T10:00:00Z"}
	if v != claimsv1.TP {
		l.Justification = map[claimsv1.Verdict]string{claimsv1.FP: "fix-installed", claimsv1.Unclear: "not-assessed"}[v]
	}
	return l
}

// scanned writes a gate's scans as a run leaves them: both setups' grype output for the deb
// image and the record, for a subject cataloged for linux/amd64.
func scanned(t *testing.T, g *gatefile.Gate) *runrecord.Record {
	t.Helper()
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	res, err := (&subject.Resolver{}).Resolve(context.Background(), gatefile.Subject{Ref: mustRef(t, "sbom:"+fixture.SBOM("deb", "syft")), Name: "deb"})
	if err != nil {
		t.Fatal(err)
	}
	res.Subject = gatefile.Subject{Ref: debRef, Name: "deb", Platform: "linux/amd64"}
	res.Dir, res.Platform = corpus.ImageDir(debRef), "linux/amd64"
	rec := &runrecord.Record{Gate: runrecord.Gate{Name: g.Name, Fingerprint: g.Fingerprint()}, Subjects: []runrecord.Subject{{Resolved: *res, Scans: map[string]string{
		"candidate": "candidate/00.json", "reference": "reference/00.json",
	}}}}
	p, err := runrecord.Start(runrecord.DefaultName, g.Name)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(fixture.Grype("v0.120.1", "deb"))
	for _, rel := range rec.Subjects[0].Scans {
		if err := p.Write(rel, out); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Replace(rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func mustRef(t *testing.T, s string) ref.Ref {
	t.Helper()
	r, err := ref.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func gate(sources ...string) *gatefile.Gate {
	g := &gatefile.Gate{Name: "deb", Path: "gates/deb.yaml", Undecided: gatefile.UndecidedFail,
		Subjects: []gatefile.Subject{{Ref: debRef, Name: "deb", Platform: "linux/amd64"}},
		Checks:   []gatefile.Check{{Name: "noNewFalseNegatives", Params: map[string]float64{"max": 0}}}}
	for _, s := range sources {
		g.Claims = append(g.Claims, gatefile.Source{Locator: s})
	}
	return g
}

func TestWarnings(t *testing.T) {
	t.Chdir(t.TempDir())
	const libc = "pkg:deb/debian/libc6"
	before := label(libc, "CVE-2026-5450", claimsv1.TP)
	before.SeenIn = &claimsv1.SeenIn{SBOM: "sha256:3e1a000000000000000000000000000000000000000000000000000000000000"}
	unseen := label(libc, "CVE-2026-5928", claimsv1.TP)
	g := gate(newCorpus(t, "linux/arm64", before, unseen))
	rec := scanned(t, g)
	v, err := gateOf(t, g, rec)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(v.Warnings, "\n")
	// the label files were written for another platform than this run catalogs
	if !strings.Contains(all, "record platform linux/arm64, and this run catalogs linux/amd64") {
		t.Errorf("expected the platform warning naming both, got\n%s", all)
	}
	// a label written against another SBOM warns naming it and both digests; one with no seenIn
	// does not
	if !strings.Contains(all, "CVE-2026-5450 on "+libc) || !strings.Contains(all, "sha256:3e1a") || !strings.Contains(all, rec.Subjects[0].UnfilteredDigest) || strings.Contains(all, "CVE-2026-5928") {
		t.Errorf("expected one seenIn warning naming the label and both digests, got\n%s", all)
	}
}

// cross-source-disagreement-reads-unlabeled: the warning reaches every renderer
func TestDisagreementInEveryRenderer(t *testing.T) {
	t.Chdir(t.TempDir())
	const libc = "pkg:deb/debian/libc6"
	published := newCorpus(t, "", label(libc, "CVE-2026-5450", claimsv1.FP))
	local := newCorpus(t, "", label(libc, "CVE-2026-5450", claimsv1.TP))
	g := gate(published, local)
	v, err := gateOf(t, g, scanned(t, g))
	if err != nil {
		t.Fatal(err)
	}
	set := report.Summarize([]report.Gate{v})
	for _, f := range report.Formats {
		var buf bytes.Buffer
		if err := report.Render(&buf, set, report.Options{Format: f}); err != nil {
			t.Fatal(err)
		}
		if out := buf.String(); !strings.Contains(out, published+": fp") || !strings.Contains(out, local+": tp") || !strings.Contains(out, "CVE-2026-5450 on "+libc) {
			t.Errorf("%s: expected the key with each source and its verdict, got\n%s", f, out)
		}
	}
	// the last source decides: the local tp
	for _, m := range v.Subjects[0].Matches {
		if m.Vulnerability == "CVE-2026-5450" && strings.Contains(m.Package, "libc6@") && m.Verdict != claimsv1.TP {
			t.Errorf("expected the disputed match to take the last source's tp, got %q", m.Verdict)
		}
	}
}

// gateOf opens the gate's claims and scores with them, as the command does.
func gateOf(t *testing.T, g *gatefile.Gate, rec *runrecord.Record) (report.Gate, error) {
	t.Helper()
	set, err := claims.OpenSet(g.Claims)
	if err != nil {
		t.Fatal(err)
	}
	return Gate(runrecord.DefaultName, g, rec, set, nil)
}

// a row id resolves back to the match it names, whatever the labels say
func TestResolveRow(t *testing.T) {
	t.Chdir(t.TempDir())
	g := gate(newCorpus(t, "", label("pkg:deb/debian/libc6", "CVE-2026-5450", claimsv1.TP)))
	rec := scanned(t, g)
	v, err := gateOf(t, g, rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range v.Subjects[0].Matches {
		row, err := ResolveRow(runrecord.DefaultName, rec, nil, m.Row)
		if err != nil {
			t.Fatal(err)
		}
		if row.Subject.Name != "deb" || analysis.MatchID(row.Match) != m.ID || row.Match.Vulnerability != m.Vulnerability {
			t.Errorf("row %s: expected match %s, got %s on %s", m.Row, m.ID, analysis.MatchID(row.Match), row.Subject.Name)
		}
	}
	if _, err := ResolveRow(runrecord.DefaultName, rec, nil, "0000000000000000"); err == nil || !strings.Contains(err.Error(), "no row 0000000000000000") {
		t.Errorf("expected an unknown row refused, got %v", err)
	}
}

// the DB lookups stored beside the scans explain the rows one setup reported, and a record
// without them scores those rows unexplained
func TestLookupsExplainOneSidedRows(t *testing.T) {
	t.Chdir(t.TempDir())
	g := gate(newCorpus(t, ""))
	g.Reference = &gatefile.Setup{}
	rec := scanned(t, g)
	// the reference reported nothing
	dir := runrecord.Dir(runrecord.DefaultName, g.Name)
	if err := os.WriteFile(filepath.Join(dir, "reference/00.json"), []byte(`{"matches": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	why := func() map[string]string {
		v, err := gateOf(t, g, rec)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, m := range v.Subjects[0].Matches {
			out[m.Vulnerability] = m.Why.Key
		}
		return out
	}
	if got := why()["CVE-2026-5450"]; got != report.WhyUnexplained {
		t.Errorf("expected a row unexplained before lookups, got %q", got)
	}
	data, _ := json.Marshal(lookup.File{Statuses: map[string]string{"CVE-2026-5450": lookup.NotInDB}})
	if err := os.WriteFile(filepath.Join(dir, "reference/lookups.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	rec.Lookups = map[string]string{"reference": "reference/lookups.json"}
	if got := why()["CVE-2026-5450"]; got != report.WhyAbsentInReference {
		t.Errorf("expected a vulnerability the reference DB lacks absent in the reference, got %q", got)
	}

	// lookups an older yardstick made still score, with a warning naming how to redo them
	outdated := func() bool {
		v, err := gateOf(t, g, rec)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(v.Warnings, func(w string) bool {
			return strings.Contains(w, "DB lookups were made by an older yardstick") && strings.Contains(w, "run yardstick "+g.Path)
		})
	}
	if !outdated() {
		t.Error("expected a warning that lookups with no version are outdated")
	}
	data, _ = json.Marshal(lookup.File{Version: lookup.Version, Statuses: map[string]string{"CVE-2026-5450": lookup.NotInDB}})
	if err := os.WriteFile(filepath.Join(dir, "reference/lookups.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if outdated() {
		t.Error("expected no warning for current lookups")
	}
}

// the vulnerabilities filter is applied when scoring, so changing it rescores the same scans
func TestVulnerabilitiesFilterRescores(t *testing.T) {
	t.Chdir(t.TempDir())
	g := gate(newCorpus(t, "", label("pkg:deb/debian/libc6", "CVE-2026-5450", claimsv1.TP)))
	g.Checks = []gatefile.Check{{Name: analysis.MatchesAtLeast, Params: map[string]float64{"min": 1}}}
	rec := scanned(t, g)
	for _, tc := range []struct {
		filter *gatefile.Vulnerabilities
		want   analysis.State
	}{
		{nil, analysis.Pass},
		{&gatefile.Vulnerabilities{Namespaces: []string{"debian:distro:debian:12"}}, analysis.Pass},
		{&gatefile.Vulnerabilities{Namespaces: []string{"nvd:cpe"}}, analysis.Fail},
		{&gatefile.Vulnerabilities{MaxYear: 2004}, analysis.Fail},
	} {
		g.Vulnerabilities = tc.filter
		if g.Fingerprint() != rec.Gate.Fingerprint {
			t.Fatalf("expected the filter to keep the fingerprint")
		}
		v, err := gateOf(t, g, rec)
		if err != nil {
			t.Fatal(err)
		}
		if v.Outcome != tc.want {
			t.Errorf("filter %+v: expected %s, got %s", tc.filter, tc.want, v.Outcome)
		}
	}
}

// scans moved with their gate file to another directory, as a CI artifact is to another checkout,
// still apply with no grype or DB there; another file named, or other SBOM content, does not
func TestStaleIgnoresLocation(t *testing.T) {
	t.Chdir(t.TempDir())
	ctx := context.Background()
	const content = `schema: v1
candidate: {grype: ../.tool/grype, db: ../build/vulnerability.db}
reference: {grype: grype@v0.119.0, db: latest}
subjects:
  - sbom:../sboms/deb.json
checks:
  - name: noNewFalseNegatives
`
	claimsDir := newCorpus(t, "")
	load := func(content, sbom string) *gatefile.Gate {
		t.Helper()
		dir := t.TempDir()
		data, err := os.ReadFile(sbom)
		if err != nil {
			t.Fatal(err)
		}
		for p, b := range map[string][]byte{"sboms/deb.json": data, "gates/deb.yaml": []byte(content)} {
			if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, p), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		g, err := gatefile.Load(filepath.Join(dir, "gates", "deb.yaml"), gatefile.Options{Checks: analysis.Definitions(), Claims: []string{claimsDir}})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	deb := fixture.SBOM("deb", "syft")
	scannedGate := load(content, deb)
	res, err := (&subject.Resolver{}).Resolve(ctx, scannedGate.Subjects[0])
	if err != nil {
		t.Fatal(err)
	}
	rec := &runrecord.Record{Gate: runrecord.Gate{Name: "deb", Fingerprint: scannedGate.Fingerprint()}, Subjects: []runrecord.Subject{{Resolved: *res}}}
	set, err := claims.OpenSet(scannedGate.Claims)
	if err != nil {
		t.Fatal(err)
	}
	if v := Stale(ctx, runrecord.DefaultName, load(content, deb), rec, set); v != nil {
		t.Errorf("expected the moved gate's scans to apply, got %s", v.Message)
	}
	for what, g := range map[string]*gatefile.Gate{
		"grype":        load(strings.Replace(content, "../.tool/grype", "../.tool/grype-other", 1), deb),
		"db":           load(strings.Replace(content, "../build/vulnerability.db", "../build/other.db", 1), deb),
		"sbom content": load(content, fixture.SBOM("rpm", "syft")),
	} {
		if v := Stale(ctx, runrecord.DefaultName, g, rec, set); v == nil {
			t.Errorf("expected another %s to make the scans stale", what)
		}
	}
}

// a record missing a setup's scan of a subject, as an interrupted run would leave it, is refused
// rather than scored as that setup reporting nothing
func TestIncompleteScansAreRefused(t *testing.T) {
	t.Chdir(t.TempDir())
	g := gate(newCorpus(t, "linux/amd64", label("pkg:deb/debian/libc6", "CVE-2026-5450", claimsv1.TP)))
	rec := scanned(t, g)
	rec.Setups = map[string]setup.Prepared{pairing.Candidate: {}, pairing.Reference: {}}
	if _, err := gateOf(t, g, rec); err != nil {
		t.Fatalf("expected the whole record scored, got %v", err)
	}
	delete(rec.Subjects[0].Scans, pairing.Reference)
	if _, err := gateOf(t, g, rec); err == nil || !strings.Contains(err.Error(), "subject deb has no reference scan") {
		t.Errorf("expected the missing reference scan refused, got %v", err)
	}
}
