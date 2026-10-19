package report

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/collect"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

func scan(t *testing.T, path string) *models.Document {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := collect.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return &doc
}

func packagesOf(t *testing.T, image string, keep ...string) []subject.Package {
	t.Helper()
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	r, err := ref.Parse("sbom:" + fixture.SBOM(image, "syft"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := (&subject.Resolver{}).Resolve(context.Background(), gatefile.Subject{Ref: r, Name: image, KeepTypes: keep})
	if err != nil {
		t.Fatal(err)
	}
	return res.Packages
}

// label is a person's call, as a claims source holds it.
func label(pkg, vuln string, v claimsv1.Verdict) claims.Label {
	l := claims.Label{Label: claimsv1.Label{Package: pkg, Vulnerability: vuln, Verdict: v}, File: "rpm.json"}
	l.Held = []claims.SourceVerdict{{Source: "claims", Verdict: v}}
	return l
}

// rpmGate is a gate whose candidate turns on CPE matching for rpm: real grype output on both sides,
// labels on a candidate-added match of each verdict, an rpm label that leaves out the epoch, and
// labels on a package the SBOM lacks and on one grype matched nothing on.
func rpmGate(t *testing.T, checks ...gatefile.Check) (Gate, *pairing.Result) {
	t.Helper()
	cand := scan(t, fixture.Path("grype", "v0.120.1-cpes", "rpm.json"))
	refScan := scan(t, fixture.Grype("v0.120.1", "rpm"))
	ls := []claims.Label{
		label("pkg:rpm/rocky/zlib", "CVE-2018-25032", claimsv1.TP),                       // added by the candidate: fixed
		label("pkg:rpm/rocky/json-c", "CVE-2020-12762", claimsv1.FP),                     // added by the candidate: introduced
		label("pkg:rpm/rocky/openssl-libs@3.5.5-2.el9_8", "CVE-2026-45447", claimsv1.TP), // no epoch: a near miss
		label("pkg:rpm/rocky/not-installed@1.0", "CVE-2024-0001", claimsv1.TP),           // not in the SBOM
		label("pkg:rpm/rocky/bash", "CVE-2024-0002", claimsv1.TP),                        // in the SBOM, matched on nothing
	}
	a := pairing.NewAliases(nil)
	a.AddScan(cand)
	a.AddScan(refScan)
	a.AddLabels(ls)
	r := pairing.Pair(a, pairing.Subject{Name: "rpm", Packages: packagesOf(t, "rpm"), Labels: ls,
		Scans: map[string]*models.Document{pairing.Candidate: cand, pairing.Reference: refScan}})
	if len(checks) == 0 {
		checks = []gatefile.Check{
			{Name: analysis.NoNewFalsePositives, Params: map[string]float64{"max": 0}},
			{Name: analysis.UnjudgedChangesAtMost, Params: map[string]float64{"max": 0}},
			{Name: analysis.NoNewFalseNegatives, Params: map[string]float64{"max": 0}},
		}
	}
	g := &gatefile.Gate{Name: "rpm-cpes", Path: "gates/rpm-cpes.yaml", Undecided: gatefile.UndecidedFail, Checks: checks}
	eval := analysis.Evaluate(g.Checks, []analysis.Subject{{Name: "rpm", Result: r}})
	return Build(g, header(), eval, []SubjectInput{{Name: "rpm", Result: r}}, r.Warnings), r
}

// header is a run header made the way a run makes it, from a record of two setups on one DB
func header() Header {
	rec := &runrecord.Record{Created: "2026-10-14T10:00:00Z", Setups: map[string]setup.Prepared{
		"candidate": {Grype: install.Tool{Spec: install.Spec{Name: "grype", Version: "v0.120.1"}}, DB: setup.DB{Checksum: "sha256:30d8bcd3"}, Env: map[string]string{"GRYPE_MATCH_RPM_USING_CPES": "true"}},
		"reference": {Grype: install.Tool{Spec: install.Spec{Name: "grype", Version: "v0.120.1"}}, DB: setup.DB{Checksum: "sha256:30d8bcd3"}},
	}, Subjects: []runrecord.Subject{{Resolved: subject.Resolved{Subject: gatefile.Subject{Name: "rpm"}, From: subject.FromBuilt, Syft: "1.54.1"}}}}
	h := NewHeader(rec, nil)
	h.Claims = []Source{{Locator: "github.com/anchore/delta-prototype@main", Snapshot: "sha256:7df20f57", Commit: "77aa0000"}}
	return h
}

func render(t *testing.T, s Set, o Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, s, o); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func passing(t *testing.T) Gate {
	t.Helper()
	g, _ := rpmGate(t, gatefile.Check{Name: analysis.UnlabeledPercentAtMost, Params: map[string]float64{"max": 100}})
	g.Name, g.Path = "rpm-coverage", "gates/rpm-coverage.yaml"
	return g
}

// fixtureSet is the run every renderer's snapshots are of: a passing gate and a failing one.
func fixtureSet(t *testing.T) Set {
	t.Helper()
	failing, _ := rpmGate(t)
	return Summarize([]Gate{passing(t), failing})
}

// snapshotLayout snapshots a layout at each details level, into __snapshots__/<format>_test.snap
// so each layout's snapshots sit in a file of their own.
func snapshotLayout(t *testing.T, format string) {
	t.Helper()
	set := fixtureSet(t)
	snap := snaps.WithConfig(snaps.Filename(format + "_test"))
	for _, d := range append([]string{""}, DetailsLevels...) {
		name := "default"
		if d != "" {
			name = "details " + d
		}
		t.Run(name, func(t *testing.T) {
			snap.MatchSnapshot(t, render(t, set, Options{Format: format, Details: d}))
		})
	}
}

// textFormats are the formats but json, which ignores every option.
func textFormats() []string {
	var out []string
	for _, f := range Formats {
		if f != "json" {
			out = append(out, f)
		}
	}
	return out
}

// the cause, check and subject layouts are snapshotted in their own test files
func TestRenderers(t *testing.T) {
	set := fixtureSet(t)
	for _, f := range []string{"table", "json"} {
		t.Run(f, func(t *testing.T) {
			snaps.MatchSnapshot(t, render(t, set, Options{Format: f}))
		})
	}
}

// verdict-set-is-immutable: every renderer shows the one set, and json is all of it
func TestVerdictSetIsImmutable(t *testing.T) {
	failing, _ := rpmGate(t)
	set := Summarize([]Gate{passing(t), failing})
	before, _ := json.Marshal(set)
	for _, f := range Formats {
		for v, d := range []string{"", DetailsPassing, DetailsRows} {
			out := render(t, set, Options{Format: f, Details: d, Quiet: v == 2})
			if f != "json" && !strings.HasSuffix(out, "FAILED 1 of 2 gates\n") {
				t.Errorf("%s details %q: expected the summary line last, got %q", f, d, out[max(0, len(out)-60):])
			}
		}
	}
	after, _ := json.Marshal(set)
	if !bytes.Equal(before, after) {
		t.Error("rendering changed the verdict set")
	}
	var decoded Set
	if err := json.Unmarshal([]byte(render(t, set, Options{Format: "json"})), &decoded); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(decoded)
	if !bytes.Equal(again, before) {
		t.Error("the json renderer is not the whole verdict set")
	}
	if set.Summary.ExitCode != 1 {
		t.Errorf("expected exit 1 with a failing gate, got %d", set.Summary.ExitCode)
	}
	if err := CheckFormat("tree"); err == nil || !strings.Contains(err.Error(), "cause, check, subject, table, json") {
		t.Errorf("expected an unknown renderer refused naming every format, got %v", err)
	}
	if err := Render(io.Discard, set, Options{Format: "tree"}); err == nil {
		t.Error("expected Render to refuse an unknown format")
	}
}

// verbosity-only-adds: each details level contains the output of the one below it
func TestVerbosityOnlyAdds(t *testing.T) {
	set := fixtureSet(t)
	for _, f := range textFormats() {
		var prev []string
		for _, d := range []string{"", DetailsPassing, DetailsRows} {
			out := render(t, set, Options{Format: f, Details: d})
			lines := strings.Split(out, "\n")
			for _, l := range prev {
				if !strings.Contains(out, l) {
					t.Errorf("%s details %q lost or reworded %q", f, d, l)
				}
			}
			prev = lines
		}
	}
}

func TestRunHeader(t *testing.T) {
	h := header()
	if len(h.Varied) != 1 || h.Varied[0].Input != "env" || strings.Join(h.Held, ",") != "grype,DB,config" || h.Attribution != "" {
		t.Errorf("expected env varied and grype, DB and config held, got %+v", h)
	}
	if len(h.Built) != 1 || h.Built[0].Syft != "1.54.1" {
		t.Errorf("expected the built SBOM listed with its syft, got %+v", h.Built)
	}
	// grype and the DB both varied: no delta can be attributed to either
	rec := &runrecord.Record{Setups: map[string]setup.Prepared{
		"candidate": {Grype: install.Tool{Spec: install.Spec{Name: "grype", Version: "v0.120.1"}}, DB: setup.DB{Checksum: "sha256:aa"}},
		"reference": {Grype: install.Tool{Spec: install.Spec{Name: "grype", Version: "v0.119.0"}}, DB: setup.DB{Checksum: "sha256:bb"}},
	}}
	if h := NewHeader(rec, nil); len(h.Varied) != 2 || h.Attribution != NotAttributable {
		t.Errorf("expected two inputs varied and no attribution, got %+v", h)
	}
	delete(rec.Setups, "reference")
	h = NewHeader(rec, nil)
	out := render(t, Summarize([]Gate{{Name: "presence", Path: "gates/presence.yaml", Header: h, Outcome: analysis.Pass, Passed: true}}), Options{Format: "check"})
	if !h.OneSetup || len(h.Varied) != 0 || !strings.Contains(out, "one setup scanned") || strings.Contains(out, "varied") {
		t.Errorf("expected a one-setup header naming nothing varied, got\n%s", out)
	}
}

func TestPerMatchCause(t *testing.T) {
	g, _ := rpmGate(t)
	causes := map[string]Miss{}
	for _, m := range g.Subjects[0].Misses {
		causes[m.Label.Vulnerability] = m
	}
	for vuln, want := range map[string]string{"CVE-2026-45447": NearMiss, "CVE-2024-0001": MissingPackage, "CVE-2024-0002": MatchingFailure} {
		if got := causes[vuln]; got.Cause != want || got.Where == "" {
			t.Errorf("%s: expected %s with where to look, got %+v", vuln, want, got)
		}
	}
	// a label with no package resolves to MATCHING FAILURE
	r := &pairing.Result{Labels: []*pairing.Bound{{Label: label("", "CVE-2024-0003", claimsv1.TP), Present: true}}}
	if m := misses(r); len(m) != 1 || m[0].Cause != MatchingFailure {
		t.Errorf("expected a package-less miss to be a matching failure, got %+v", m)
	}
	// a miss on a package the candidate matched other vulnerabilities on fits none of the three
	_, pr := rpmGate(t)
	pr.Labels = append(pr.Labels, &pairing.Bound{Label: label("pkg:rpm/rocky/zlib", "CVE-2024-0004", claimsv1.TP), Present: true})
	pr.Labels[len(pr.Labels)-1].Fields.Name = "zlib"
	found := false
	for _, m := range misses(pr) {
		found = found || (m.Label.Vulnerability == "CVE-2024-0004" && m.Cause == NoCause)
	}
	if !found {
		t.Error("expected NO CAUSE for a miss that fits none of the others")
	}
}

func TestNearMissProbe(t *testing.T) {
	g, _ := rpmGate(t)
	var miss Miss
	for _, m := range g.Subjects[0].Misses {
		if m.Label.Vulnerability == "CVE-2026-45447" {
			miss = m
		}
	}
	if len(miss.NearMiss) != 1 || miss.NearMiss[0].Field != "version" || !strings.Contains(miss.NearMiss[0].Package, "openssl-libs@3.5.5-2.el9_8?") || !strings.Contains(miss.NearMiss[0].Package, "epoch=1") {
		t.Errorf("expected the version named as the field whose removal pairs it, with the match, got %+v", miss.NearMiss)
	}
	// the probe changes nothing: the label is still a miss in both setups and the check counts it
	for _, c := range g.Checks {
		if c.Name == analysis.NoNewFalseNegatives && c.State != analysis.Pass {
			t.Errorf("a label both setups miss is no new false negative, got %s", c.State)
		}
	}
	// of the four tp labels the candidate pairs only zlib's: the near miss is not paired
	if c := g.Subjects[0].Counts["candidate"]; c.Labels != 4 || c.Satisfied != 1 {
		t.Errorf("the probe changed what the candidate satisfies: %+v", c)
	}
}

func TestDirection(t *testing.T) {
	g, _ := rpmGate(t)
	got := map[string]string{}
	for _, m := range g.Subjects[0].Matches {
		got[m.Vulnerability+" "+m.Package[:strings.Index(m.Package, "@")]] = m.Direction
	}
	for k, want := range map[string]string{
		"CVE-2018-25032 pkg:rpm/rocky/zlib":         Fixed,
		"CVE-2020-12762 pkg:rpm/rocky/json-c":       Introduced,
		"CVE-2023-48795 pkg:rpm/rocky/libssh":       Review,
		"CVE-2026-45447 pkg:rpm/rocky/openssl-libs": "",
	} {
		if got[k] != want {
			t.Errorf("%s: expected direction %q, got %q", k, want, got[k])
		}
	}
	// a candidate-dropped tp is introduced
	m := &pairing.Match{Rows: map[string][]int{pairing.Reference: {0}}, Verdict: claimsv1.TP}
	if d := direction(m); d != Introduced {
		t.Errorf("expected a dropped tp introduced, got %q", d)
	}
	// rows under a one-setup check carry none
	out := render(t, Summarize([]Gate{g}), Options{Format: "check", Details: DetailsRows})
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "unlabeledPercentAtMost") {
			t.Errorf("unexpected check %s", line)
		}
	}
}

// color-is-only-style: a colored report is the plain one with escape codes added, so the plain
// output and the additive rule hold whatever a terminal shows
func TestColorIsOnlyStyle(t *testing.T) {
	failing, _ := rpmGate(t)
	set := Summarize([]Gate{passing(t), failing})
	escape := regexp.MustCompile("\x1b\\[[0-9;]*m")
	for _, f := range textFormats() {
		for _, d := range []string{"", DetailsPassing, DetailsRows} {
			plain := render(t, set, Options{Format: f, Details: d})
			colored := render(t, set, Options{Format: f, Details: d, Color: true})
			if !escape.MatchString(colored) {
				t.Errorf("%s details %q: expected escape codes with color on", f, d)
			}
			if got := escape.ReplaceAllString(colored, ""); got != plain {
				t.Errorf("%s details %q: the colored report differs from the plain one beyond its escape codes", f, d)
			}
		}
	}
	// a file is never colored, and a writer that is no terminal gets no color
	dir := t.TempDir()
	var stdout bytes.Buffer
	if err := WriteOutputs(&stdout, set, []Output{{Format: "check"}, {Format: "table", Path: dir + "/t.txt"}}, Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	if file, _ := os.ReadFile(dir + "/t.txt"); escape.Match(file) || !escape.Match(stdout.Bytes()) {
		t.Error("expected color on stdout only")
	}
	if Colorable(&stdout) {
		t.Error("expected no color for a writer that is not a terminal")
	}
}

// every row carries its matcher and the file its package was found in, so the same log4j-core in
// two jars prints as two packages, and json carries both
func TestRowsCarryLocation(t *testing.T) {
	doc := scan(t, fixture.Grype("v0.120.1", "java"))
	a := pairing.NewAliases(nil)
	a.AddScan(doc)
	r := pairing.Pair(a, pairing.Subject{Name: "java", Packages: packagesOf(t, "java"),
		Scans: map[string]*models.Document{pairing.Candidate: doc, pairing.Reference: doc}})
	g := &gatefile.Gate{Name: "java", Path: "gates/java.yaml", Undecided: gatefile.UndecidedFail}
	v := Build(g, header(), analysis.Evaluate(nil, nil), []SubjectInput{{Name: "java", Result: r}}, nil)
	where := map[string][]string{}
	for _, m := range v.Subjects[0].Matches {
		if m.Matcher != "java-matcher" {
			t.Errorf("%s: expected java-matcher, got %q", m.ID, m.Matcher)
		}
		if strings.Contains(m.Package, "log4j-core@2.14.1") && m.Vulnerability == "GHSA-jfh8-c2jp-5v3q" {
			where[m.Package] = append(where[m.Package], m.Location)
		}
	}
	want := []string{"/opt/app-a/lib/log4j-core-2.14.1.jar", "/opt/app-b/lib/log4j-core-2.14.1.jar"}
	for _, locs := range where {
		slices.Sort(locs)
		if !slices.Equal(locs, want) {
			t.Errorf("expected one row per jar, told apart by location, got %v", locs)
		}
	}
	if len(where) != 1 {
		t.Errorf("expected the two jars' rows on one purl, got %v", where)
	}
	out := render(t, Summarize([]Gate{v}), Options{Format: "json"})
	for _, l := range want {
		if !strings.Contains(out, `"location": "`+l+`"`) || !strings.Contains(out, `"matcher": "java-matcher"`) {
			t.Errorf("expected json to carry the matcher and %s", l)
		}
	}
}
