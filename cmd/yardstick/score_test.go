package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
)

const vocabulary = `justifications:
  fp: {fix-installed: Installed version has the fix}
  tp: {no-fix: Vulnerable code present, no fix for this version}
  unclear: {not-assessed: Nobody has assessed this version}
fact-sources: [nvd]
advisory-ids: [ELSA, ALSA]
vulnerability-namespaces: [CVE, GHSA]
`

// workspace is a directory with a claims corpus holding the deb image's SBOM and labels, and
// stub grypes printing the fixture deb output, whole or with matches dropped.
type workspace struct {
	t     *testing.T
	dir   string
	tools string
}

func newWorkspace(t *testing.T) *workspace {
	t.Helper()
	w := &workspace{t: t, dir: t.TempDir(), tools: t.TempDir()}
	r, _ := ref.Parse(debImage)
	sbom, _ := os.ReadFile(fixture.SBOM("deb", "syft"))
	writeFile(t, filepath.Join(w.dir, "claims", claimsv1.ImageDir(r), claimsv1.ImageSBOMFile), string(sbom))
	writeFile(t, filepath.Join(w.dir, "claims", claimsv1.VocabularyFile), vocabulary)
	return w
}

// grype is a stub printing the fixture deb output without the named vulnerability-on-package
// matches: a setup that does not report them.
func (w *workspace) grype(name string, drop ...string) string {
	w.t.Helper()
	data, err := os.ReadFile(fixture.Grype("v0.120.1", "deb"))
	if err != nil {
		w.t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		w.t.Fatal(err)
	}
	var kept []any
	for _, m := range doc["matches"].([]any) {
		mm := m.(map[string]any)
		key := mm["vulnerability"].(map[string]any)["id"].(string) + " " + mm["artifact"].(map[string]any)["name"].(string)
		if !contains(drop, key) {
			kept = append(kept, m)
		}
	}
	doc["matches"] = kept
	out, _ := json.Marshal(doc)
	output := filepath.Join(w.tools, name+".json")
	writeFile(w.t, output, string(out))
	return stubTool(w.t, w.tools, name, "#!/bin/sh\ncat \""+output+"\"\n")
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// label writes a tp label into the deb image's deb.json.
func (w *workspace) label(pkg, vuln string) {
	w.t.Helper()
	r, _ := ref.Parse(debImage)
	f := claimsv1.TypeFile(claimsv1.ImageDir(r), "deb")
	p := filepath.Join(w.dir, "claims", filepath.FromSlash(f))
	file := claimsv1.File{Schema: claimsv1.Version, Subject: &claimsv1.Subject{Image: r.Image()}}
	if data, err := os.ReadFile(p); err == nil {
		parsed, err := claimsv1.Parse(f, data)
		if err != nil {
			w.t.Fatal(err)
		}
		file = *parsed
	}
	file.Labels = append(file.Labels, claimsv1.Label{Package: pkg, Vulnerability: vuln, Verdict: claimsv1.TP, Author: "e2e", FirstIssued: "2026-10-14T10:00:00Z", LastUpdated: "2026-10-14T10:00:00Z"})
	data, _ := claimsv1.Marshal(&file)
	writeFile(w.t, p, string(data))
}

func (w *workspace) gate(name, candidate, reference, extra string, checks string) {
	w.t.Helper()
	writeFile(w.t, filepath.Join(w.dir, "gates", name+".yaml"), `schema: v1
claims: [../claims]
candidate: {grype: `+candidate+`, db: "dir:`+w.tools+`"}
reference: {grype: `+reference+`, db: "dir:`+w.tools+`"}
subjects: [{ref: "`+debImage+`", name: deb}`+extra+`]
checks:
`+checks)
}

const (
	tar  = "pkg:deb/debian/tar"
	libc = "pkg:deb/debian/libc6"
)

// summary-line-and-exit-code, and the score half of gate-and-score-commands
func TestScore(t *testing.T) {
	w := newWorkspace(t)
	whole := w.grype("whole")
	noTar := w.grype("no-tar", "CVE-2005-2541 tar")
	noNcurses := w.grype("no-ncurses", "CVE-2025-69720 ncurses-base")
	w.label(libc, "CVE-2026-5450")
	w.label(tar, "CVE-2005-2541")
	w.gate("passes", whole, whole, "", "  - name: noNewFalseNegatives\n")
	w.gate("fails", noTar, whole, "", "  - name: noNewFalseNegatives\n")
	w.gate("undecided", noNcurses, whole, "", "  - name: unjudgedChangesAtMost\n    params: {max: 0}\n")

	stdout, stderr, code := yardstick(t, w.dir, "gates/passes.yaml", "gates/fails.yaml", "gates/undecided.yaml", "-o", "check")
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if code != 1 || lines[len(lines)-1] != "FAILED 2 of 3 gates" {
		t.Fatalf("expected FAILED 2 of 3 gates and exit 1, got %d: %s %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "FAIL gate fails") || !strings.Contains(stdout, "UNDECIDED gate undecided (undecided: fail, so it fails)") || !strings.Contains(stdout, "PASS gate passes") {
		t.Errorf("expected each gate's outcome, got\n%s", stdout)
	}
	// the header: grype varied (two stubs), the DB held
	if !strings.Contains(stdout, "varied   grype  ") || !strings.Contains(stdout, "held     DB ") {
		t.Errorf("expected the header to name grype varied and the DB held, got\n%s", stdout)
	}

	// a fourth gate with an unknown check: exit 2, and no scan runs
	writeFile(t, filepath.Join(w.dir, "gates/bad.yaml"), strings.Replace(validGate, "noNewFalseNegatives", "noRegressions", 1))
	_ = os.RemoveAll(filepath.Join(w.dir, ".yardstick"))
	_, stderr, code = yardstick(t, w.dir, "gates/passes.yaml", "gates/fails.yaml", "gates/undecided.yaml", "gates/bad.yaml")
	if code != 2 || !strings.Contains(stderr, "noRegressions") {
		t.Errorf("expected exit 2 naming the bad gate, got %d: %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(w.dir, ".yardstick")); !os.IsNotExist(err) {
		t.Errorf("expected no scan, got %v", err)
	}

	// score with no scans names the command that makes them
	_, stderr, code = yardstick(t, w.dir, "score", "gates/fails.yaml")
	if code != 2 || !strings.Contains(stderr, "run yardstick gates/fails.yaml") {
		t.Errorf("expected exit 2 naming yardstick gates/fails.yaml, got %d: %s", code, stderr)
	}
}

// score-never-runs-grype and scans-follow-the-gate-file
func TestScoreNeverRunsGrype(t *testing.T) {
	w := newWorkspace(t)
	noTar := w.grype("no-tar", "CVE-2005-2541 tar")
	whole := w.grype("whole")
	w.label(libc, "CVE-2026-5450")
	// the dropped tar match is unlabeled, so the gate is undecided, and passes under its policy
	w.gate("deb", noTar, whole, "", "  - name: noNewFalseNegatives\nundecided: pass\n")
	if stdout, stderr, code := yardstick(t, w.dir, "gates/deb.yaml", "-o", "check"); code != 0 || !strings.Contains(stdout, "UNDECIDED gate deb (undecided: pass, so it passes)") || !strings.HasSuffix(stdout, "PASSED 1 of 1 gates\n") {
		t.Fatalf("expected the gate undecided and passing under undecided: pass, got %d: %s %s", code, stdout, stderr)
	}

	// no grype anywhere: score still runs, and counts a label written since the scan
	if err := os.RemoveAll(w.tools); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	w.label(tar, "CVE-2005-2541")
	stdout, stderr, code := yardstick(t, w.dir, "score", "gates/deb.yaml", "-o", "check")
	if code != 1 || !strings.Contains(stdout, "FAIL noNewFalseNegatives") || !strings.Contains(stdout, "CVE-2005-2541") {
		t.Fatalf("expected the new label to fail the gate with no tool run, got %d: %s %s", code, stdout, stderr)
	}

	// an edit to checks alone keeps the scans
	w.gate("deb", noTar, whole, "", "  - name: noNewFalseNegatives\n    params: {max: 1}\nundecided: pass\n")
	if stdout, stderr, code := yardstick(t, w.dir, "score", "gates/deb.yaml"); code != 0 || !strings.Contains(stdout, "PASSED 1 of 1 gates") {
		t.Errorf("expected the edited check to be scored and pass, got %d: %s %s", code, stdout, stderr)
	}
	// a gate scanned under the run is also found by its name, as claims propose --gate does
	if stdout, stderr, code := yardstick(t, w.dir, "score", "deb"); code != 0 || !strings.Contains(stdout, "PASSED 1 of 1 gates") {
		t.Errorf("expected the gate scored by name, got %d: %s %s", code, stdout, stderr)
	}
	if _, stderr, code := yardstick(t, w.dir, "score", "nope"); code != 2 || !strings.Contains(stderr, "neither a gate file nor a gate scanned") {
		t.Errorf("expected exit 2 for an unknown gate name, got %d: %s", code, stderr)
	}

	// a new subject changes what the scans are of: undecided until the gate runs again
	w.gate("deb", noTar, whole, `, "sbom:`+fixture.SBOM("npm", "syft")+`"`, "  - name: noNewFalseNegatives\nundecided: fail\n")
	stdout, _, code = yardstick(t, w.dir, "score", "gates/deb.yaml", "-o", "check")
	if code != 1 || !strings.Contains(stdout, "UNDECIDED gate deb") || !strings.Contains(stdout, "run yardstick ") || !strings.Contains(stdout, "gates/deb.yaml") {
		t.Errorf("expected the gate undecided naming yardstick <file>, got %d: %s", code, stdout)
	}
}

// scans-follow-the-gate-file: another claims source rescores the same scans, unless it holds a
// subject's SBOM other than the one scanned; app-config: claims written once, for every gate
func TestScoreWithOtherClaims(t *testing.T) {
	w := newWorkspace(t)
	noTar := w.grype("no-tar", "CVE-2005-2541 tar")
	whole := w.grype("whole")
	w.label(libc, "CVE-2026-5450")
	// the gate lists no claims: the app config does
	writeFile(t, filepath.Join(w.dir, ".yardstick.yaml"), "claims: [./claims]\n")
	w.gate("deb", noTar, whole, "", "  - name: noNewFalseNegatives\nundecided: pass\n")
	gate := filepath.Join(w.dir, "gates", "deb.yaml")
	data, _ := os.ReadFile(gate)
	writeFile(t, gate, strings.Replace(string(data), "claims: [../claims]\n", "", 1))
	if stdout, stderr, code := yardstick(t, w.dir, "gates/deb.yaml"); code != 0 {
		t.Fatalf("expected the gate to run from the app config's claims, got %d: %s %s", code, stdout, stderr)
	}

	// a labels-only source, given as --claims after the run: scored with the same scans
	r, _ := ref.Parse(debImage)
	demo := filepath.Join(w.dir, ".demo-claims")
	file := claimsv1.File{Schema: claimsv1.Version, Subject: &claimsv1.Subject{Image: r.Image()}, Labels: []claimsv1.Label{{Package: tar, Vulnerability: "CVE-2005-2541", Verdict: claimsv1.TP, Author: "e2e", FirstIssued: "2026-10-16T10:00:00Z", LastUpdated: "2026-10-16T10:00:00Z"}}}
	out, _ := claimsv1.Marshal(&file)
	writeFile(t, filepath.Join(demo, filepath.FromSlash(claimsv1.TypeFile(claimsv1.ImageDir(r), "deb"))), string(out))
	t.Setenv("PATH", "")
	stdout, stderr, code := yardstick(t, w.dir, "score", "gates/deb.yaml", "--claims", ".demo-claims", "-o", "check")
	if code != 1 || !strings.Contains(stdout, "FAIL noNewFalseNegatives") || strings.Contains(stdout, "UNDECIDED gate deb") {
		t.Fatalf("expected the --claims label to fail the gate on the existing scans, got %d: %s %s", code, stdout, stderr)
	}

	// a source ahead of the corpus holding another SBOM for the image: the scans no longer apply
	npm, _ := os.ReadFile(fixture.SBOM("npm", "syft"))
	writeFile(t, filepath.Join(w.dir, "other", claimsv1.ImageDir(r), claimsv1.ImageSBOMFile), string(npm))
	writeFile(t, filepath.Join(w.dir, ".yardstick.yaml"), "claims: [./other, ./claims]\n")
	stdout, _, code = yardstick(t, w.dir, "score", "gates/deb.yaml", "-o", "check")
	if code != 0 || !strings.Contains(stdout, "UNDECIDED gate deb") || !strings.Contains(stdout, "subject deb was scanned from SBOM") || !strings.Contains(stdout, "run yardstick ") {
		t.Errorf("expected the gate undecided naming subject deb and yardstick <file>, got %d: %s", code, stdout)
	}

	// the Python yardstick's config is refused by name
	writeFile(t, filepath.Join(w.dir, ".yardstick.yaml"), "x-ref:\n  images: []\nresult-sets: {}\n")
	if _, stderr, code := yardstick(t, w.dir, "score", "gates/deb.yaml"); code != 2 || !strings.Contains(stderr, "Python yardstick configuration") {
		t.Errorf("expected exit 2 naming the Python config, got %d: %s", code, stderr)
	}
}

// logs-go-to-stderr: with -o json -vvv stdout is still one JSON document, and the logs are on
// stderr
func TestLogsGoToStderr(t *testing.T) {
	w := newWorkspace(t)
	whole := w.grype("whole")
	w.gate("deb", whole, whole, "", "  - name: noNewFalseNegatives\n")

	stdout, stderr, code := yardstick(t, w.dir, "gates/deb.yaml", "-o", "json", "-vvv")
	// the unlabeled gate is undecided and fails (exit 1); only exit 2 is an error
	if code != 1 {
		t.Fatalf("expected exit 1, got %d: %s %s", code, stdout, stderr)
	}
	dec := json.NewDecoder(strings.NewReader(stdout))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil || dec.More() {
		t.Fatalf("expected stdout to be one JSON document, got %v: %s", err, stdout)
	}
	if !strings.Contains(stderr, "running 1 gates") || !strings.Contains(stderr, "options:") {
		t.Errorf("expected info and debug logs on stderr, got %q", stderr)
	}

	// by default only warnings and errors are logged
	if _, stderr, _ = yardstick(t, w.dir, "gates/deb.yaml", "-o", "json"); strings.Contains(stderr, "running 1 gates") {
		t.Errorf("expected no info log without -v, got %q", stderr)
	}

	// an unknown --details fails before any scan
	_ = os.RemoveAll(filepath.Join(w.dir, ".yardstick"))
	if _, stderr, code = yardstick(t, w.dir, "gates/deb.yaml", "--details", "lots"); code != 2 || !strings.Contains(stderr, "unknown details") {
		t.Errorf("expected exit 2 on an unknown --details, got %d: %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(w.dir, ".yardstick")); !os.IsNotExist(err) {
		t.Errorf("expected no scan, got %v", err)
	}
}

// log-levels: each -v adds detail to the same run. -v names each subject's SBOM lookup and scan,
// -vv adds the grype invocations, -vvv adds timings
func TestLogLevels(t *testing.T) {
	w := newWorkspace(t)
	whole := w.grype("whole")
	w.gate("deb", whole, whole, "", "  - name: noNewFalseNegatives\n")

	logs := func(args ...string) string {
		t.Helper()
		_ = os.RemoveAll(filepath.Join(w.dir, ".yardstick"))
		_, stderr, _ := yardstick(t, w.dir, append([]string{"gates/deb.yaml"}, args...)...)
		return stderr
	}
	v, vv, vvv := logs("-v"), logs("-vv"), logs("-vvv")

	for _, want := range []string{"finding the SBOM of deb", "scanning deb with the candidate setup", "scanning deb with the reference setup"} {
		if !strings.Contains(v, want) {
			t.Errorf("expected -v to log %q, got\n%s", want, v)
		}
	}
	if strings.Contains(v, "exec: ") || strings.Contains(v, "elapsed=") {
		t.Errorf("expected -v to leave out commands and timings, got\n%s", v)
	}
	if !strings.Contains(vv, "exec: "+whole) || strings.Contains(vv, "elapsed=") {
		t.Errorf("expected -vv to add the grype invocation and no timings, got\n%s", vv)
	}
	if !strings.Contains(vvv, "elapsed=") || !strings.Contains(vvv, "scanning deb") {
		t.Errorf("expected -vvv to add timings, got\n%s", vvv)
	}
	if strings.Contains(vvv, "%!") {
		t.Errorf("expected no formatting errors in the logs, got\n%s", vvv)
	}
}

// -q quiets the logs but an error still reaches stderr
func TestQuietKeepsErrors(t *testing.T) {
	w := newWorkspace(t)
	whole := w.grype("whole")
	w.gate("deb", whole, whole, "", "  - name: noNewFalseNegatives\n")

	if _, stderr, code := yardstick(t, w.dir, "gates/missing.yaml", "-q"); code != 2 || !strings.Contains(stderr, "gates/missing.yaml") {
		t.Errorf("expected -q to keep the error, got %d: %q", code, stderr)
	}
	if _, stderr, _ := yardstick(t, w.dir, "gates/deb.yaml", "-q", "-vvv"); stderr != "" {
		t.Errorf("expected -q to log nothing on a good run, got %q", stderr)
	}
}

// relate adds an alias to a vulnerability's matches in a stub's output, as grype relates a GHSA to
// its CVE.
func (w *workspace) relate(name, vuln, alias string) {
	w.t.Helper()
	p := filepath.Join(w.tools, name+".json")
	data, _ := os.ReadFile(p)
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		w.t.Fatal(err)
	}
	for _, m := range doc["matches"].([]any) {
		mm := m.(map[string]any)
		if mm["vulnerability"].(map[string]any)["id"] == vuln {
			related, _ := mm["relatedVulnerabilities"].([]any)
			mm["relatedVulnerabilities"] = append(related, map[string]any{"id": alias})
		}
	}
	out, _ := json.Marshal(doc)
	writeFile(w.t, p, string(out))
}

// rowless is a json document without its focus and rows: what a focus leaves as it was.
func rowless(t *testing.T, doc string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	var strip func(any)
	strip = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for _, k := range []string{"focus", "matches", "misses", "loose", "effects", "failsOn", "rows", "unmet"} {
				delete(v, k)
			}
			for _, x := range v {
				strip(x)
			}
		case []any:
			for _, x := range v {
				strip(x)
			}
		}
	}
	strip(v)
	out, _ := json.Marshal(v)
	return string(out)
}

// A focus never moves the verdict, and focus-narrows-rows: focus does not change the verdict, an
// alias selects the row, and nothing in focus. The narrowed fields are compared against the
// unfocused document rather than fixed numbers, which is what catches a focus reaching the checks.
func TestFocusNeverMovesTheVerdict(t *testing.T) {
	w := newWorkspace(t)
	// tar and libc6 drop a tp each, failing noNewFalseNegatives on two CVEs on two packages, and
	// the unlabeled ncurses-base drop leaves unjudgedChangesAtMost undecided
	cand := w.grype("dropped", "CVE-2005-2541 tar", "CVE-2026-5450 libc6", "CVE-2025-69720 ncurses-base")
	whole := w.grype("whole")
	const cve, ghsa = "CVE-2005-2541", "GHSA-aaaa-bbbb-cccc"
	w.relate("whole", cve, ghsa)
	w.label(tar, cve)
	w.label(libc, "CVE-2026-5450")
	checks := "  - name: noNewFalseNegatives\n  - name: unjudgedChangesAtMost\n    params: {max: 0}\n"
	w.gate("one", cand, whole, "", checks)
	w.gate("two", cand, whole, "", checks)
	gates := []string{"gates/one.yaml", "gates/two.yaml"}
	if stdout, stderr, code := yardstick(t, w.dir, append(gates, "-q")...); code != 1 {
		t.Fatalf("expected both gates to fail, got %d: %s %s", code, stdout, stderr)
	}

	score := func(args ...string) (string, report.Set) {
		t.Helper()
		stdout, stderr, code := yardstick(t, w.dir, append(append([]string{"score"}, gates...), args...)...)
		if code != 1 {
			t.Fatalf("%v: expected exit 1, got %d: %s %s", args, code, stdout, stderr)
		}
		var s report.Set
		if err := json.Unmarshal([]byte(stdout), &s); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return stdout, s
	}
	wholeDoc, all := score("-o", "json")
	cveDoc, byCVE := score("-o", "json", "--vulnerability", cve)
	ghsaDoc, byGHSA := score("-o", "json", "--vulnerability", ghsa)
	noneDoc, none := score("-o", "json", "--vulnerability", "CVE-2099-0001")
	for name, doc := range map[string]string{"cve": cveDoc, "ghsa": ghsaDoc, "none": noneDoc} {
		if rowless(t, doc) != rowless(t, wholeDoc) {
			t.Errorf("%s: the focus moved an outcome, a check value or state, a count or the summary", name)
		}
	}
	if all.Focus != nil || byCVE.Focus == nil || byGHSA.Focus == nil || none.Focus == nil {
		t.Errorf("expected a focus field on the focused documents only, got %v %v %v %v", all.Focus, byCVE.Focus, byGHSA.Focus, none.Focus)
	}

	// the focused rows and effects are the unfocused document's of that CVE
	for i, g := range all.Gates {
		var rows []report.Match
		for _, m := range g.Subjects[0].Matches {
			if strings.HasSuffix(m.ID, "/"+cve) {
				rows = append(rows, m)
			}
		}
		var effects []analysis.Effect
		for _, e := range g.Effects {
			if strings.HasSuffix(e.Match, "/"+cve) {
				effects = append(effects, e)
			}
		}
		got := byCVE.Gates[i]
		if len(rows) == 0 || !reflect.DeepEqual(got.Subjects[0].Matches, rows) {
			t.Errorf("gate %s: expected the %d rows of %s, got %+v", g.Name, len(rows), cve, got.Subjects[0].Matches)
		}
		if len(g.Effects) == 0 || !reflect.DeepEqual(got.Effects, effects) {
			t.Errorf("gate %s: expected the effects of %s only, of %d, got %+v", g.Name, cve, len(g.Effects), got.Effects)
		}
		if len(none.Gates[i].Subjects[0].Matches)+len(none.Gates[i].Effects) != 0 {
			t.Errorf("gate %s: expected no row in focus of CVE-2099-0001", g.Name)
		}
	}
	// the alias run is the CVE run apart from its focus
	byCVE.Focus, byGHSA.Focus = nil, nil
	if !reflect.DeepEqual(byCVE, byGHSA) {
		t.Errorf("expected --vulnerability %s to select what %s does", ghsa, cve)
	}

	// nothing in focus: every text layout prints each gate's outcome and a line saying so
	for _, f := range []string{"cause", "check", "subject"} {
		stdout, _, code := yardstick(t, w.dir, append(append([]string{"score"}, gates...), "-o", f, "--vulnerability", "CVE-2099-0001")...)
		if code != 1 || strings.Count(stdout, "\n  no rows match the focus\n") != 2 || !strings.Contains(stdout, "focus  rows of CVE-2099-0001") {
			t.Errorf("%s: expected exit 1, the focus named and a no-rows line per gate, got %d:\n%s", f, code, stdout)
		}
	}
}
