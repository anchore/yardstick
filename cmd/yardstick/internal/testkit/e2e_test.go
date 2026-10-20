package testkit

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver"
)

// state is the part of a gate's /api/gates/<gate>/state this test reads.
type state struct {
	Gate struct {
		Result struct {
			Outcome string
			Checks  []struct{ Name, State string }
		}
	}
	Causes []struct {
		Title string
		Rows  []string
	}
	Explanations []struct{ Rows []string }
	Subjects     []struct {
		Name string
		Rows []struct {
			Row, Vulnerability, Verdict, Location string
			InCandidate, InReference              bool
			Package                               struct{ Ref string }
			Hint                                  *struct{ Verdict string }
			Causes                                []string
		}
	}
}

func get(t *testing.T, h http.Handler, path string, v any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatal(err)
	}
}

// open lists the changes a gate has no tp or fp for, as "<subject> <added|dropped> <vulnerability>
// <package name>[ <hint>][ cause]", sorted. These are the rows SCENARIO.md lists.
func (s *state) open() []string {
	var out []string
	for _, sub := range s.Subjects {
		for _, r := range sub.Rows {
			if r.InCandidate == r.InReference || r.Verdict == "tp" || r.Verdict == "fp" {
				continue
			}
			dir := "dropped"
			if r.InCandidate {
				dir = "added"
			}
			name := strings.SplitN(strings.TrimPrefix(r.Package.Ref, "pkg:"), "@", 2)[0]
			line := sub.Name + " " + dir + " " + r.Vulnerability + " " + name[strings.LastIndex(name, "/")+1:]
			if r.Verdict == "unclear" {
				line += " unclear"
			}
			if r.Hint != nil {
				line += " hint:" + r.Hint.Verdict
			}
			if len(r.Causes) > 0 {
				line += " cause"
			}
			out = append(out, line)
		}
	}
	slices.Sort(out)
	return out
}

// the facts SCENARIO.md states: if the material drifts, this fails before any browser does
func TestE2EWorkspace(t *testing.T) {
	dir, tools := t.TempDir(), t.TempDir()
	bin := filepath.Join(tools, "yardstick")
	if out, err := exec.Command("go", "build", "-o", bin, "../..").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	t.Chdir(dir)
	E2E(t, dir, tools, bin)
	srv, err := NewServer(context.Background(), dir, bin)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	var gates struct {
		Gates []struct{ ID, GateOutcome string }
	}
	get(t, h, "/api/gates", &gates)
	// listed newest scan first, which two gates scanned across a minute boundary swap
	outcomes := map[string]string{}
	for _, g := range gates.Gates {
		outcomes[g.ID] = g.GateOutcome
	}
	if !maps.Equal(outcomes, map[string]string{"deb-java": "fail", "deb-npm": "undecided"}) {
		t.Fatalf("gates: %+v", gates.Gates)
	}

	var a state
	get(t, h, "/api/gates/deb-java/state", &a)
	checks := map[string]string{}
	for _, c := range a.Gate.Result.Checks {
		checks[c.Name] = c.State
	}
	wantChecks := map[string]string{"f1NotWorse": "fail", "noNewFalseNegatives": "fail", "noNewFalsePositives": "fail", "unjudgedChangesAtMost": "undecided"}
	if a.Gate.Result.Outcome != "fail" || !maps.Equal(checks, wantChecks) {
		t.Errorf("deb-java: %s %v", a.Gate.Result.Outcome, checks)
	}
	// the UI names a subject by its repository's base and tag
	const deb, java, npm = "vulnerabilities-debian-12-tar-util-linux:617d48d ", "grype-quality-java-log4j-two-jars:e363e44 ", "grype-quality-npm-babel:8e253b5 "
	wantA := []string{
		java + "added GHSA-jfh8-c2jp-5v3q log4j-core hint:tp",
		java + "added GHSA-jfh8-c2jp-5v3q log4j-core hint:tp",
		java + "added GHSA-vc5p-v9hr-52mj log4j-core unclear hint:tp",
		java + "added GHSA-vc5p-v9hr-52mj log4j-core unclear hint:tp",
		deb + "added CVE-2026-3184 libblkid1 cause",
		deb + "added CVE-2026-3184 libmount1 cause",
		deb + "added CVE-2026-3184 mount cause",
		deb + "added CVE-2026-3184 util-linux cause",
		deb + "dropped CVE-2005-2541 tar hint:fp",
		deb + "dropped CVE-2026-18508 tar",
	}
	if got := a.open(); !slices.Equal(got, wantA) {
		t.Errorf("deb-java open:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantA, "\n"))
	}
	if len(a.Causes) != 1 || len(a.Causes[0].Rows) != 4 || len(a.Explanations) != 1 || len(a.Explanations[0].Rows) != 4 {
		t.Errorf("deb-java cause and explanation: %+v %+v", a.Causes, a.Explanations)
	}

	var b state
	get(t, h, "/api/gates/deb-npm/state", &b)
	wantB := []string{npm + "dropped GHSA-67hx-6x53-jw92 traverse", deb + "dropped CVE-2005-2541 tar hint:fp", deb + "dropped CVE-2026-41992 gzip hint:fp"}
	if got := b.open(); b.Gate.Result.Outcome != "undecided" || !slices.Equal(got, wantB) {
		t.Errorf("deb-npm: %s\n%s", b.Gate.Result.Outcome, strings.Join(got, "\n"))
	}

	t.Run("gate tables", func(t *testing.T) { checkGateTables(t, h) })

	// the labels SCENARIO.md says flip deb-java: fp for the dropped tar changes, tp for the added ones
	add := func(gate, subject, pkg, vuln, verdict, why string) {
		t.Helper()
		cmd := exec.Command(bin, "claims", "add", "--gate", "gates/"+gate+".yaml", "--author", "e2e", "--subject", subject,
			"--package", pkg, "--vulnerability", vuln, "--verdict", verdict, "--justification", why)
		cmd.Env = append(os.Environ(), "YARDSTICK_CACHE_DIR="+filepath.Join(tools, "cache"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("claims add: %v\n%s", err, out)
		}
	}
	for _, v := range []string{"CVE-2005-2541", "CVE-2026-18508"} {
		add("deb-java", e2eImage("deb").String(), "pkg:deb/debian/tar", v, "fp", "fix-installed")
	}
	for _, p := range []string{"util-linux", "libblkid1", "libmount1", "mount"} {
		add("deb-java", e2eImage("deb").String(), "pkg:deb/debian/"+p, "CVE-2026-3184", "tp", "no-fix")
	}
	const log4j = "pkg:maven/org.apache.logging.log4j/log4j-core"
	add("deb-java", e2eImage("java").String(), log4j, "GHSA-jfh8-c2jp-5v3q", "tp", "no-fix")
	add("deb-java", e2eImage("java").String(), log4j, "GHSA-vc5p-v9hr-52mj", "tp", "no-fix")

	get(t, h, "/api/gates/deb-java/state", &a)
	if a.Gate.Result.Outcome != "pass" || len(a.open()) != 0 {
		t.Errorf("deb-java after labeling: %s, open %v", a.Gate.Result.Outcome, a.open())
	}
	// the tar label is shared: deb-npm is down to one change per image, which its max of 1 allows
	get(t, h, "/api/gates/deb-npm/state", &b)
	if b.Gate.Result.Outcome != "pass" || len(b.open()) != 2 {
		t.Errorf("deb-npm after labeling: %s, open %v", b.Gate.Result.Outcome, b.open())
	}

	// a tp on a dropped row fails noNewFalseNegatives, and that label is what decides it
	add("deb-java", e2eImage("deb").String(), "pkg:deb/debian/tar", "CVE-2026-18508", "tp", "no-fix")
	var fn labelserver.CheckFindings
	get(t, h, "/api/gates/deb-java/checks/noNewFalseNegatives/findings", &fn)
	if got := findingLines(fn); fn.Check.State != "fail" || !slices.Equal(got, []string{"e3bfd3b0b0c30ee6 decides tp -"}) {
		t.Errorf("noNewFalseNegatives after a tp on a dropped row: %s %v", fn.Check.State, got)
	}
	if got := failsOn(t, h, "deb-java")["noNewFalseNegatives"]; !slices.Equal(got, []string{"e3bfd3b0b0c30ee6"}) {
		t.Errorf("noNewFalseNegatives failsOn in /state: %v", got)
	}
	if got := rowEffects(t, h, "deb-java")["e3bfd3b0b0c30ee6"]; got != "decides" {
		t.Errorf("the tar tp row's effect in /state: %q", got)
	}
	var tar labelserver.GateLabels
	get(t, h, "/api/gates/deb-java/labels?q=CVE-2026-18508", &tar)
	if len(tar.Labels) != 1 || !slices.Contains(tar.Labels[0].Decides, "noNewFalseNegatives") || tar.Labels[0].Row != "e3bfd3b0b0c30ee6" {
		t.Errorf("the tar tp label: %+v", tar.Labels)
	}
}

const (
	debSlug  = "vulnerabilities-debian-12-tar-util-linux-617d48d"
	javaSlug = "grype-quality-java-log4j-two-jars-e363e44"
	npmSlug  = "grype-quality-npm-babel-8e253b5"
)

// failsOn are each check's failsOn in a gate's /state: the rows deciding it.
func failsOn(t *testing.T, h http.Handler, gate string) map[string][]string {
	t.Helper()
	var st struct {
		Gate struct{ Result struct{ Checks []labelserver.CheckResult } }
	}
	get(t, h, "/api/gates/"+gate+"/state", &st)
	out := map[string][]string{}
	for _, c := range st.Gate.Result.Checks {
		out[c.Name] = c.FailsOn
	}
	return out
}

// rowEffects are each row's effect in a gate's /state, by row id.
func rowEffects(t *testing.T, h http.Handler, gate string) map[string]string {
	t.Helper()
	var st struct {
		Subjects []struct{ Rows []struct{ ID, Effect string } }
	}
	get(t, h, "/api/gates/"+gate+"/state", &st)
	out := map[string]string{}
	for _, s := range st.Subjects {
		for _, r := range s.Rows {
			out[r.ID] = r.Effect
		}
	}
	return out
}

// findingLines are a check's findings as "<row> <effect> <label verdict|-> <hint kind|->", in order.
func findingLines(f labelserver.CheckFindings) []string {
	var out []string
	for _, x := range f.Findings {
		label, hint := "-", "-"
		if x.Label != nil {
			label = x.Label.Verdict
		}
		if x.Hint != nil {
			hint = x.Hint.Kind
		}
		out = append(out, x.Row+" "+x.Effect+" "+label+" "+hint)
	}
	return out
}

// checkGateTables asserts the /ui/gates/ tables over the seeded workspace, as SCENARIO.md has it.
func checkGateTables(t *testing.T, h http.Handler) {
	var f1 labelserver.CheckFindings
	get(t, h, "/api/gates/deb-java/checks/f1NotWorse/findings", &f1)
	// java has no tp or fp label, which fails it outright: any label on a java row changes that.
	// deb is undecided, so its two fp labels are counted, not deciding
	want := []string{
		"e1af7851f0e60bb4 could-move - proposal",
		"783bbb63489d81a6 could-move - proposal",
		"42c45bf99e4f741b could-move unclear proposal",
		"a88b3bd584c62516 could-move unclear proposal",
		"c54934489d4ac861 counted fp -",
		"6d210210168e93db counted fp -",
		"d2572e8f87a44f74 counted - cause",
		"781d813b74ed9e10 counted - cause",
		"12fab8dbf4fcf9e8 counted - cause",
		"0fe9fc814bcd060a counted - proposal",
		"e3bfd3b0b0c30ee6 counted - -",
		"9f5eb52729c83cc1 counted - cause",
	}
	if got := findingLines(f1); !slices.Equal(got, want) {
		t.Errorf("f1NotWorse findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	wantImages := map[string]labelserver.Tally{
		debSlug:  {FP: 2, Hinted: 5, Open: 6, Total: 8},
		javaSlug: {Unclear: 2, Hinted: 2, Open: 2, Total: 4},
	}
	if f1.Check.State != "fail" || f1.Check.Threshold != 0 || !maps.Equal(f1.Images, wantImages) {
		t.Errorf("f1NotWorse: %+v %+v", f1.Check, f1.Images)
	}
	// /state says the same: no label decides f1NotWorse, since the subject its labels count in passes
	if got := failsOn(t, h, "deb-java")["f1NotWorse"]; len(got) != 0 {
		t.Errorf("f1NotWorse failsOn in /state: %v", got)
	}
	// and each row's effect in /state is its strongest over the checks: the deb fp labels count, the
	// java rows could move f1NotWorse
	effects := rowEffects(t, h, "deb-java")
	for id, want := range map[string]string{"c54934489d4ac861": "counted", "6d210210168e93db": "counted", "e1af7851f0e60bb4": "could-move", "d2572e8f87a44f74": "counted"} {
		if effects[id] != want {
			t.Errorf("row %s effect in /state: %q, want %q", id, effects[id], want)
		}
	}
	x := f1.Findings[4]
	if x.Image.Name != "vulnerabilities-debian-12-tar-util-linux:617d48d" || x.Image.Slug != debSlug || !strings.HasPrefix(x.Image.Ref, "oci:ghcr.io/anchore/test-images/vulnerabilities-debian-12-tar-util-linux:617d48d@sha256:") ||
		x.Vulnerability != "CVE-2011-3389" || x.Package.Name != "libgnutls30" || x.Direction != "dropped" || x.Label.Justification != "fix-installed" {
		t.Errorf("the libgnutls30 finding: %+v", x)
	}

	var fn labelserver.CheckFindings
	get(t, h, "/api/gates/deb-java/checks/noNewFalseNegatives/findings", &fn)
	// a dropped row is all deb has for it; the added java rows move it only by giving java a label
	want = []string{
		"e1af7851f0e60bb4 could-move - proposal",
		"783bbb63489d81a6 could-move - proposal",
		"42c45bf99e4f741b could-move unclear proposal",
		"a88b3bd584c62516 could-move unclear proposal",
		"0fe9fc814bcd060a counted - proposal",
		"e3bfd3b0b0c30ee6 counted - -",
	}
	if got := findingLines(fn); !slices.Equal(got, want) {
		t.Errorf("noNewFalseNegatives findings:\n%s", strings.Join(got, "\n"))
	}

	var labels labelserver.GateLabels
	get(t, h, "/api/gates/deb-java/labels", &labels)
	var lines []string
	for _, l := range labels.Labels {
		img := "global"
		if l.Image != nil {
			img = l.Image.Slug
		}
		lines = append(lines, string(l.Verdict)+" "+l.Vulnerability+" "+l.Package.Name+" "+img+" "+l.Row)
	}
	want = []string{
		"tp CVE-2026-5450 libc6 " + debSlug + " ",
		"fp CVE-2026-5704 tar " + debSlug + " 6d210210168e93db",
		"fp CVE-2011-3389 libgnutls30 global c54934489d4ac861",
		"unclear GHSA-vc5p-v9hr-52mj log4j-core " + javaSlug + " 42c45bf99e4f741b",
	}
	if labels.Total != 4 || !maps.Equal(labels.Counts, map[string]int{"tp": 1, "fp": 2, "unclear": 1}) ||
		!maps.Equal(labels.PerImage, map[string]int{debSlug: 3, javaSlug: 1}) || len(labels.Sources) != 1 || !slices.Equal(lines, want) {
		t.Errorf("deb-java labels: %d %v %v %v\n%s", labels.Total, labels.Counts, labels.PerImage, labels.Sources, strings.Join(lines, "\n"))
	}
	// counts leave out the verdict filter, perImage the image filter
	labels = labelserver.GateLabels{} // a decode merges into maps it is given
	get(t, h, "/api/gates/deb-java/labels?image="+javaSlug+"&verdict=fp", &labels)
	if labels.Total != 0 || !maps.Equal(labels.Counts, map[string]int{"tp": 0, "fp": 0, "unclear": 1}) || !maps.Equal(labels.PerImage, map[string]int{debSlug: 2, javaSlug: 0}) {
		t.Errorf("deb-java labels, java fp: %d %v %v", labels.Total, labels.Counts, labels.PerImage)
	}
	labels = labelserver.GateLabels{}
	get(t, h, "/api/gates/deb-java/labels?q=tar&offset=0&limit=1", &labels)
	if labels.Total != 1 || len(labels.Labels) != 1 || labels.Labels[0].Vulnerability != "CVE-2026-5704" {
		t.Errorf("deb-java labels about tar: %+v", labels)
	}
	// npm has no deb package, so the global libgnutls30 label is deb's alone
	labels = labelserver.GateLabels{}
	get(t, h, "/api/gates/deb-npm/labels", &labels)
	if labels.Total != 3 || !maps.Equal(labels.PerImage, map[string]int{debSlug: 3, npmSlug: 0}) {
		t.Errorf("deb-npm labels: %d %v", labels.Total, labels.PerImage)
	}

	// the rail's counts: the changed rows per image
	var st struct {
		Subjects []struct {
			Slug    string
			Changes labelserver.Tally
		}
	}
	get(t, h, "/api/gates/deb-java/state", &st)
	if len(st.Subjects) != 2 || st.Subjects[0].Changes != wantImages[debSlug] || st.Subjects[1].Changes != wantImages[javaSlug] {
		t.Errorf("deb-java state counts: %+v", st.Subjects)
	}
	// and the gate list's strip, the same counts per gate
	var list labelserver.GateList
	get(t, h, "/api/gates", &list)
	for _, g := range list.Gates {
		if g.ID == "deb-java" && !slices.Equal(g.Changes, []labelserver.Tally{wantImages[debSlug], wantImages[javaSlug]}) {
			t.Errorf("deb-java gate list counts: %+v", g.Changes)
		}
	}
}
