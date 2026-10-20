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
}
