package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// logged wraps a stub so each run appends its arguments to calls.
func logged(t *testing.T, stub, calls string) string {
	t.Helper()
	return stubTool(t, filepath.Dir(stub), filepath.Base(stub)+"-logged", "#!/bin/sh\necho \"$*\" >> \""+calls+"\"\nexec \""+stub+"\" \"$@\"\n")
}

// lines is each line a stub logged, none when it never ran.
func lines(t *testing.T, calls string) []string {
	t.Helper()
	data, err := os.ReadFile(calls)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// scanCalls counts the logged runs that scanned an SBOM.
func scanCalls(t *testing.T, calls string) int {
	t.Helper()
	n := 0
	for _, l := range lines(t, calls) {
		if strings.Contains(l, "sbom:") {
			n++
		}
	}
	return n
}

// collect-sboms-for-a-gate: of a gate's three images the claims source holds two, so syft builds
// only the third, into the cache, and no grype starts; the image form and --gate together run
// nothing
func TestCollectSBOMsForAGate(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "cache")
	t.Setenv("YARDSTICK_CACHE_DIR", cache)
	w := newWorkspace(t)
	rpm := "oci:docker.io/anchore/yardstick-fixture-rpm@sha256:" + strings.Repeat("1", 64)
	npm := "oci:docker.io/anchore/yardstick-fixture-npm@sha256:" + strings.Repeat("2", 64)
	r, _ := ref.Parse(rpm)
	sbom, _ := os.ReadFile(fixture.SBOM("rpm", "syft"))
	writeFile(t, filepath.Join(w.dir, "claims", claimsv1.ImageDir(r), claimsv1.ImageSBOMFile), string(sbom))
	syftCalls, grypeCalls := filepath.Join(w.tools, "syft-calls"), filepath.Join(w.tools, "grype-calls")
	syft := stubTool(t, w.tools, "syft", "#!/bin/sh\necho \"$*\" >> \""+syftCalls+"\"\ncat \""+fixture.SBOM("npm", "syft")+"\"\n")
	grype := logged(t, w.grype("grype"), grypeCalls)
	writeFile(t, filepath.Join(w.dir, "gates/three.yaml"), `schema: v1
claims: [../claims]
catalog: {syft: `+syft+`}
candidate: {grype: `+grype+`, db: "dir:`+w.tools+`"}
subjects:
  - {ref: "`+debImage+`", name: deb}
  - {ref: "`+rpm+`", name: rpm}
  - {ref: "`+npm+`", name: npm}
checks: [{name: expectationsMetAtLeast, params: {min: 1}}]
`)

	_, stderr, code := yardstick(t, w.dir, "collect", "sboms", debImage, "--gate", "gates/three.yaml")
	if code != 2 || !strings.Contains(stderr, "the image form (<oci-subject>, --catalog, --out) and --gate are exclusive") {
		t.Errorf("expected exit 2 saying the forms are exclusive, got %d: %s", code, stderr)
	}
	if got := lines(t, syftCalls); got != nil {
		t.Errorf("expected nothing run, got syft %v", got)
	}

	stdout, stderr, code := yardstick(t, w.dir, "collect", "sboms", "--gate", "gates/three.yaml")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d: %s", code, stderr)
	}
	if got := lines(t, syftCalls); len(got) != 1 || !strings.Contains(got[0], "yardstick-fixture-npm@") {
		t.Errorf("expected syft run once, for npm, got %v", got)
	}
	built, _ := filepath.Glob(filepath.Join(cache, "sboms", "sha256:"+strings.Repeat("2", 64), "*.syft.json"))
	if len(built) != 1 || stdout != "wrote "+built[0]+"\n" {
		t.Errorf("expected npm's SBOM written to the cache and named, got %v and %q", built, stdout)
	}
	if got := lines(t, grypeCalls); got != nil {
		t.Errorf("expected no grype process, got %v", got)
	}

	// --rebuild-sboms builds the two the claims source holds as well; npm's is in the cache now and
	// is used from there, as a gate run would
	if _, stderr, code := yardstick(t, w.dir, "collect", "sboms", "--gate", "gates/three.yaml", "--rebuild-sboms"); code != 0 {
		t.Fatalf("expected exit 0, got %d: %s", code, stderr)
	}
	got := lines(t, syftCalls)
	if len(got) != 3 || !strings.Contains(got[1], "yardstick-fixture-deb@") || !strings.Contains(got[2], "yardstick-fixture-rpm@") {
		t.Errorf("expected syft run for deb and rpm, got %v", got)
	}
	if got := lines(t, grypeCalls); got != nil {
		t.Errorf("expected no grype process, got %v", got)
	}

	// a build that fails fails the command, where a gate run would scan the SBOM the source holds
	t.Setenv("YARDSTICK_CACHE_DIR", filepath.Join(t.TempDir(), "cache"))
	stubTool(t, w.tools, "syft", "#!/bin/sh\necho 'unable to pull the image' >&2\nexit 1\n")
	gate, _ := os.ReadFile(filepath.Join(w.dir, "gates/three.yaml"))
	writeFile(t, filepath.Join(w.dir, "gates/held.yaml"), strings.Replace(string(gate), "  - {ref: \""+npm+"\", name: npm}\n", "", 1))
	_, stderr, code = yardstick(t, w.dir, "collect", "sboms", "--gate", "gates/held.yaml", "--rebuild-sboms")
	if code != 2 || !strings.Contains(stderr, "unable to pull the image") {
		t.Errorf("expected exit 2 with syft's error, got %d: %s", code, stderr)
	}
}

// collect-scans-command, scan now, score later: collect scans writes the scans and prints no
// report, and score then fails the gate on the dropped true positive without running grype
func TestCollectScansThenScore(t *testing.T) {
	w := newWorkspace(t)
	w.label(tar, "CVE-2005-2541")
	calls := filepath.Join(w.tools, "calls")
	candidate := logged(t, w.grype("no-tar", "CVE-2005-2541 tar"), calls)
	reference := logged(t, w.grype("whole"), calls)
	w.gate("deb", candidate, reference, "", "  - name: noNewFalseNegatives\n")

	stdout, stderr, code := yardstick(t, w.dir, "collect", "scans", "gates/deb.yaml")
	if code != 0 || stdout != "" {
		t.Fatalf("expected exit 0 and no report, got %d: %q %s", code, stdout, stderr)
	}
	if n := scanCalls(t, calls); n != 2 {
		t.Errorf("expected both setups to scan, got %d scans", n)
	}
	if _, err := os.Stat(filepath.Join(w.dir, ".yardstick", "runs", "default", "deb", "yardstick-run.json")); err != nil {
		t.Errorf("expected the gate's scans written, got %v", err)
	}

	stdout, _, code = yardstick(t, w.dir, "score", "gates/deb.yaml", "-o", "check")
	if code != 1 || !strings.Contains(stdout, "FAIL noNewFalseNegatives") {
		t.Errorf("expected score to fail the gate on the dropped tp, got %d: %s", code, stdout)
	}
	if n := scanCalls(t, calls); n != 2 {
		t.Errorf("expected score to run no grype, got %d scans", n)
	}

	// it takes no report flag
	if _, stderr, code := yardstick(t, w.dir, "collect", "scans", "gates/deb.yaml", "-o", "json"); code != 2 || !strings.Contains(stderr, "unknown shorthand flag: 'o'") {
		t.Errorf("expected -o refused, got %d: %s", code, stderr)
	}
}

// collect-scans-command, same scans as a gate run: a gate run straight after collect scans
// reuses every scan and starts no grype process
func TestGateRunReusesCollectedScans(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", filepath.Join(t.TempDir(), "cache"))
	w := newWorkspace(t)
	calls := filepath.Join(w.tools, "calls")
	candidate := logged(t, w.grype("cand"), calls)
	reference := logged(t, w.grype("ref"), calls)
	// a DB file gives the dir: DB an identity, so its scans are stored
	writeFile(t, filepath.Join(w.tools, "6", "vulnerability.db"), "a DB")
	w.gate("deb", candidate, reference, "", "  - name: noNewFalseNegatives\n")

	if _, stderr, code := yardstick(t, w.dir, "collect", "scans", "gates/deb.yaml"); code != 0 {
		t.Fatalf("expected exit 0, got %d: %s", code, stderr)
	}
	ran := lines(t, calls)
	if len(ran) != 2 {
		t.Fatalf("expected both setups to scan, got %v", ran)
	}
	// the deb subject has no labels, so the gate fails; what matters is that it ran
	if _, stderr, code := yardstick(t, w.dir, "gates/deb.yaml"); code == 2 {
		t.Fatalf("expected the gate run, got %d: %s", code, stderr)
	}
	if got := lines(t, calls); len(got) != len(ran) {
		t.Errorf("expected no grype process, got %v", got[len(ran):])
	}
}

// the old collect <oci-subject> has no alias; collect alone is its help
func TestOldCollectSpelling(t *testing.T) {
	_, stderr, code := yardstick(t, t.TempDir(), "collect", debImage)
	if code != 2 || !strings.Contains(stderr, `unknown command "`+debImage+`" for "yardstick collect"`) {
		t.Errorf("expected exit 2 naming the unknown command, got %d: %s", code, stderr)
	}
	stdout, _, code := yardstick(t, t.TempDir(), "collect")
	if code != 0 || !strings.Contains(stdout, "sboms") || !strings.Contains(stdout, "scans") {
		t.Errorf("expected collect to print its help, got %d:\n%s", code, stdout)
	}
}
