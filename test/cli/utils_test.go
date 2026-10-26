package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/db/v6/testdb"
)

// claimsPin is the published anchore/claims snapshot every scenario reads its labels from, ahead of
// the workspace's own claims/ where the tests write theirs.
const claimsPin = "github.com/anchore/claims@dc0289a3a409265fb2c37d3526ec94385998cfcb"

// bin is the yardstick binary under test: YARDSTICK_BINARY_LOCATION when set (a snapshot build in
// CI), else built once from this checkout.
var bin string

func TestMain(m *testing.M) {
	os.Exit(func() int {
		bin = os.Getenv("YARDSTICK_BINARY_LOCATION")
		if bin == "" {
			dir, err := os.MkdirTemp("", "yardstick-cli-")
			if err != nil {
				panic(err)
			}
			defer os.RemoveAll(dir)
			bin = filepath.Join(dir, "yardstick")
			cmd := exec.Command("go", "build", "-o", bin, "./cmd/yardstick")
			cmd.Dir = repoRoot()
			if out, err := cmd.CombinedOutput(); err != nil {
				panic(string(out))
			}
		}
		return m.Run()
	}())
}

func repoRoot() string {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		panic(err)
	}
	return root
}

// cacheDir holds the grype releases, the claims snapshot and the SBOMs, shared by every scenario and
// kept across runs: YARDSTICK_CACHE_DIR, else .tmp/cli/cache as `make cli` sets it.
func cacheDir() string {
	if d := os.Getenv("YARDSTICK_CACHE_DIR"); d != "" {
		return d
	}
	return filepath.Join(repoRoot(), ".tmp", "cli", "cache")
}

// step runs one step of a scenario as a subtest. Every step builds on the one before, so the
// scenario stops at the first that fails.
func step(t *testing.T, name string, fn func(t *testing.T)) {
	t.Helper()
	if !t.Run(name, fn) {
		t.FailNow()
	}
}

type traitAssertion func(tb testing.TB, stdout, stderr string, rc int)

func assertReturnCode(want int) traitAssertion {
	return func(tb testing.TB, _, stderr string, rc int) {
		tb.Helper()
		if rc != want {
			tb.Errorf("expected exit %d, got %d:\n%s", want, rc, stderr)
		}
	}
}

func assertInOutput(want string) traitAssertion {
	return func(tb testing.TB, stdout, stderr string, _ int) {
		tb.Helper()
		if !strings.Contains(stdout, want) && !strings.Contains(stderr, want) {
			tb.Errorf("expected %q in the output, got:\n%s%s", want, stdout, stderr)
		}
	}
}

// workspace is a scenario's working directory: its gates, a DB built from its records, an app
// config naming the pinned claims and ./claims, and whatever yardstick writes as it runs.
type workspace struct {
	dir      string
	scenario string
}

func newWorkspace(t *testing.T, scenario string) *workspace {
	t.Helper()
	src := filepath.Join("testdata", scenario)
	w := &workspace{dir: t.TempDir(), scenario: scenario}
	for _, d := range []string{"gates", "grype"} {
		if _, err := os.Stat(filepath.Join(src, d)); err == nil {
			if err := os.CopyFS(filepath.Join(w.dir, d), os.DirFS(filepath.Join(src, d))); err != nil {
				t.Fatal(err)
			}
		}
	}
	buildDB(t, filepath.Join(src, "vunnel"), filepath.Join(w.dir, "db"))
	if err := os.WriteFile(filepath.Join(w.dir, ".yardstick.yaml"), []byte("claims: ["+claimsPin+", ./claims]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return w
}

// buildDB builds a v6 DB from a vunnel flat-file workspace into dir in grype's cache layout, so a
// gate reads it with db: dir:<dir>. The build stamps the time, so every build has its own identity.
func buildDB(t *testing.T, records, dir string) {
	t.Helper()
	// the builder writes metadata and checksums into its input, so it reads a copy, and only the
	// provider directories: the extractor's db.yaml and db-lock.json sit beside them
	in := t.TempDir()
	entries, err := os.ReadDir(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			if err := os.CopyFS(filepath.Join(in, e.Name()), os.DirFS(filepath.Join(records, e.Name()))); err != nil {
				t.Fatal(err)
			}
		}
	}
	// an include pattern also skips the builder's "output newer than input" shortcut
	testdb.BuildFromFlatFileDir(t, time.Now(), filepath.Join(dir, "6"), in, "**/*.json")
}

// yardstick runs the binary in the workspace, applies the traits and returns stdout.
func (w *workspace) yardstick(t *testing.T, args []string, traits ...traitAssertion) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = w.dir
	// assertions read plain text, even where CI would color it
	cmd.Env = append(os.Environ(), "YARDSTICK_CACHE_DIR="+cacheDir(), "NO_COLOR=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	rc := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		rc = exit.ExitCode()
	}
	t.Logf("yardstick %s: exit %d", strings.Join(args, " "), rc)
	for _, trait := range traits {
		trait(t, stdout.String(), stderr.String(), rc)
	}
	return stdout.String()
}

// report is the part of `-o json` the scenarios read, for one gate.
type report struct {
	Name    string
	Outcome string
	Header  struct {
		Scanned string
		Varied  []struct{ Input string }
		Claims  []struct{ Locator, Snapshot, Commit string }
	}
	Checks   []check
	Effects  []effect
	Subjects []struct {
		Name    string
		Matches []row
	}
}

type check struct {
	Name  string
	State string
	Value struct{ Best, Worst float64 }
}

// effect is what labeling one open row would do: each check's state per verdict.
type effect struct {
	Subject string
	Match   string
	States  map[string]map[string]string
}

type row struct {
	ID            string
	Vulnerability string
	Package       string
	Verdict       string
	Direction     string
	InCandidate   bool
	InReference   bool
	Why           *struct{ Key string }
}

func parseReport(t *testing.T, stdout string) report {
	t.Helper()
	var r struct{ Gates []report }
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("expected a JSON report: %v\n%s", err, stdout)
	}
	if len(r.Gates) != 1 {
		t.Fatalf("expected one gate in the report, got %d", len(r.Gates))
	}
	return r.Gates[0]
}

// run runs a gate, scanning, and returns its JSON report; the default text report goes to stdout for the
// light checks the traits make.
func (w *workspace) run(t *testing.T, gate string, traits ...traitAssertion) report {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.json")
	w.yardstick(t, []string{"gates/" + gate + ".yaml", "-o", "cause", "-o", "json=" + out}, traits...)
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return parseReport(t, string(data))
}

// score re-scores a gate's last scans against the labels as they are now.
func (w *workspace) score(t *testing.T, gate string) report {
	t.Helper()
	return parseReport(t, w.yardstick(t, []string{"score", "gates/" + gate + ".yaml", "-o", "json"}))
}

func (r report) states() map[string]string {
	out := map[string]string{}
	for _, c := range r.Checks {
		out[c.Name] = c.State
	}
	return out
}

func (r report) row(id string) (row, bool) {
	for _, s := range r.Subjects {
		for _, m := range s.Matches {
			if m.ID == id {
				return m, true
			}
		}
	}
	return row{}, false
}

// changed is the vulnerabilities of the rows only one setup reported, by direction, sorted.
func (r report) changed() map[string][]string {
	out := map[string][]string{}
	for _, s := range r.Subjects {
		for _, m := range s.Matches {
			if m.InCandidate != m.InReference {
				out[m.Direction] = append(out[m.Direction], m.Vulnerability)
			}
		}
	}
	for _, v := range out {
		slices.Sort(v)
	}
	return out
}

func assertOutcome(t *testing.T, r report, want string) {
	t.Helper()
	if r.Outcome != want {
		t.Errorf("gate %s: expected outcome %s, got %s (checks %v)", r.Name, want, r.Outcome, r.states())
	}
}

func assertStates(t *testing.T, r report, want map[string]string) {
	t.Helper()
	got := r.states()
	for name, state := range want {
		if got[name] != state {
			t.Errorf("gate %s: expected check %s %s, got %s", r.Name, name, state, got[name])
		}
	}
	if len(got) != len(want) {
		t.Errorf("gate %s: expected checks %v, got %v", r.Name, want, got)
	}
}

// assertHeader checks the gate varies only the given inputs and reads the pinned claims first.
func assertHeader(t *testing.T, r report, varied ...string) {
	t.Helper()
	var got []string
	for _, v := range r.Header.Varied {
		got = append(got, v.Input)
	}
	if !slices.Equal(got, varied) {
		t.Errorf("gate %s: expected header.varied %v, got %v", r.Name, varied, got)
	}
	if len(r.Header.Claims) == 0 || r.Header.Claims[0].Locator != claimsPin || !strings.HasSuffix(claimsPin, "@"+r.Header.Claims[0].Commit) {
		t.Errorf("gate %s: expected header.claims to start with %s at its commit, got %+v", r.Name, claimsPin, r.Header.Claims)
	}
}

// assertChanged checks the changed rows by direction, and that each has a computed reason.
func assertChanged(t *testing.T, r report, want map[string][]string) {
	t.Helper()
	got := r.changed()
	for dir, vulns := range want {
		if !slices.Equal(got[dir], vulns) {
			t.Errorf("gate %s: expected %s rows %v, got %v", r.Name, dir, vulns, got[dir])
		}
	}
	if len(got) != len(want) {
		t.Errorf("gate %s: expected changed rows %v, got %v", r.Name, want, got)
	}
	for _, s := range r.Subjects {
		for _, m := range s.Matches {
			if m.InCandidate != m.InReference && (m.Why == nil || m.Why.Key == "" || m.Why.Key == "unexplained") {
				t.Errorf("gate %s: expected a computed reason for %s on %s, got %+v", r.Name, m.Vulnerability, m.Package, m.Why)
			}
		}
	}
}

// assertWhy checks every changed row's primary computed reason.
func assertWhy(t *testing.T, r report, key string) {
	t.Helper()
	for _, s := range r.Subjects {
		for _, m := range s.Matches {
			if m.InCandidate != m.InReference && (m.Why == nil || m.Why.Key != key) {
				t.Errorf("gate %s: expected the reason %s for %s on %s, got %+v", r.Name, key, m.Vulnerability, m.Package, m.Why)
			}
		}
	}
}

// labelAsPredicted labels the gate's first open row with verdict through `claims add`, re-scores,
// and checks every check landed on the state that row's effect predicted for that verdict: the
// report's promise rather than a hard-coded number. It also checks the score ran no scan and the
// label landed in claims/ with seenIn filled. It returns the new report.
func (w *workspace) labelAsPredicted(t *testing.T, gate, verdict, justification string) report {
	t.Helper()
	before := w.score(t, gate)
	if len(before.Effects) == 0 {
		t.Fatalf("gate %s: expected an open row to label, got none", gate)
	}
	e := before.Effects[0]
	r, ok := before.row(e.Match)
	if !ok {
		t.Fatalf("gate %s: the effect names row %s, which the report doesn't have", gate, e.Match)
	}
	want := e.States[verdict]
	runs := w.runFiles(t)

	args := []string{"claims", "add", "--gate", "gates/" + gate + ".yaml", "--subject", e.Subject,
		"--package", r.Package, "--vulnerability", r.Vulnerability, "--verdict", verdict, "--author", "cli-test"}
	if justification != "" {
		args = append(args, "--justification", justification)
	}
	w.yardstick(t, args, assertReturnCode(0))
	after := w.score(t, gate)

	for name, state := range after.states() {
		if state != want[name] {
			t.Errorf("gate %s: labeled %s %s, so its effect predicted check %s %s, got %s", gate, r.Vulnerability, verdict, name, want[name], state)
		}
	}
	if got, _ := after.row(e.Match); got.Verdict != verdict {
		t.Errorf("gate %s: expected row %s to read the new %s label, got %q", gate, e.Match, verdict, got.Verdict)
	}
	if after.Header.Scanned != before.Header.Scanned || !equalMaps(runs, w.runFiles(t)) {
		t.Errorf("gate %s: expected score to reuse the scans from %s, got a scan at %s", gate, before.Header.Scanned, after.Header.Scanned)
	}
	w.assertLabelWritten(t, r.Vulnerability, r.Package, verdict)
	return after
}

// labelThrough labels every open row of the gate, one at a time, each as predicted.
func (w *workspace) labelThrough(t *testing.T, gate, verdict, justification string) report {
	t.Helper()
	r := w.score(t, gate)
	for len(r.Effects) > 0 && !t.Failed() {
		r = w.labelAsPredicted(t, gate, verdict, justification)
	}
	return r
}

// runFiles is every file under .yardstick/runs with its modification time: a scan rewrites some.
func (w *workspace) runFiles(t *testing.T) map[string]time.Time {
	t.Helper()
	out := map[string]time.Time{}
	err := filepath.WalkDir(filepath.Join(w.dir, ".yardstick", "runs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out[p] = info.ModTime()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func equalMaps(a, b map[string]time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !b[k].Equal(v) {
			return false
		}
	}
	return true
}

// labelFile is the part of a label file the scenarios read.
type labelFile struct {
	Labels []struct {
		Package, Vulnerability, Verdict string
		SeenIn                          *struct {
			SBOM  string
			Tools []struct{ Name, Version string }
		}
	}
}

func (w *workspace) assertLabelWritten(t *testing.T, vuln, pkg, verdict string) {
	t.Helper()
	found := false
	err := filepath.WalkDir(filepath.Join(w.dir, "claims"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || found {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var lf labelFile
		if err := json.Unmarshal(data, &lf); err != nil {
			return err
		}
		for _, l := range lf.Labels {
			if l.Vulnerability == vuln && l.Package == pkg && l.Verdict == verdict {
				found = true
				if l.SeenIn == nil || l.SeenIn.SBOM == "" || len(l.SeenIn.Tools) == 0 {
					t.Errorf("expected the %s label on %s in %s to carry seenIn, got %+v", vuln, pkg, p, l.SeenIn)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Errorf("expected a %s label for %s on %s under claims/, found none", verdict, vuln, pkg)
	}
}

// validateLabels runs `claims validate` on the labels the test wrote. claims/ is a workspace's
// scratch directory rather than a corpus, so they are laid out as one would be once folded into
// anchore/claims: the pinned snapshot's vocabulary.yaml and catalog.yaml at the root, and its SBOM
// beside each label file's matches/. Those come from the snapshot yardstick cached by its digest.
func (w *workspace) validateLabels(t *testing.T, r report) {
	t.Helper()
	corpus := t.TempDir()
	claims := filepath.Join(w.dir, "claims")
	if err := os.CopyFS(corpus, os.DirFS(claims)); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"vocabulary.yaml": true, "catalog.yaml": true}
	err := filepath.WalkDir(claims, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		// a label file sits in its subject's matches/, and the SBOM beside that
		rel, _ := filepath.Rel(claims, filepath.Dir(filepath.Dir(p)))
		want[filepath.ToSlash(filepath.Join(rel, "sbom.syft.json"))] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := strings.TrimPrefix(r.Header.Claims[0].Snapshot, "sha256:")
	z, err := zip.OpenReader(filepath.Join(cacheDir(), "claims", snapshot+".zip"))
	if err != nil {
		t.Fatalf("expected the pinned snapshot in the cache: %v", err)
	}
	defer z.Close()
	for _, f := range z.File {
		if !want[f.Name] {
			continue
		}
		delete(want, f.Name)
		src, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(corpus, filepath.FromSlash(f.Name))
		data, err := io.ReadAll(src)
		src.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(want) > 0 {
		t.Fatalf("expected the snapshot to hold %v", want)
	}
	w.yardstick(t, []string{"claims", "validate", corpus}, assertReturnCode(0), assertInOutput("is valid"))
}
