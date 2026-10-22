package collect

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
	"github.com/anchore/yardstick/cmd/yardstick/internal/lookup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

func TestDecodeKeepsGrypesFields(t *testing.T) {
	for _, v := range fixture.GrypeVersions {
		for _, image := range fixture.Images {
			data, err := os.ReadFile(fixture.Grype(v, image))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := Decode(data)
			if err != nil {
				t.Fatalf("%s %s: %v", v, image, err)
			}
			if len(doc.Matches) == 0 {
				continue
			}
			// matchDetails, which a hand parser drops, is kept
			if d := doc.Matches[0].MatchDetails; len(d) == 0 || d[0].Matcher == "" || d[0].SearchedBy == nil {
				t.Errorf("%s %s: expected matchDetails decoded, got %+v", v, image, d)
			}
		}
	}
}

// stubGrype stands in for one setup's grype: it logs its arguments and DB, and prints the fixture
// grype output for the image the SBOM it is given was cataloged from, or fails for the image
// named in $FAIL. Its DB has no records, and it logs at the level it is given.
const stubGrype = `#!/bin/sh
case "$*" in *"db import"*) exit 0 ;; *"db search"*) echo "$(basename "$0") $*" >> "$CALLS.lookups"; echo '[]'; exit 0 ;; esac
echo "[0000] $GRYPE_LOG_LEVEL from $(basename "$0")" >&2
echo "$(basename "$0") $* db=$GRYPE_DB_CACHE_DIR" >> "$CALLS"
if [ -n "$EVENTS" ]; then echo + >> "$EVENTS"; sleep 0.3; echo - >> "$EVENTS"; fi
for a in "$@"; do case "$a" in sbom:*) sbom="${a#sbom:}" ;; esac; done
# the image the SBOM was cataloged from names the fixture output
for n in deb rpm npm java; do grep -q "yardstick-fixture-$n" "$sbom" && name=$n; done
if [ -n "$FAIL" ] && [ "$name" = "$FAIL" ]; then echo "1 error occurred: unable to read $sbom" >&2; exit 1; fi
if [ -n "$GARBAGE" ]; then echo '{"matches": "not a list"}'; exit 0; fi
cat "$OUTPUTS/$(basename "$0")/$name.json"
`

type stubs struct {
	candidate, reference string
	calls                string
}

func newStubs(t *testing.T) stubs {
	t.Helper()
	dir := t.TempDir()
	s := stubs{candidate: filepath.Join(dir, "candidate-grype"), reference: filepath.Join(dir, "reference-grype"), calls: filepath.Join(dir, "calls")}
	outputs := t.TempDir()
	for stub, version := range map[string]string{"candidate-grype": "v0.120.1", "reference-grype": "v0.119.0"} {
		// the comment makes each stub a different binary, as two grype versions are
		if err := os.WriteFile(filepath.Join(dir, stub), []byte(stubGrype+"# "+version+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(fixture.Path("grype", version), filepath.Join(outputs, stub)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CALLS", s.calls)
	t.Setenv("OUTPUTS", outputs)
	t.Setenv("FAIL", "")
	t.Setenv("GARBAGE", "")
	t.Setenv("EVENTS", "")
	return s
}

func (s stubs) log(t *testing.T) []string {
	t.Helper()
	data, _ := os.ReadFile(s.calls)
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// gate is a two-setup gate over the deb image (its SBOM in the claims source) and the npm SBOM
// document, on a DB directory, so nothing is downloaded.
func gate(t *testing.T, s stubs) *gatefile.Gate {
	t.Helper()
	corpus := t.TempDir()
	debRef, err := ref.Parse("oci:docker.io/anchore/yardstick-fixture-deb@sha256:617d48dd2601779266746a9a382bfb9f3fee2744fba698733b320366f41718b0")
	if err != nil {
		t.Fatal(err)
	}
	sbom, _ := os.ReadFile(fixture.SBOM("deb", "syft"))
	write(t, filepath.Join(corpus, claimsv1.ImageDir(debRef), claimsv1.ImageSBOMFile), sbom)
	npm, err := ref.Parse("sbom:" + fixture.SBOM("npm", "syft"))
	if err != nil {
		t.Fatal(err)
	}
	db := "dir:" + t.TempDir()
	return &gatefile.Gate{
		Name:      "deb-and-npm",
		Candidate: &gatefile.Setup{Grype: s.candidate, DB: db},
		Reference: &gatefile.Setup{Grype: s.reference, DB: db},
		Claims:    []gatefile.Source{{Locator: corpus}},
		Subjects:  []gatefile.Subject{{Ref: debRef, Name: "deb"}, {Ref: npm, Name: "npm"}},
	}
}

func write(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func scanner() Scans {
	run := execute.Runner{}
	return Scans{Run: run, RunName: runrecord.DefaultName, Preparer: setup.NewPreparer(install.NewResolver(), run), Build: func(context.Context, ref.Ref, string, *subject.Catalog) ([]byte, error) {
		panic("no subject here is built")
	}}
}

// tree is every file under dir with the sha256 of its bytes.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := os.ReadFile(p)
			sum := sha256.Sum256(data)
			out[p] = hex.EncodeToString(sum[:])
		}
		return err
	})
	return out
}

func TestScanGate(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	s := newStubs(t)
	g := gate(t, s)
	rec, err := scanGate(t, scanner(), g)
	if err != nil {
		t.Fatal(err)
	}

	// both setups scan one SBOM per subject, pinned to their DB
	bySBOM := map[string][]string{}
	for _, call := range s.log(t) {
		fields := strings.Fields(call)
		for _, f := range fields {
			if strings.HasPrefix(f, "sbom:") {
				bySBOM[f] = append(bySBOM[f], fields[0])
			}
		}
		if !strings.Contains(call, "db="+strings.TrimPrefix(g.Candidate.DB, "dir:")) {
			t.Errorf("grype ran without its DB pinned: %s", call)
		}
	}
	if len(bySBOM) != 2 {
		t.Fatalf("expected two SBOMs scanned, got %v", bySBOM)
	}
	for sbom, setups := range bySBOM {
		if len(setups) != 2 || setups[0] == setups[1] {
			t.Errorf("expected %s scanned once by each setup, got %v", sbom, setups)
		}
	}

	// the record says what each setup resolved to, where each SBOM came from, and what was read
	loaded, err := runrecord.Load(runrecord.DefaultName, g.Name)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Gate.Fingerprint != g.Fingerprint() || loaded.Setups[Candidate].Grype.SHA256 == "" || loaded.Setups[Reference].Grype.Spec.Path != s.reference {
		t.Errorf("expected the gate and both setups recorded, got %+v", loaded)
	}
	deb, npm := loaded.Subjects[0], loaded.Subjects[1]
	if deb.From != subject.FromSource || deb.Source != g.Claims[0].Locator || npm.From != subject.FromFile || deb.Digest == "" || deb.Syft != "1.54.1" || len(deb.Packages) == 0 {
		t.Errorf("expected each subject's SBOM, digest, origin and packages recorded, got %+v / %+v", deb.Resolved, npm.Resolved)
	}
	if len(loaded.Claims) != 1 || !strings.HasPrefix(loaded.Claims[0].Snapshot, "sha256:") {
		t.Errorf("expected the claims source's snapshot recorded, got %+v", loaded.Claims)
	}
	want, _ := os.ReadFile(fixture.Grype("v0.119.0", "deb"))
	got, _ := os.ReadFile(filepath.Join(runrecord.Dir(runrecord.DefaultName, g.Name), deb.Scans[Reference]))
	if string(got) != string(want) || rec.Subjects[1].Scans[Candidate] == "" {
		t.Errorf("expected each setup's grype output kept as written")
	}

	// a rerun that fails on one subject leaves the last scans byte for byte
	before := tree(t, runrecord.RunsDir)
	t.Setenv("FAIL", "npm")
	_, err = scanGate(t, scanner(), g)
	if err == nil || !strings.Contains(err.Error(), "subject npm") || !strings.Contains(err.Error(), "setup") || !strings.Contains(err.Error(), "unable to read") {
		t.Fatalf("expected a failure naming the subject, the setup and grype's stderr, got %v", err)
	}
	after := tree(t, runrecord.RunsDir)
	if len(before) != len(after) {
		t.Errorf("a failed rerun changed the scans: %d files, then %d", len(before), len(after))
	}
	for p, sum := range before {
		if after[p] != sum {
			t.Errorf("a failed rerun changed %s", p)
		}
	}
}

func TestOutputGrypesModelsReject(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	s := newStubs(t)
	t.Setenv("GARBAGE", "1")
	_, err := scanGate(t, scanner(), gate(t, s))
	if err == nil || !strings.Contains(err.Error(), "subject ") || !strings.Contains(err.Error(), "setup (grype ") || !strings.Contains(err.Error(), "grype's own models do not read") {
		t.Errorf("expected a failure naming the subject, the setup and grype, got %v", err)
	}
	if _, err := os.Stat(runrecord.Dir(runrecord.DefaultName, "deb-and-npm")); !os.IsNotExist(err) {
		t.Errorf("expected no scans kept, got %v", err)
	}
}

// with --inherit-env the record names each inherited variable and holds nothing of its value,
// which may be a credential
func TestInheritedEnvValuesStayOutOfTheRecord(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	const secret = "hunter2-registry-password"
	t.Setenv("SYFT_REGISTRY_AUTH_PASSWORD", secret)
	s := newStubs(t)
	g := gate(t, s)
	m := scanner()
	m.Run.InheritEnv = true
	rec, err := scanGate(t, m, g)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range rec.InheritedEnv {
		found = found || k == "SYFT_REGISTRY_AUTH_PASSWORD"
	}
	if !found {
		t.Errorf("expected the inherited variable named, got %v", rec.InheritedEnv)
	}
	data, err := os.ReadFile(filepath.Join(runrecord.Dir(runrecord.DefaultName, g.Name), runrecord.File))
	sum := sha256.Sum256([]byte(secret))
	if err != nil || strings.Contains(string(data), secret) || strings.Contains(string(data), hex.EncodeToString(sum[:])) {
		t.Errorf("the inherited value, or its digest, reached the record on disk (%v)", err)
	}
}

// maxRunning is the most grype processes the stub had started and not finished at once.
func maxRunning(t *testing.T, events string) int {
	t.Helper()
	data, _ := os.ReadFile(events)
	cur, most := 0, 0
	for _, c := range strings.TrimSpace(string(data)) {
		switch c {
		case '+':
			cur++
		case '-':
			cur--
		}
		most = max(most, cur)
	}
	return most
}

func TestParallelismBoundsRunningGrypes(t *testing.T) {
	// four scans: two subjects, each with two setups
	for _, tc := range []struct{ limit, want int }{{1, 1}, {2, 2}, {4, 4}} {
		t.Run(strconv.Itoa(tc.limit), func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
			s := newStubs(t)
			events := filepath.Join(t.TempDir(), "events")
			t.Setenv("EVENTS", events)
			m := scanner()
			m.Parallelism = tc.limit
			if _, err := scanGate(t, m, gate(t, s)); err != nil {
				t.Fatal(err)
			}
			if got := maxRunning(t, events); got != tc.want {
				t.Errorf("expected at most %d grypes at once and that many reached, got %d", tc.want, got)
			}
		})
	}
}

func TestParallelismBelowOneFailsBeforeAnyScan(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	s := newStubs(t)
	m := scanner()
	m.Parallelism = -1
	_, err := scanGate(t, m, gate(t, s))
	if err == nil || !strings.Contains(err.Error(), "--parallelism") {
		t.Errorf("expected a parallelism error, got %v", err)
	}
	if _, err := os.Stat(s.calls); !os.IsNotExist(err) {
		t.Errorf("expected no grype run, got %v", err)
	}
	if CheckParallelism(0) == nil || CheckParallelism(1) != nil {
		t.Errorf("expected 0 rejected and 1 accepted")
	}
}

// the first failure cancels the scans not yet started: with one at a time, the failing npm scan
// is the third, so the fourth never runs
func TestFirstFailureCancelsTheRest(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	s := newStubs(t)
	t.Setenv("FAIL", "npm")
	m := scanner()
	m.Parallelism = 1
	if _, err := scanGate(t, m, gate(t, s)); err == nil {
		t.Fatal("expected the failure")
	}
	if n := len(s.log(t)); n != 3 {
		t.Errorf("expected 3 grype runs before the cancel, got %d", n)
	}
}

// stubLoaderGrype reads its config the way grype's loader does: with no -c, ~/.grype.yaml applies,
// and its ignore rule drops every match.
const stubLoaderGrype = `#!/bin/sh
if [ "$1" != "-c" ] && grep -qs ignore "$HOME/.grype.yaml"; then echo '{"matches":[]}'; exit 0; fi
cat "$OUTPUT"
`

// grype-runs-with-its-db-pinned, a config in the user's home directory
func TestHomeConfigDoesNotChangeAScan(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	grype := filepath.Join(t.TempDir(), "grype")
	write(t, grype, []byte(stubLoaderGrype))
	if err := os.Chmod(grype, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OUTPUT", filepath.Join(fixture.Path("grype", "v0.120.1"), "deb.json"))
	p := setup.Prepared{Grype: install.Tool{Bin: grype}}

	t.Setenv("HOME", t.TempDir())
	_, _, without, err := Scan(context.Background(), execute.Runner{}, p, "deb.syft.json")
	if err != nil {
		t.Fatal(err)
	}
	if without == 0 {
		t.Fatal("expected the fixture scan to hold matches")
	}

	home := t.TempDir()
	write(t, filepath.Join(home, ".grype.yaml"), []byte("ignore:\n  - vulnerability: CVE-2018-19591\n"))
	t.Setenv("HOME", home)
	_, _, with, err := Scan(context.Background(), execute.Runner{}, p, "deb.syft.json")
	if err != nil {
		t.Fatal(err)
	}
	if with != without {
		t.Errorf("expected %d matches with a home config as without one, got %d", without, with)
	}
}

// scanGate opens the gate's claims once and scans with them, as the command does.
func scanGate(t *testing.T, m Scans, g *gatefile.Gate) (*runrecord.Record, error) {
	t.Helper()
	set, err := claims.OpenSet(g.Claims)
	if err != nil {
		t.Fatal(err)
	}
	return m.Gate(context.Background(), g, set)
}

// each scan keeps its grype log gzipped beside it, with the sha256 of its text, and a reused scan
// keeps the log stored with it; each DB is asked about the rows only the other setup reported
func TestScanKeepsLogsAndLookups(t *testing.T) {
	s, g, _ := cachedEnv(t)
	// the reference reports nothing on the deb image, so every candidate match there is one-sided
	outputs := t.TempDir()
	if err := os.Symlink(fixture.Path("grype", "v0.120.1"), filepath.Join(outputs, "candidate-grype")); err != nil {
		t.Fatal(err)
	}
	npm, _ := os.ReadFile(fixture.Grype("v0.119.0", "npm"))
	write(t, filepath.Join(outputs, "reference-grype", "npm.json"), npm)
	write(t, filepath.Join(outputs, "reference-grype", "deb.json"), []byte(`{"matches": []}`))
	t.Setenv("OUTPUTS", outputs)
	for range 2 {
		rec := run(t, g)
		dir := runrecord.Dir(runrecord.DefaultName, g.Name)
		for _, sub := range rec.Subjects {
			for _, setup := range []string{Candidate, Reference} {
				l := sub.Logs[setup]
				data, err := os.ReadFile(filepath.Join(dir, l.Path))
				if err != nil {
					t.Fatalf("subject %s, %s: %v", sub.Name, setup, err)
				}
				zr, err := gzip.NewReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				text, _ := io.ReadAll(zr)
				sum := sha256.Sum256(text)
				if want := "[0000] trace from " + setup + "-grype\n"; string(text) != want || hex.EncodeToString(sum[:]) != l.SHA256 {
					t.Errorf("subject %s, %s: expected the trace log and its sha256, got %q", sub.Name, setup, text)
				}
			}
		}
		if rec.Lookups[Candidate] != "candidate/lookups.json" || rec.Lookups[Reference] != "reference/lookups.json" {
			t.Errorf("expected both DBs' lookups recorded, got %v", rec.Lookups)
		}
		for _, rel := range rec.Lookups {
			if _, err := lookup.Load(filepath.Join(dir, rel)); err != nil {
				t.Error(err)
			}
		}
	}
	if got := s.scanCalls(t); got["candidate-grype"] != 2 {
		t.Errorf("expected the second run to reuse the scans, got %v", got)
	}
	calls, _ := os.ReadFile(s.calls + ".lookups")
	for _, stub := range []string{"candidate-grype", "reference-grype"} {
		if !strings.Contains(string(calls), stub+" -c ") {
			t.Errorf("expected %s searched with its config, got\n%s", stub, calls)
		}
	}
}

// Ctrl-C mid-scan: clio cancels the command's context, the run fails, and the last good scans
// stay as they were rather than being replaced by a record with scans missing
func TestCancelMidScanKeepsTheLastScans(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	s := newStubs(t)
	g := gate(t, s)
	if _, err := scanGate(t, scanner(), g); err != nil {
		t.Fatal(err)
	}
	before := tree(t, runrecord.RunsDir)

	// each scan now takes 0.3s, one at a time; cancel once the first has started
	events := filepath.Join(t.TempDir(), "events")
	t.Setenv("EVENTS", events)
	m := scanner()
	m.Parallelism, m.Rescan = 1, true
	set, err := claims.OpenSet(g.Claims)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			if _, err := os.Stat(events); err == nil {
				cancel()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	_, err = m.Gate(ctx, g, set)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected the run to fail as cancelled, got %v", err)
	}
	if n := len(s.log(t)); n != 4+1 {
		t.Errorf("expected the first run's 4 scans and the one the cancel killed, got %d grype runs", n)
	}
	after := tree(t, runrecord.RunsDir)
	if len(before) != len(after) {
		t.Errorf("a cancelled rerun changed the scans: %d files, then %d", len(before), len(after))
	}
	for p, sum := range before {
		if after[p] != sum {
			t.Errorf("a cancelled rerun changed %s", p)
		}
	}
}
