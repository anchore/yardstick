package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/discard"
	"github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/bus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

// cachedEnv is a project directory and cache of their own, and a gate whose setups import a DB
// archive, so its DB is identified by the archive's checksum.
func cachedEnv(t *testing.T) (stubs, *gatefile.Gate, string) {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	s := newStubs(t)
	g := gate(t, s)
	archive := filepath.Join(t.TempDir(), "vulnerability.db.tar.zst")
	write(t, archive, []byte("a DB archive"))
	g.Candidate.DB, g.Reference.DB = archive, archive
	return s, g, archive
}

// scanCalls is how many scans each stub grype ran, by stub name.
func (s stubs) scanCalls(t *testing.T) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, call := range s.log(t) {
		if strings.Contains(call, "sbom:") {
			out[strings.Fields(call)[0]]++
		}
	}
	return out
}

func run(t *testing.T, g *gatefile.Gate) *runrecord.Record {
	t.Helper()
	rec, err := scanGate(t, scanner(), g)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func scanFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(cache.Dir("scans", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// scans-reused-by-input-key, an unchanged rerun
func TestUnchangedRerunStartsNoScan(t *testing.T) {
	s, g, _ := cachedEnv(t)
	first := run(t, g)
	if got := s.scanCalls(t); got["candidate-grype"] != 2 || got["reference-grype"] != 2 {
		t.Fatalf("expected the first run to scan each subject with each setup, got %v", got)
	}
	stored := scanFiles(t)
	if len(stored) != 4 {
		t.Fatalf("expected one stored scan per scan, got %v", stored)
	}
	old := time.Now().Add(-48 * time.Hour)
	for _, f := range stored {
		if err := os.Chtimes(f, old, old); err != nil {
			t.Fatal(err)
		}
	}

	second := run(t, g)
	if got := s.scanCalls(t); got["candidate-grype"] != 2 || got["reference-grype"] != 2 {
		t.Errorf("expected the rerun to start no scan, got %v", got)
	}
	for i, sub := range first.Subjects {
		for name, rel := range sub.Scans {
			want, _ := os.ReadFile(filepath.Join(runrecord.Dir(runrecord.DefaultName, g.Name), rel))
			if got := second.Subjects[i].Scans[name]; got != rel {
				t.Errorf("expected the same scan path, got %s", got)
			}
			if got, _ := os.ReadFile(filepath.Join(runrecord.Dir(runrecord.DefaultName, g.Name), rel)); string(got) != string(want) || len(got) == 0 {
				t.Errorf("expected the reused scan kept as stored")
			}
		}
	}
	// a reuse is a use
	for _, f := range stored {
		if info, err := os.Stat(f); err != nil || time.Since(info.ModTime()) > time.Hour {
			t.Errorf("expected %s touched by the reuse, got %v %v", f, info, err)
		}
	}
}

// scans-reused-by-input-key, a new DB under db: latest: a DB with other bytes is another identity
func TestNewDBScansAgain(t *testing.T) {
	s, g, archive := cachedEnv(t)
	run(t, g)
	write(t, archive, []byte("the DB a new day publishes"))
	run(t, g)
	if got := s.scanCalls(t); got["candidate-grype"] != 4 || got["reference-grype"] != 4 {
		t.Errorf("expected every scan to run again against the new DB, got %v", got)
	}
}

// scans-reused-by-input-key, one setup's config changed
func TestChangedConfigScansOnlyThatSetup(t *testing.T) {
	s, g, _ := cachedEnv(t)
	cfg := filepath.Join(t.TempDir(), "reference.yaml")
	write(t, cfg, []byte("check-for-app-update: false\n"))
	g.Reference.Config = cfg
	run(t, g)
	write(t, cfg, []byte("check-for-app-update: true\n"))
	run(t, g)
	if got := s.scanCalls(t); got["candidate-grype"] != 2 || got["reference-grype"] != 4 {
		t.Errorf("expected only the reference's scans to run again, got %v", got)
	}
}

// scans-reused-by-input-key, a scan shared between gates: gate A's reference is gate B's
// candidate, under other names
func TestScanSharedBetweenGates(t *testing.T) {
	s, a, _ := cachedEnv(t)
	run(t, a)
	b := *a
	b.Name = "other-gate"
	b.Candidate, b.Reference = a.Reference, nil
	b.Subjects = []gatefile.Subject{a.Subjects[0], a.Subjects[1]}
	b.Subjects[0].Name, b.Subjects[1].Name = "renamed-deb", "renamed-npm"
	rec := run(t, &b)
	if got := s.scanCalls(t); got["candidate-grype"] != 2 || got["reference-grype"] != 2 {
		t.Errorf("expected gate B to reuse gate A's scans, got %v", got)
	}
	want, _ := os.ReadFile(fixture.Grype("v0.119.0", "deb"))
	if got, _ := os.ReadFile(filepath.Join(runrecord.Dir(runrecord.DefaultName, b.Name), rec.Subjects[0].Scans[gatefile.Candidate])); string(got) != string(want) {
		t.Errorf("expected gate A's reference scan of the deb image in gate B's set")
	}
}

// mixedSBOM is the deb image's SBOM with one package retyped as an apk, so keeping only the deb
// types drops a package and changes the bytes grype reads.
func mixedSBOM(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(fixture.SBOM("deb", "syft"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["artifacts"].([]any)[0].(map[string]any)["type"] = "apk"
	data, _ = json.Marshal(doc)
	path := filepath.Join(t.TempDir(), "mixed.syft.json")
	write(t, path, data)
	return path
}

// scans-reused-by-input-key, a filtered subject
func TestChangedKeepTypesScansThatSubjectAgain(t *testing.T) {
	s, g, _ := cachedEnv(t)
	mixed, err := ref.Parse("sbom:" + mixedSBOM(t))
	if err != nil {
		t.Fatal(err)
	}
	g.Subjects[1] = gatefile.Subject{Ref: mixed, Name: "mixed"}
	run(t, g)
	g.Subjects[1].KeepTypes = []string{"deb"}
	run(t, g)
	// only the filtered subject's scans ran again, one per setup
	if got := s.scanCalls(t); got["candidate-grype"] != 3 || got["reference-grype"] != 3 {
		t.Errorf("expected only the filtered subject's scans to run again, got %v", got)
	}
}

// scans-reused-by-input-key, a damaged entry
func TestDamagedEntryIsReplaced(t *testing.T) {
	s, g, _ := cachedEnv(t)
	run(t, g)
	stored := scanFiles(t)
	for _, f := range stored {
		data, _ := os.ReadFile(f)
		if err := os.WriteFile(f, data[:len(data)/2], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run(t, g)
	if got := s.scanCalls(t); got["candidate-grype"] != 4 || got["reference-grype"] != 4 {
		t.Errorf("expected every damaged scan to run again, got %v", got)
	}
	for _, f := range stored {
		data, _ := os.ReadFile(f)
		if _, err := Decode(data); err != nil {
			t.Errorf("expected %s replaced with a whole scan: %v", f, err)
		}
	}
}

// gate-scans-survive-cache-deletion: the gate's own directory holds a copy of every scan, reused
// ones included
func TestGateKeepsACopyOfEveryScan(t *testing.T) {
	s, g, _ := cachedEnv(t)
	run(t, g)
	rec := run(t, g)
	if err := os.RemoveAll(cache.Dir("scans")); err != nil {
		t.Fatal(err)
	}
	loaded, err := runrecord.Load(runrecord.DefaultName, g.Name)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, sub := range loaded.Subjects {
		for _, rel := range sub.Scans {
			data, err := os.ReadFile(filepath.Join(runrecord.Dir(runrecord.DefaultName, g.Name), rel))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(data); err != nil {
				t.Errorf("%s: %v", rel, err)
			}
			n++
		}
	}
	if n != 4 || len(rec.Subjects) != 2 {
		t.Errorf("expected four scans copied into the gate's directory, got %d", n)
	}
	if got := s.scanCalls(t); got["candidate-grype"] != 2 {
		t.Errorf("expected no tool to run on the second run, got %v", got)
	}
}

// publisher collects what a run puts on the bus.
type publisher struct {
	mu     sync.Mutex
	events []partybus.Event
}

func (p *publisher) Publish(e partybus.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, e)
}

// reused-scans-are-reported, a partly cached run: three of four scans are stored. The bus says
// which finished without starting, the log counts them, and the record holds each scan's key.
func TestPartlyCachedRunIsReported(t *testing.T) {
	_, g, _ := cachedEnv(t)
	run(t, g)
	stored := scanFiles(t)
	if err := os.Remove(stored[0]); err != nil {
		t.Fatal(err)
	}

	pub := &publisher{}
	bus.Set(pub)
	logFile := filepath.Join(t.TempDir(), "log")
	l, err := logrus.New(logrus.Config{FileLocation: logFile, Level: logger.InfoLevel})
	if err != nil {
		t.Fatal(err)
	}
	log.Set(l)
	t.Cleanup(func() { bus.Set(nil); log.Set(discard.New()) })
	rec := run(t, g)

	started, cached, ran := 0, 0, 0
	for _, e := range pub.events {
		scan, err := event.Parse[event.Scan](e)
		switch {
		case err != nil:
		case e.Type == event.ScanStarted:
			started++
		case scan.Cached:
			cached++
			if scan.Matches == 0 {
				t.Errorf("expected a reused scan to carry its match count, got %+v", scan)
			}
		default:
			ran++
		}
	}
	if started != 1 || cached != 3 || ran != 1 {
		t.Errorf("expected 1 scan started and finished, 3 finished as cached, got %d started, %d ran, %d cached", started, ran, cached)
	}
	if data, _ := os.ReadFile(logFile); !strings.Contains(string(data), "3 reused, 1 ran") {
		t.Errorf("expected the log to count 3 reused and 1 ran, got:\n%s", data)
	}
	keys := map[string]bool{}
	for _, sub := range rec.Subjects {
		for name := range sub.Scans {
			keys[sub.ScanKeys[name]+".json"] = true
		}
	}
	for _, f := range stored {
		if !keys[filepath.Base(f)] {
			t.Errorf("expected the record to hold the key of %s, got %v", f, keys)
		}
	}
	loaded, err := runrecord.Load(runrecord.DefaultName, g.Name)
	if err != nil || len(loaded.Subjects[0].ScanKeys) != 2 {
		t.Errorf("expected each scan's key in the record on disk, got %+v (%v)", loaded.Subjects[0].ScanKeys, err)
	}
}

// scanWith runs the gate with m.
func scanWith(t *testing.T, m Scans, g *gatefile.Gate) {
	t.Helper()
	if _, err := scanGate(t, m, g); err != nil {
		t.Fatal(err)
	}
}

// inheriting is a gate scanner that passes the caller's GRYPE_* variables on.
func inheriting() Scans {
	m := scanner()
	m.Run.InheritEnv = true
	return m
}

// inherited-env-and-dir-dbs-are-keyed, the same inherited env
func TestSameInheritedEnvReusesTheScan(t *testing.T) {
	s, g, _ := cachedEnv(t)
	t.Setenv("GRYPE_MATCH_JAVA_USING_CPES", "false")
	scanWith(t, inheriting(), g)
	scanWith(t, inheriting(), g)
	if got := s.scanCalls(t); got["candidate-grype"] != 2 || got["reference-grype"] != 2 {
		t.Errorf("expected the second run to start no scan, got %v", got)
	}
	if stored := scanFiles(t); len(stored) != 4 {
		t.Errorf("expected the scans stored, got %v", stored)
	}
}

// inherited-env-and-dir-dbs-are-keyed, a changed non-secret value
func TestChangedInheritedValueScansAgain(t *testing.T) {
	s, g, _ := cachedEnv(t)
	t.Setenv("GRYPE_MATCH_JAVA_USING_CPES", "false")
	scanWith(t, inheriting(), g)
	t.Setenv("GRYPE_MATCH_JAVA_USING_CPES", "true")
	scanWith(t, inheriting(), g)
	if got := s.scanCalls(t); got["candidate-grype"] != 4 || got["reference-grype"] != 4 {
		t.Errorf("expected every scan to run again, got %v", got)
	}
	// a run that inherits nothing is a different scan from one that does
	scanWith(t, scanner(), g)
	if got := s.scanCalls(t); got["candidate-grype"] != 6 {
		t.Errorf("expected a scrubbed run not to reuse an inheriting run's scan, got %v", got)
	}
}

// inherited-env-and-dir-dbs-are-keyed, a changed secret value alone
func TestChangedSecretValueStillReuses(t *testing.T) {
	s, g, _ := cachedEnv(t)
	t.Setenv("GRYPE_REGISTRY_AUTH_PASSWORD", "one")
	t.Setenv("GRYPE_REGISTRY_AUTH_TOKEN", "one")
	t.Setenv("SYFT_REGISTRY_AUTH_PASSWORD", "one")
	scanWith(t, inheriting(), g)
	t.Setenv("GRYPE_REGISTRY_AUTH_PASSWORD", "two")
	t.Setenv("GRYPE_REGISTRY_AUTH_TOKEN", "")
	t.Setenv("SYFT_REGISTRY_AUTH_PASSWORD", "two")
	scanWith(t, inheriting(), g)
	if got := s.scanCalls(t); got["candidate-grype"] != 2 || got["reference-grype"] != 2 {
		t.Errorf("expected the second run to start no scan, got %v", got)
	}
}

// dirDB is the directory both setups of the gate import from.
func dirDB(g *gatefile.Gate) string {
	return strings.TrimPrefix(g.Candidate.DB, "dir:")
}

// inherited-env-and-dir-dbs-are-keyed, a directory DB identified by grype's import metadata, and
// one identified by a hash of its file
func TestDirDBIsReusedWhileUnchanged(t *testing.T) {
	for name, files := range map[string]struct{ path, before, after string }{
		"import metadata": {"6/import.json", `{"digest": "xxh64:aaaa"}`, `{"digest": "xxh64:bbbb"}`},
		"file hash":       {"6/vulnerability.db", "a DB", "the same DB, rebuilt"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
			s := newStubs(t)
			g := gate(t, s)
			path := filepath.Join(dirDB(g), files.path)
			write(t, path, []byte(files.before))
			run(t, g)
			run(t, g)
			if got := s.scanCalls(t); got["candidate-grype"] != 2 || got["reference-grype"] != 2 {
				t.Errorf("expected the unchanged DB's scans reused, got %v", got)
			}
			write(t, path, []byte(files.after))
			run(t, g)
			if got := s.scanCalls(t); got["candidate-grype"] != 4 || got["reference-grype"] != 4 {
				t.Errorf("expected every scan to run again against the changed DB, got %v", got)
			}
		})
	}
}

// a dir: DB holding no DB has no identity, so its scans are neither read nor written
func TestDirDBWithoutAnIdentityIsNotCached(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	s := newStubs(t)
	g := gate(t, s)
	run(t, g)
	run(t, g)
	if got := s.scanCalls(t); got["candidate-grype"] != 4 || got["reference-grype"] != 4 {
		t.Errorf("expected every scan to run both times, got %v", got)
	}
	if stored := scanFiles(t); len(stored) != 0 {
		t.Errorf("expected nothing stored, got %v", stored)
	}
}

// rescan-on-request, forcing a rescan
func TestRescanRunsEveryScanAndReplacesTheStoredOne(t *testing.T) {
	s, g, _ := cachedEnv(t)
	run(t, g)
	stored := scanFiles(t)
	whole := map[string][]byte{}
	for _, f := range stored {
		data, _ := os.ReadFile(f)
		whole[f] = data
		// still a scan that decodes, so a plain rerun would reuse it
		write(t, f, append(data, '\n', '\n'))
	}
	m := scanner()
	m.Rescan = true
	scanWith(t, m, g)
	if got := s.scanCalls(t); got["candidate-grype"] != 4 || got["reference-grype"] != 4 {
		t.Errorf("expected every scan to run again, got %v", got)
	}
	for f, want := range whole {
		if got, _ := os.ReadFile(f); string(got) != string(want) {
			t.Errorf("expected %s replaced with the new output", f)
		}
	}
	// the replaced entries are reused by a run without it
	run(t, g)
	if got := s.scanCalls(t); got["candidate-grype"] != 4 {
		t.Errorf("expected the rescanned entries reused, got %v", got)
	}
}
