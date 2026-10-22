package setup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
)

// stubGrype is a grype stand-in that logs every call to $CALLS. `db list -o text` prints
// testdata/grype-db-list.txt, captured from grype v0.120.1; `db import` fills the DB directory,
// and fails for an archive named not-a-db.tar.zst.
const stubGrype = `#!/bin/sh
# every call carries -c; the file it names is logged to $CONFIGS, or the call is flagged
if [ "$1" = "-c" ]; then echo "$2" >> "$CONFIGS"; shift 2; else echo "no -c: $*" >> "$CONFIGS"; fi
echo "$*" >> "$CALLS"
case "$1 $2" in
"db list") cat "$LISTING" ;;
"db import")
  case "$3" in */not-a-db.tar.zst) echo "failed to import DB: not a grype DB archive" >&2; exit 1 ;; esac
  [ -n "$IMPORT_SLEEP" ] && sleep "$IMPORT_SLEEP"
  mkdir -p "$GRYPE_DB_CACHE_DIR" && echo "$3" > "$GRYPE_DB_CACHE_DIR/imported" ;;
esac
`

// listed is the DB the captured listing names.
const listed = "sha256:30d8bcd3c09e03c9f734c522e104c1387e285e3f6e33da2ee7b55f521daadb3f"

func stub(t *testing.T) (grype string, calls func() []string) {
	t.Helper()
	dir := t.TempDir()
	grype = filepath.Join(dir, "grype")
	if err := os.WriteFile(grype, []byte(stubGrype), 0o755); err != nil {
		t.Fatal(err)
	}
	listing, err := filepath.Abs("testdata/grype-db-list.txt")
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls")
	t.Setenv("CALLS", log)
	t.Setenv("CONFIGS", log+".configs")
	t.Setenv("LISTING", listing)
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	return grype, func() []string {
		data, _ := os.ReadFile(log)
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
}

// configs is the config each stub call was given.
func configs(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("CONFIGS"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func count(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// tools-and-dbs-are-cached-by-identity, the DB half
func TestLatestResolvesOnceAndImportsOnce(t *testing.T) {
	grype, calls := stub(t)
	ctx := context.Background()
	p := NewPreparer(install.NewResolver(), execute.Runner{})
	cand, err := p.Prepare(ctx, "candidate", &gatefile.Setup{Grype: grype, DB: "latest"})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := p.Prepare(ctx, "reference", &gatefile.Setup{Grype: grype, DB: "latest"})
	if err != nil {
		t.Fatal(err)
	}
	if cand.DB != ref.DB || cand.DB.Checksum != listed || cand.DB.Requested != "latest" {
		t.Errorf("expected both setups on the listed DB, got %+v and %+v", cand.DB, ref.DB)
	}
	if !strings.HasSuffix(cand.DB.Dir, filepath.Join("grype-db", strings.ReplaceAll(listed, ":", "-"))) {
		t.Errorf("expected the DB imported under its checksum, got %s", cand.DB.Dir)
	}
	if got := calls(); count(got, "db list") != 1 || count(got, "db import") != 1 {
		t.Errorf("expected one listing and one import, got %v", got)
	}

	// a second invocation asks what latest is, and imports nothing
	again, err := NewPreparer(install.NewResolver(), execute.Runner{}).Prepare(ctx, "candidate", &gatefile.Setup{Grype: grype, DB: "latest"})
	if err != nil {
		t.Fatal(err)
	}
	if got := calls(); again.DB != cand.DB || count(got, "db import") != 1 {
		t.Errorf("expected the imported DB reused, got %+v after %v", again.DB, got)
	}
}

func TestArchiveCheckedByContent(t *testing.T) {
	grype, calls := stub(t)
	archive := filepath.Join(t.TempDir(), "vulnerability.db.tar.zst")
	if err := os.WriteFile(archive, []byte("a DB archive's bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "grype.yaml")
	if err := os.WriteFile(cfg, []byte("match:\n  java:\n    using-cpes: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &gatefile.Setup{Grype: grype, DB: archive, Config: cfg, Env: map[string]string{"GRYPE_MATCH_JAVA_USING_CPES": "false"}}
	got, err := NewPreparer(install.NewResolver(), execute.Runner{}).Prepare(context.Background(), "candidate", s)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("a DB archive's bytes"))
	if got.DB.Checksum != "sha256:"+hex.EncodeToString(sum[:]) || got.DB.Source != archive {
		t.Errorf("expected the archive identified by its digest, got %+v", got.DB)
	}
	cfgSum := sha256.Sum256([]byte("match:\n  java:\n    using-cpes: false\n"))
	if got.Config == nil || got.Config.SHA256 != hex.EncodeToString(cfgSum[:]) || got.Env["GRYPE_MATCH_JAVA_USING_CPES"] != "false" {
		t.Errorf("expected the config's digest and the declared env recorded, got %+v", got)
	}
	if len(got.Grype.SHA256) != 64 || got.Grype.Spec.Path != grype {
		t.Errorf("expected the grype binary used in place with its digest, got %+v", got.Grype)
	}
	if c := calls(); count(c, "db list") != 0 || count(c, "db import") != 1 {
		t.Errorf("expected one import and no listing, got %v", c)
	}

	dir := filepath.Join(t.TempDir(), "db")
	got, err = NewPreparer(install.NewResolver(), execute.Runner{}).Prepare(context.Background(), "reference", &gatefile.Setup{Grype: grype, DB: "dir:" + dir})
	if err != nil || got.DB.Dir != dir {
		t.Errorf("expected a dir: DB used as it is, got %+v %v", got.DB, err)
	}
}

func TestADBThatCannotBeImportedNamesTheSetup(t *testing.T) {
	grype, _ := stub(t)
	archive := filepath.Join(t.TempDir(), "not-a-db.tar.zst")
	if err := os.WriteFile(archive, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewPreparer(install.NewResolver(), execute.Runner{}).Prepare(context.Background(), "reference", &gatefile.Setup{Grype: grype, DB: archive})
	if err == nil || !strings.HasPrefix(err.Error(), "reference: unable to prepare DB") || !strings.Contains(err.Error(), "not a grype DB archive") {
		t.Errorf("expected the failure to name the setup and carry grype's stderr, got %v", err)
	}
}

// grype-runs-with-its-db-pinned: the listing and the import run with an empty config, so a
// config in the user's home never changes which DB a setup resolves to
func TestDBCommandsRunWithAnEmptyConfig(t *testing.T) {
	grype, _ := stub(t)
	if _, err := NewPreparer(install.NewResolver(), execute.Runner{}).Prepare(context.Background(), "candidate", &gatefile.Setup{Grype: grype, DB: "latest"}); err != nil {
		t.Fatal(err)
	}
	got := configs(t)
	if len(got) != 2 {
		t.Fatalf("expected the listing and the import, got %v", got)
	}
	for _, cfg := range got {
		if !strings.HasPrefix(cfg, cache.Dir()) {
			t.Errorf("expected an empty config under the cache, got %q", cfg)
		}
		if data, err := os.ReadFile(cfg); err != nil || len(data) != 0 {
			t.Errorf("expected %s to be an empty file, got %q, %v", cfg, data, err)
		}
	}
}

// DBs in the cache: the entries of grype-db, and the temporary imports beside them.
func dbEntries(t *testing.T) (entries, temps []string) {
	t.Helper()
	found, err := os.ReadDir(cache.Dir("grype-db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range found {
		if strings.HasPrefix(e.Name(), ".") {
			temps = append(temps, e.Name())
		} else {
			entries = append(entries, e.Name())
		}
	}
	return entries, temps
}

// cache-writes-are-atomic: two processes importing one DB at once both end up with it
func TestConcurrentImportsOfOneDB(t *testing.T) {
	grype, calls := stub(t)
	t.Setenv("IMPORT_SLEEP", "0.3")
	var wg sync.WaitGroup
	prepared := make([]Prepared, 2)
	errs := make([]error, 2)
	for i := range prepared {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// one preparer each, as two processes would have
			prepared[i], errs[i] = NewPreparer(install.NewResolver(), execute.Runner{}).Prepare(context.Background(), "candidate", &gatefile.Setup{Grype: grype, DB: "latest"})
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("process %d: %v", i, err)
		}
	}
	if got := count(calls(), "db import"); got != 2 {
		t.Fatalf("expected both processes to import, as neither saw the other's DB yet, got %d", got)
	}
	entries, temps := dbEntries(t)
	if len(entries) != 1 || len(temps) != 0 {
		t.Errorf("expected one DB and no leftover import, got %v and %v", entries, temps)
	}
	for _, p := range prepared {
		if _, err := os.Stat(filepath.Join(p.DB.Dir, "imported")); err != nil {
			t.Errorf("expected the DB whole at %s: %v", p.DB.Dir, err)
		}
	}
}

// cache-writes-are-atomic: a failed import leaves no DB, and nothing half imported
func TestFailedImportLeavesNothing(t *testing.T) {
	grype, _ := stub(t)
	archive := filepath.Join(t.TempDir(), "not-a-db.tar.zst")
	if err := os.WriteFile(archive, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPreparer(install.NewResolver(), execute.Runner{}).Prepare(context.Background(), "reference", &gatefile.Setup{Grype: grype, DB: archive}); err == nil {
		t.Fatal("expected the import to fail")
	}
	if entries, temps := dbEntries(t); len(entries) != 0 || len(temps) != 0 {
		t.Errorf("expected nothing left in the cache, got %v and %v", entries, temps)
	}
}

// cache-entries-record-last-use, a reused DB
func TestReusedDBRecordsItsUse(t *testing.T) {
	grype, _ := stub(t)
	s := &gatefile.Setup{Grype: grype, DB: "latest"}
	first, err := NewPreparer(install.NewResolver(), execute.Runner{}).Prepare(context.Background(), "candidate", s)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-20 * 24 * time.Hour)
	if err := os.Chtimes(first.DB.Dir, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPreparer(install.NewResolver(), execute.Runner{}).Prepare(context.Background(), "candidate", s); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(first.DB.Dir)
	if err != nil || time.Since(info.ModTime()) > time.Minute {
		t.Errorf("expected the DB's modification time from this run, got %v %v", info.ModTime(), err)
	}
}

// a DB directory an import left half done under the old layout, with no marker, is replaced
func TestUnmarkedDBDirectoryIsReplaced(t *testing.T) {
	grype, _ := stub(t)
	dir := cache.Dir("grype-db", strings.ReplaceAll(listed, ":", "-"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "partial"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := NewPreparer(install.NewResolver(), execute.Runner{}).Prepare(context.Background(), "candidate", &gatefile.Setup{Grype: grype, DB: "latest"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(got.DB.Dir, "imported")); err != nil {
		t.Errorf("expected the import in place, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(got.DB.Dir, "partial")); err == nil {
		t.Error("expected the half-done directory gone")
	}
}

// a DB URL pinned with @sha256: is imported with that checksum for grype to verify, and cached by
// it rather than by the URL
func TestURLWithAChecksum(t *testing.T) {
	grype, calls := stub(t)
	sum := strings.Repeat("ab", 32)
	got, err := NewPreparer(install.NewResolver(), execute.Runner{}).Prepare(context.Background(), "candidate",
		&gatefile.Setup{Grype: grype, DB: "https://example.invalid/vulnerability-db.tar.zst@sha256:" + sum})
	if err != nil {
		t.Fatal(err)
	}
	if got.DB.Source != "https://example.invalid/vulnerability-db.tar.zst" || got.DB.Checksum != "sha256:"+sum ||
		filepath.Base(got.DB.Dir) != "sha256-"+sum {
		t.Errorf("expected the URL without its suffix, the checksum, and the DB cached by it, got %+v", got.DB)
	}
	if c := calls(); count(c, "db import https://example.invalid/vulnerability-db.tar.zst?checksum=sha256%3A"+sum) != 1 {
		t.Errorf("expected grype to import the URL with the checksum to verify, got %v", c)
	}
}

// db: latest is listed with the setup's env and config, which can point grype at another listing,
// and two setups share a listing only when they would ask the same thing
func TestLatestFollowsTheSetupsEnvAndConfig(t *testing.T) {
	grype, calls := stub(t)
	ctx := context.Background()
	cfg := filepath.Join(t.TempDir(), "grype.yaml")
	if err := os.WriteFile(cfg, []byte("db:\n  update-url: https://example.invalid/listing.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := NewPreparer(install.NewResolver(), execute.Runner{})
	for _, s := range []*gatefile.Setup{
		{Grype: grype, DB: "latest"},
		{Grype: grype, DB: "latest"},
		{Grype: grype, DB: "latest", Env: map[string]string{"GRYPE_DB_UPDATE_URL": "https://example.invalid/listing.json"}},
		{Grype: grype, DB: "latest", Config: cfg},
	} {
		if _, err := p.Prepare(ctx, "candidate", s); err != nil {
			t.Fatal(err)
		}
	}
	if got := calls(); count(got, "db list") != 3 {
		t.Errorf("expected one listing for the two alike setups and one each for the other two, got %v", got)
	}
	if got := configs(t); !slices.Contains(got, cfg) {
		t.Errorf("expected a listing run with the setup's config %s, got %v", cfg, got)
	}
}
