package cache

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// put writes a cache entry of size bytes last used age ago, and returns its path
func put(t *testing.T, age time.Duration, size int, elem ...string) string {
	t.Helper()
	path := Dir(elem...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0o600); err != nil {
		t.Fatal(err)
	}
	setAge(t, path, age)
	return path
}

func setAge(t *testing.T, path string, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func paths(entries []Entry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Path)
	}
	slices.Sort(out)
	return out
}

func TestEveryKindHasALayout(t *testing.T) {
	for _, k := range Kinds {
		if _, ok := layouts[k]; !ok {
			t.Errorf("kind %q has no layout", k)
		}
	}
	if len(layouts) != len(Kinds) {
		t.Errorf("%d layouts for %d kinds", len(layouts), len(Kinds))
	}
}

func TestParseAge(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30d":    days(30),
		"12h":    12 * time.Hour,
		"1d12h":  days(1) + 12*time.Hour,
		" 2D ":   days(2),
		"90m":    90 * time.Minute,
		"1h30m":  90 * time.Minute,
		"365d":   days(365),
		"0d36h":  36 * time.Hour,
		"7d0.5h": days(7) + 30*time.Minute,
	} {
		if got, err := ParseAge(in); err != nil || got != want {
			t.Errorf("%q: expected %s, got %s, %v", in, want, got, err)
		}
	}
	for _, in := range []string{"", "d", "xd", "30", "3x", "-1d", "0", "0d", "1d-2h", "1.5d"} {
		if got, err := ParseAge(in); err == nil {
			t.Errorf("%q: expected an error, got %s", in, got)
		}
	}
}

func TestParseKinds(t *testing.T) {
	if got, err := ParseKinds(nil); err != nil || !slices.Equal(got, Kinds) {
		t.Errorf("no kind should mean every kind, got %v, %v", got, err)
	}
	if got, err := ParseKinds([]string{"dbs", "scans"}); err != nil || !slices.Equal(got, []string{"dbs", "scans"}) {
		t.Errorf("got %v, %v", got, err)
	}
	_, err := ParseKinds([]string{"dbs", "images"})
	if err == nil || !strings.Contains(err.Error(), `"images"`) || !strings.Contains(err.Error(), strings.Join(Kinds, ", ")) {
		t.Errorf("expected an error naming the kind and the valid ones, got %v", err)
	}
}

// the layout each kind is read from, the way the rest of yardstick writes it
func TestListReadsEachKindWhereItIsWritten(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	put(t, 0, 10, "tools", "grype", "v0.100.0", "grype")
	put(t, 0, 10, "tools", "grype", "v0.100.0", ".binny.state.json")
	put(t, 0, 10, "tools", "grype", "v0.120.1", "grype")
	put(t, 0, 100, "grype-db", "sha256-aa", "6", "vulnerability.db")
	put(t, 0, 1, "grype-db", "sha256-aa", ".yardstick-imported")
	put(t, 0, 5, "sboms", "sha256-img", "sha256-cat.syft.json")
	put(t, 0, 5, "sboms-read", "sha256-sbom.syft.json")
	put(t, 0, 5, "sboms-filtered", "sha256-unf", "apk.syft.json")
	put(t, 0, 5, "catalog-config", "abc.yaml")
	put(t, 0, 7, "scans", "ab12.json")
	put(t, 0, 9, "claims", "sha256-snap.zip")
	// not entries
	put(t, 0, 50, "workdir", "empty-config.yaml")
	put(t, 0, 50, "scans", ".tmp-123")
	put(t, 0, 50, "grype-db", ".import-123", "x")
	put(t, 0, 50, "sboms", "sha256-img", ".tmp-456")

	want := map[string]struct {
		entries int
		size    int64
	}{
		"tools":  {2, 30},
		"dbs":    {1, 101},
		"sboms":  {4, 20},
		"scans":  {1, 7},
		"claims": {1, 9},
	}
	for kind, w := range want {
		entries, err := List(kind)
		if err != nil {
			t.Fatal(err)
		}
		var size int64
		for _, e := range entries {
			size += e.Size
		}
		if len(entries) != w.entries || size != w.size {
			t.Errorf("%s: expected %d entries of %d bytes, got %d of %d: %v", kind, w.entries, w.size, len(entries), size, paths(entries))
		}
	}
}

func TestListOfAnEmptyCache(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", filepath.Join(t.TempDir(), "missing"))
	for _, kind := range Kinds {
		if entries, err := List(kind); err != nil || len(entries) != 0 {
			t.Errorf("%s: expected no entries, got %v, %v", kind, entries, err)
		}
	}
}

// the last use of an entry is its mtime: a directory's own, not its files'
func TestListLastUseIsTheEntryMtime(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	put(t, 0, 1, "grype-db", "sha256-aa", "6", "vulnerability.db")
	setAge(t, Dir("grype-db", "sha256-aa"), days(10))
	entries, _ := List("dbs")
	if age := time.Since(entries[0].LastUse); age < days(10) || age > days(10)+time.Minute {
		t.Errorf("expected a last use 10 days ago, got %s ago", age)
	}
}

// trimming old DBs: DBs last used 1, 10 and 40 days ago, and only the one from 40 days ago goes
func TestDeleteOlderThan(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	var dirs []string
	for i, age := range []int{1, 10, 40} {
		db := Dir("grype-db", "sha256-"+string(rune('a'+i)))
		put(t, 0, 100*(i+1), "grype-db", filepath.Base(db), "6", "vulnerability.db")
		setAge(t, db, days(age))
		dirs = append(dirs, db)
	}
	scan := put(t, days(40), 1, "scans", "old.json")

	removed, err := Delete("dbs", days(30))
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0].Path != dirs[2] || removed[0].Size != 300 {
		t.Errorf("expected only the DB from 40 days ago, 300 bytes, got %v", removed)
	}
	if !exists(dirs[0]) || !exists(dirs[1]) || exists(dirs[2]) {
		t.Errorf("expected the DBs from 1 and 10 days ago to stay, and the one from 40 to go")
	}
	if !exists(scan) {
		t.Error("deleting dbs removed a scan")
	}
}

func TestDeleteWithoutAnAgeRemovesEveryEntry(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	put(t, 0, 1, "tools", "grype", "v1", "grype")
	put(t, 0, 1, "sboms", "d", "c.syft.json")
	put(t, 0, 1, "scans", "a.json")
	put(t, 0, 1, "workdir", "empty-config.yaml")
	for _, kind := range []string{"tools", "sboms", "scans"} {
		if removed, err := Delete(kind, 0); err != nil || len(removed) != 1 {
			t.Errorf("%s: expected one entry removed, got %v, %v", kind, removed, err)
		}
	}
	if !exists(Dir("workdir", "empty-config.yaml")) {
		t.Error("the work directory is not an entry and must stay")
	}
}

// an import in progress is never deleted: its directory is a dot-prefixed temp entry, removed only once stale
func TestDeleteKeepsAnImportInProgress(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	young := put(t, time.Hour, 5, "grype-db", ".import-young", "6", "vulnerability.db")
	stale := put(t, 0, 5, "grype-db", ".import-stale", "6", "vulnerability.db")
	setAge(t, Dir("grype-db", ".import-young"), time.Hour)
	setAge(t, Dir("grype-db", ".import-stale"), days(2))
	tmp := put(t, 0, 5, "scans", ".tmp-1")
	done := put(t, 0, 5, "grype-db", "sha256-a", "6", "vulnerability.db")

	removed, err := Delete("dbs", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !exists(young) || !exists(tmp) {
		t.Error("a young temp entry was deleted")
	}
	if exists(stale) || exists(Dir("grype-db", ".import-stale")) || exists(done) {
		t.Error("expected the stale import and the finished DB to go")
	}
	if len(removed) != 2 {
		t.Errorf("expected two entries reported removed, got %v", paths(removed))
	}
	// an age filter never makes a temp entry go sooner than a day
	if removed, _ := Delete("dbs", time.Minute); len(removed) != 0 || !exists(young) {
		t.Errorf("a young import was removed under --older-than: %v", removed)
	}
}

// a tool store with a binny staging directory being written is an install in progress
func TestDeleteKeepsAToolBeingInstalled(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	busy := put(t, 0, 5, "tools", "grype", "v1", "binny-install-grype-1", "grype")
	idle := put(t, days(40), 5, "tools", "grype", "v2", "grype")
	setAge(t, Dir("tools", "grype", "v1"), days(40))
	removed, err := Delete("tools", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !exists(busy) || exists(idle) || len(removed) != 1 {
		t.Errorf("expected only the idle tool removed, got %v", paths(removed))
	}
	// once the staging directory is stale it is left over from a killed install
	setAge(t, Dir("tools", "grype", "v1", "binny-install-grype-1"), days(2))
	if removed, _ := Delete("tools", 0); len(removed) != 1 || exists(busy) {
		t.Errorf("expected the abandoned install removed, got %v", paths(removed))
	}
}
