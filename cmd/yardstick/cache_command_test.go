package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
)

// fillCache writes the cache the size-report scenario describes: two grype versions, one DB and
// 28 scans.
func fillCache(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("YARDSTICK_CACHE_DIR", root)
	writeFile(t, filepath.Join(root, "tools/grype/v0.100.0/grype"), strings.Repeat("g", 1000))
	writeFile(t, filepath.Join(root, "tools/grype/v0.120.1/grype"), strings.Repeat("g", 2000))
	writeFile(t, filepath.Join(root, "grype-db/sha256-aa/6/vulnerability.db"), strings.Repeat("d", 5000))
	for i := range 28 {
		writeFile(t, filepath.Join(root, "scans", strings.Repeat("a", 3)+string(rune('a'+i%26))+string(rune('a'+i/26))+".json"), strings.Repeat("s", 100))
	}
	return root
}

func age(t *testing.T, path string, d time.Duration) {
	t.Helper()
	when := time.Now().Add(-d)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

// cache-status-command, the size report
func TestCacheStatusSizeReport(t *testing.T) {
	root := fillCache(t)
	age(t, filepath.Join(root, "tools/grype/v0.100.0"), 40*24*time.Hour)

	stdout, stderr, code := yardstick(t, t.TempDir(), "cache", "status")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, root) {
		t.Errorf("expected the cache root %s:\n%s", root, stdout)
	}
	rows := map[string][]string{}
	for _, line := range strings.Split(stdout, "\n") {
		if f := strings.Fields(line); len(f) > 1 {
			rows[f[0]] = f[1:]
		}
	}
	for kind, want := range map[string]string{"tools": "2 3.0 kB", "dbs": "1 5.0 kB", "sboms": "0 0 B -", "scans": "28 2.8 kB", "claims": "0 0 B -", "total": "31 11 kB"} {
		if got := strings.Join(rows[kind], " "); !strings.HasPrefix(got, want) {
			t.Errorf("%s: expected a row starting %q, got %q\n%s", kind, want, got, stdout)
		}
	}
	// the oldest use of the tools is the older version's
	if want := time.Now().Add(-40 * 24 * time.Hour).Format("2006-01-02"); !strings.Contains(stdout, want) {
		t.Errorf("expected the oldest tool use %s:\n%s", want, stdout)
	}
	if _, err := os.Stat(filepath.Join(root, "sboms")); err == nil {
		t.Error("status created a directory in the cache")
	}
}

func TestCacheStatusJSON(t *testing.T) {
	root := fillCache(t)
	stdout, stderr, code := yardstick(t, t.TempDir(), "cache", "status", "-o", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var got struct {
		Root  string
		Kinds []struct {
			Kind      string
			Entries   int
			Size      int64
			OldestUse *time.Time
		}
		Total struct{ Entries int }
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	if got.Root != root || len(got.Kinds) != len(cache.Kinds) || got.Total.Entries != 31 || got.Kinds[3].Kind != "scans" || got.Kinds[3].Entries != 28 || got.Kinds[4].OldestUse != nil {
		t.Errorf("unexpected status %+v", got)
	}
	if _, stderr, code := yardstick(t, t.TempDir(), "cache", "status", "-o", "yaml"); code != 2 || !strings.Contains(stderr, "text, json") {
		t.Errorf("expected exit 2 naming the outputs, got %d: %s", code, stderr)
	}
}

// cache-delete-command, trimming old DBs
func TestCacheDeleteTrimmingOldDBs(t *testing.T) {
	root := t.TempDir()
	t.Setenv("YARDSTICK_CACHE_DIR", root)
	for i, days := range []time.Duration{1, 10, 40} {
		dir := filepath.Join(root, "grype-db", "sha256-"+string(rune('a'+i)))
		writeFile(t, filepath.Join(dir, "6/vulnerability.db"), strings.Repeat("d", 1000*(i+1)))
		age(t, dir, days*24*time.Hour)
	}
	writeFile(t, filepath.Join(root, "scans/x.json"), "{}")

	stdout, stderr, code := yardstick(t, t.TempDir(), "cache", "delete", "dbs", "--older-than", "30d")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"removed grype-db/sha256-c (3.0 kB)", "removed 1 entry, freed 3.0 kB"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("expected %q:\n%s", want, stdout)
		}
	}
	for name, want := range map[string]bool{"sha256-a": true, "sha256-b": true, "sha256-c": false} {
		if _, err := os.Stat(filepath.Join(root, "grype-db", name)); (err == nil) != want {
			t.Errorf("%s: expected present=%v", name, want)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "scans/x.json")); err != nil {
		t.Error("deleting dbs removed a scan")
	}
}

// cache-delete-command, deleting everything
func TestCacheDeleteEverything(t *testing.T) {
	root := fillCache(t)
	writeFile(t, filepath.Join(root, "sboms/sha256-i/sha256-c.syft.json"), "{}")
	writeFile(t, filepath.Join(root, "sboms-read/sha256-s.syft.json"), "{}")
	writeFile(t, filepath.Join(root, "claims/sha256-z.zip"), "zip")

	stdout, stderr, code := yardstick(t, t.TempDir(), "cache", "delete")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "removed 34 entries, freed") {
		t.Errorf("expected the count and the bytes freed:\n%s", stdout)
	}
	for _, kind := range cache.Kinds {
		if entries, err := cache.List(kind); err != nil || len(entries) != 0 {
			t.Errorf("%s: expected nothing left, got %v, %v", kind, entries, err)
		}
	}
}

// cache-delete-command, an unknown kind
func TestCacheDeleteUnknownKind(t *testing.T) {
	root := fillCache(t)
	_, stderr, code := yardstick(t, t.TempDir(), "cache", "delete", "images")
	if code != 2 || !strings.Contains(stderr, strings.Join(cache.Kinds, ", ")) {
		t.Errorf("expected exit 2 naming the kinds, got %d: %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "grype-db")); err != nil {
		t.Error("an unknown kind deleted something")
	}
	// a known kind beside an unknown one deletes nothing either
	_, _, code = yardstick(t, t.TempDir(), "cache", "delete", "scans", "images")
	if entries, _ := cache.List("scans"); code != 2 || len(entries) != 28 {
		t.Errorf("expected exit 2 and no scans deleted, got %d with %d scans", code, len(entries))
	}
}

func TestCacheDeleteBadAge(t *testing.T) {
	fillCache(t)
	for _, v := range []string{"soon", "-1d", "30"} {
		if _, stderr, code := yardstick(t, t.TempDir(), "cache", "delete", "--older-than", v); code != 2 || !strings.Contains(stderr, v) {
			t.Errorf("%q: expected exit 2 naming it, got %d: %s", v, code, stderr)
		}
	}
	if entries, _ := cache.List("scans"); len(entries) != 28 {
		t.Error("a bad --older-than deleted scans")
	}
}

func TestCacheHelpNamesTheKinds(t *testing.T) {
	for _, args := range [][]string{{"cache", "status", "--help"}, {"cache", "delete", "--help"}} {
		help, _, _ := yardstick(t, t.TempDir(), args...)
		if !strings.Contains(help, strings.Join(cache.Kinds, ", ")) {
			t.Errorf("%v: expected the help to name the kinds:\n%s", args, help)
		}
	}
}
