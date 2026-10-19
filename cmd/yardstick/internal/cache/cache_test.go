package cache

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// cache-writes-are-atomic: two writers of one entry leave one whole entry and no temporary file
func TestWriteFileConcurrentWritersOfOneEntry(t *testing.T) {
	target := filepath.Join(t.TempDir(), "sboms", "entry.json")
	data := []byte(strings.Repeat("0123456789", 100000))
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := WriteFile(target, data); err != nil {
				t.Error(err)
			}
		}()
	}
	// a reader sees the entry absent or whole, never partial
	for range 200 {
		if got, err := os.ReadFile(target); err == nil && len(got) != len(data) {
			t.Fatalf("read a partial entry of %d bytes", len(got))
		}
	}
	wg.Wait()
	if got, err := os.ReadFile(target); err != nil || string(got) != string(data) {
		t.Errorf("expected the whole entry, got %d bytes, %v", len(got), err)
	}
	entries, _ := os.ReadDir(filepath.Dir(target))
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected only the entry, got %v", names)
	}
}

func TestWriteFileFailureLeavesNoEntry(t *testing.T) {
	dir := t.TempDir()
	// the target is a non-empty directory, so the rename fails
	target := filepath.Join(dir, "entry")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(target, []byte("x")); err == nil {
		t.Fatal("expected the write to fail")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected the failed write's temporary file removed, got %d entries", len(entries))
	}
}

// cache-entries-record-last-use
func TestTouchSetsTheModificationTimeToNow(t *testing.T) {
	for name, create := range map[string]func(string) error{
		"a file":      func(p string) error { return os.WriteFile(p, []byte("x"), 0o600) },
		"a directory": func(p string) error { return os.Mkdir(p, 0o755) },
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "entry")
			if err := create(p); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-20 * 24 * time.Hour)
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
			Touch(p)
			info, err := os.Stat(p)
			if err != nil || time.Since(info.ModTime()) > time.Minute {
				t.Errorf("expected a modification time of now, got %v, %v", info.ModTime(), err)
			}
		})
	}
	Touch(filepath.Join(t.TempDir(), "missing")) // not an error
}
