// Package cache is yardstick's per-user cache directory. Tools, grype DBs, built SBOMs and
// fetched claims snapshots live under it, each keyed by identity, so a second run with the same
// inputs downloads nothing. It is yardstick's own: delta's cache is never read or written.
package cache

import (
	"os"
	"path/filepath"
	"time"

	"github.com/adrg/xdg"

	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// Dir returns a path in yardstick's cache, rooted at YARDSTICK_CACHE_DIR, else <xdg cache>/yardstick.
func Dir(elem ...string) string {
	root := os.Getenv("YARDSTICK_CACHE_DIR")
	if root == "" {
		root = filepath.Join(xdg.CacheHome, "yardstick")
	}
	return filepath.Join(append([]string{root}, elem...)...)
}

// WriteFile writes a cache entry whole or not at all: to a temporary name beside it, then renamed
// into place. A reader sees the old entry or the new one, and two writers of one entry leave
// whichever renamed last.
func WriteFile(target string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), target)
}

// Touch records a use of the cache entry at path by setting its modification time to now, which
// is the entry's last use: access times aren't kept on most mounts. An entry that can't be touched
// is still good to use, so a failure is logged and not returned.
func Touch(path string) {
	now := time.Now()
	if err := os.Chtimes(path, now, now); err != nil {
		log.Debugf("unable to record the use of cache entry %s: %v", path, err)
	}
}
