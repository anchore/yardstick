package cache

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Kinds are the groups of cache entries `yardstick cache` reports on and deletes, in the order it
// lists them. It is the one list a kind is validated against and named in help and errors.
var Kinds = []string{kindTools, kindDBs, kindSBOMs, kindScans, kindClaims}

const (
	kindTools  = "tools"
	kindDBs    = "dbs"
	kindSBOMs  = "sboms"
	kindScans  = "scans"
	kindClaims = "claims"
)

// layout is where a kind lives under the cache root: its directories, and how many levels below
// one an entry sits. Depth 0 means every file is an entry, since SBOMs are filed under a digest
// directory in some places and not in others.
type layout struct {
	dirs  []string
	depth int
}

var layouts = map[string]layout{
	kindTools:  {[]string{"tools"}, 2}, // tools/<name>/<version>/
	kindDBs:    {[]string{"grype-db"}, 1},
	kindSBOMs:  {[]string{"sboms", "sboms-read", "sboms-filtered", "catalog-config"}, 0},
	kindScans:  {[]string{"scans"}, 1},
	kindClaims: {[]string{"claims"}, 1},
}

// StaleTemp is how old a temporary entry (a dot-prefixed name, such as a DB import in progress)
// must be before it is taken to be left by a killed run and removed. Younger ones may be being
// written.
const StaleTemp = 24 * time.Hour

// binnyStaging is the prefix of the directory binny installs a tool into inside the tool's store.
const binnyStaging = "binny-install-"

// Entry is one cache entry: a file or directory, its size on disk and its last use, which is its
// modification time (see Touch).
type Entry struct {
	Path    string
	Size    int64
	LastUse time.Time
}

// ParseKinds checks the kinds named on the command line, and returns every kind when none is.
func ParseKinds(names []string) ([]string, error) {
	if len(names) == 0 {
		return Kinds, nil
	}
	for _, n := range names {
		if _, ok := layouts[n]; !ok {
			return nil, fmt.Errorf("unknown cache kind %q: use one of %s", n, strings.Join(Kinds, ", "))
		}
	}
	return names, nil
}

// ParseAge reads a duration that may carry a day count, such as 30d or 1d12h, as well as anything
// time.ParseDuration reads, such as 12h. It must be positive.
func ParseAge(s string) (time.Duration, error) {
	in := strings.ToLower(strings.TrimSpace(s))
	var days time.Duration
	if n, rest, ok := strings.Cut(in, "d"); ok {
		d, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: want a number of days before the d", s)
		}
		days, in = time.Duration(d)*24*time.Hour, rest
	}
	var rest time.Duration
	if in != "" {
		var err error
		if rest, err = time.ParseDuration(in); err != nil {
			return 0, fmt.Errorf("invalid duration %q: use a number of days (30d) or a Go duration (12h)", s)
		}
	}
	if rest < 0 || days+rest <= 0 {
		return 0, fmt.Errorf("invalid duration %q: must be positive", s)
	}
	return days + rest, nil
}

// List returns the entries of a kind, leaving out temporary ones. A kind nothing was ever written
// for has none.
func List(kind string) ([]Entry, error) {
	entries, _, err := scan(kind)
	return entries, err
}

// Delete removes the entries of a kind and returns them. With olderThan above zero it removes
// only entries last used longer ago. Temporary entries are removed only once stale, and a tool
// with an install in progress is kept.
func Delete(kind string, olderThan time.Duration) ([]Entry, error) {
	entries, temps, err := scan(kind)
	if err != nil {
		return nil, err
	}
	var removed []Entry
	for _, e := range entries {
		if (olderThan > 0 && time.Since(e.LastUse) <= olderThan) || installing(kind, e) {
			continue
		}
		if err := os.RemoveAll(e.Path); err != nil {
			return removed, err
		}
		removed = append(removed, e)
	}
	for _, e := range temps {
		if time.Since(e.LastUse) <= max(StaleTemp, olderThan) {
			continue
		}
		if err := os.RemoveAll(e.Path); err != nil {
			return removed, err
		}
		removed = append(removed, e)
	}
	return removed, nil
}

// installing is whether a tool entry holds a binny staging directory touched recently.
func installing(kind string, e Entry) bool {
	if kind != kindTools {
		return false
	}
	children, _ := os.ReadDir(e.Path)
	for _, c := range children {
		if info, err := c.Info(); err == nil && strings.HasPrefix(c.Name(), binnyStaging) && time.Since(info.ModTime()) <= StaleTemp {
			return true
		}
	}
	return false
}

// scan walks a kind's directories, separating its entries from the temporary ones beside them.
func scan(kind string) (entries, temps []Entry, err error) {
	l, ok := layouts[kind]
	if !ok {
		return nil, nil, fmt.Errorf("unknown cache kind %q", kind)
	}
	for _, d := range l.dirs {
		if err := collect(Dir(d), l.depth, &entries, &temps); err != nil {
			return nil, nil, err
		}
	}
	return entries, temps, nil
}

func collect(dir string, depth int, entries, temps *[]Entry) error {
	children, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, c := range children {
		path := filepath.Join(dir, c.Name())
		if !strings.HasPrefix(c.Name(), ".") && c.IsDir() && depth != 1 {
			if err := collect(path, max(depth-1, 0), entries, temps); err != nil {
				return err
			}
			continue
		}
		e, err := entryAt(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue // removed while walking
		}
		if err != nil {
			return err
		}
		if strings.HasPrefix(c.Name(), ".") {
			*temps = append(*temps, e)
		} else {
			*entries = append(*entries, e)
		}
	}
	return nil
}

// entryAt measures the entry at path: the bytes of every regular file under it.
func entryAt(path string) (Entry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{Path: path, LastUse: info.ModTime()}
	err = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			e.Size += fi.Size()
		}
		return nil
	})
	return e, err
}
