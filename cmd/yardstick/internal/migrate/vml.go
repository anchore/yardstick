package migrate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// vmlLabel is one label of anchore/vulnerability-match-labels: a person's TP, FP or ?? on one
// vulnerability id reported on one package (by name and version) of one image.
type vmlLabel struct {
	ID    string `json:"ID"`
	Image struct {
		Exact string `json:"exact"`
	} `json:"image"`
	Label   string `json:"label"`
	Package *struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
	Vulnerability string `json:"vulnerability_id"`
	Tool          string `json:"tool"`
	User          string `json:"user"`
	Timestamp     string `json:"timestamp"`
	Note          string `json:"note"`
}

// record is an input label and the file it was read from, relative to the labels root.
type record struct {
	vmlLabel
	Source string
}

// readDir reads every label under a labels root (labels/<image>/<uuid>.json), or under one
// image's directory. Copied from delta's importer and changed to keep every label, so each one
// reaches the report.
func readDir(dir string) ([]record, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		// the labels root: its image directories hold the files
		if files, err = filepath.Glob(filepath.Join(dir, "*", "*.json")); err != nil {
			return nil, err
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no label files in %s (expected the labels directory, or one image's directory in it)", dir)
	}
	sort.Strings(files)
	log.Debugf("reading %d label files under %s", len(files), dir)
	defer log.Timed("reading label files under %s", dir)()

	var out []record
	for _, path := range files {
		labels, err := readFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		rel, _ := filepath.Rel(dir, path)
		log.Debugf("read %s: %d labels", rel, len(labels))
		for _, l := range labels {
			out = append(out, record{vmlLabel: l, Source: filepath.ToSlash(rel)})
		}
	}
	return out, nil
}

// readFile reads a label file, which may hold several JSON objects one after another.
func readFile(path string) ([]vmlLabel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []vmlLabel
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var l vmlLabel
		if err := dec.Decode(&l); errors.Is(err, io.EOF) {
			return out, nil
		} else if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
}

// parseNaiveTime reads ISO timestamps with or without an offset; those without one are UTC.
func parseNaiveTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse timestamp %q", s)
}
