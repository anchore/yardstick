// Package runrecord is the record of a gate's last scans under a run name,
// .yardstick/runs/<name>/<gate>/yardstick-run.json in the working directory, beside the grype
// outputs it lists: what each setup resolved to, each claims source's snapshot, and each subject's
// SBOM. yardstick score and yardstick claims add find it by run name and gate name. It is the only
// run file yardstick writes or reads, and nothing under .yardstick/ outside RunsDir is touched.
package runrecord

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

// File is the record's name in a gate's scans directory.
const File = "yardstick-run.json"

// RunsDir holds one directory per run name, each holding its gates' scans, relative to the working
// directory. Python yardstick owns the other entries of .yardstick/, so both can share it.
var RunsDir = filepath.Join(".yardstick", "runs")

// DefaultName is the run name when none is given.
const DefaultName = "default"

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// CheckName refuses a run name that is not one safe path segment.
func CheckName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("run name %q must match [a-z0-9][a-z0-9._-]*, since it names a directory under %s", name, RunsDir)
	}
	return nil
}

// Record is one gate's last scans.
type Record struct {
	Gate    Gate                      `json:"gate"`
	Created string                    `json:"created"`
	Setups  map[string]setup.Prepared `json:"setups"`
	Claims  []Source                  `json:"claims"`
	// RebuildSBOMs says the corpus SBOMs were bypassed (--rebuild-sboms).
	RebuildSBOMs bool `json:"rebuildSBOMs,omitempty"`
	// InheritedEnv names the caller's GRYPE_* and SYFT_* variables --inherit-env passed on. Their
	// values, which may be credentials, are never recorded.
	InheritedEnv []string  `json:"inheritedEnv,omitempty"`
	Subjects     []Subject `json:"subjects"`
	// Lookups are, by setup, what its DB said about the rows only the other setup reported,
	// relative to the scans directory. A record made before lookups has none, and those rows
	// score as unexplained.
	Lookups  map[string]string `json:"lookups,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
}

// Complete fails unless every subject has a scan from every setup the record prepared: what an
// interrupted run would leave, and what scoring would read as a setup reporting nothing.
func (r *Record) Complete() error {
	for _, s := range r.Subjects {
		for _, setup := range slices.Sorted(maps.Keys(r.Setups)) {
			if s.Scans[setup] == "" {
				return fmt.Errorf("the scans of gate %s are incomplete: subject %s has no %s scan", r.Gate.Name, s.Name, setup)
			}
		}
	}
	return nil
}

// Gate identifies the gate file the scans were made for.
type Gate struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Fingerprint string `json:"fingerprint"`
}

// Source is a claims source and the snapshot of what the scan read from it.
type Source struct {
	Locator  string `json:"locator"`
	Kind     string `json:"kind"`
	Snapshot string `json:"snapshot"`
	Commit   string `json:"commit,omitempty"`
}

// Subject is one subject's SBOM and each setup's grype output, relative to the scans directory.
type Subject struct {
	// the resolved subject, its scanned SBOM's packages included, so scoring reads no SBOM
	subject.Resolved
	// Scans are each setup's grype output, relative to the scans directory.
	Scans map[string]string `json:"scans"`
	// ScanKeys are the keys each setup's scan is stored under in the scan cache. A scan that
	// cannot be keyed, a dir: DB holding no DB file, has none.
	ScanKeys map[string]string `json:"scanKeys,omitempty"`
	// Logs are each setup's grype stderr from its scan, gzipped, relative to the scans directory.
	// A scan reused from a cache entry stored before logs were kept has none.
	Logs map[string]Log `json:"logs,omitempty"`
}

// Log is a gzipped tool log and the sha256 of its text, so an excerpt quoted from it can be checked.
type Log struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Rerun is the command that writes a gate's scans under a run name, for an error to point at.
func Rerun(name, gatePath string) string {
	if name == DefaultName {
		return "yardstick " + gatePath
	}
	return "yardstick " + gatePath + " --name " + name
}

// Dir is a gate's scans directory under a run name.
func Dir(name, gate string) string {
	return filepath.Join(RunsDir, name, gate)
}

// Load reads a gate's record under a run name; os.ErrNotExist when the gate was never scanned
// under it here.
func Load(name, gate string) (*Record, error) {
	data, err := os.ReadFile(filepath.Join(Dir(name, gate), File))
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(Dir(name, gate), File), err)
	}
	return &r, nil
}

// Partial is a set of scans being made, in a directory beside the gate's, until Replace makes it
// the gate's scans. A run that fails part way leaves the last scans as they were.
type Partial struct {
	Name string
	Gate string
	Dir  string
}

// Start begins a new set of scans for a gate under a run name, clearing one an earlier failed run
// left. The partial and old directories sit beside the gate's, under the name.
func Start(name, gate string) (*Partial, error) {
	// the one place a run directory is made, so no write lands outside a valid name
	if err := CheckName(name); err != nil {
		return nil, err
	}
	dir := filepath.Join(RunsDir, name, ".partial-"+gate)
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Partial{Name: name, Gate: gate, Dir: dir}, nil
}

// Write puts a file into the partial set, by its path relative to the scans directory.
func (p *Partial) Write(rel string, data []byte) error {
	target := filepath.Join(p.Dir, rel)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o600)
}

// Replace writes the record into the partial set and makes it the gate's scans.
func (p *Partial) Replace(r *Record) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := p.Write(File, append(data, '\n')); err != nil {
		return err
	}
	final := Dir(p.Name, p.Gate)
	old := filepath.Join(RunsDir, p.Name, ".old-"+p.Gate)
	if err := os.RemoveAll(old); err != nil {
		return err
	}
	if err := os.Rename(final, old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(p.Dir, final); err != nil {
		return err
	}
	return os.RemoveAll(old)
}

// Discard removes a partial set that will not be used.
func (p *Partial) Discard() {
	_ = os.RemoveAll(p.Dir)
}
