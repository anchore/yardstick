// Package lookup asks each setup's DB about the rows only the other setup reported, right after
// scanning, so a one-sided row's computed reason (is the vulnerability in the other DB at all, was
// it rejected, what does the other DB have for the package) is answered offline when scoring.
// Ported from delta's internal/assay/lookup.go and internal/scan/affected.go.
package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"

	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
)

// NotInDB is the status of a vulnerability a DB has no record of.
const NotInDB = "not-in-db"

// File is what one setup's DB says about the rows the other setup alone reported, stored beside
// that setup's scans as <setup>/lookups.json.
type File struct {
	// Statuses are each one-sided row's ids' record status in this DB (active, rejected, ...) or
	// NotInDB.
	Statuses map[string]string `json:"statuses"`
	// Queries are the record searches that were made, with the rows each was made for.
	Queries []Query    `json:"queries"`
	Records []Affected `json:"records"`
}

// Looked says whether this DB's records were searched for a row.
func (f *File) Looked(row string) bool {
	if f == nil {
		return false
	}
	for _, q := range f.Queries {
		if slices.Contains(q.Rows, row) {
			return true
		}
	}
	return false
}

// Affected is one record a DB has for a vulnerability and a package: what the DB would match
// against, whether or not this scan matched it.
type Affected struct {
	Vulnerability string `json:"vulnerability"`
	Namespace     string `json:"namespace"`
	Package       string `json:"package,omitempty"`
	Ecosystem     string `json:"ecosystem,omitempty"`
	// CPE is set for a CPE record (e.g. in nvd:cpe), instead of a package.
	CPE         string   `json:"cpe,omitempty"`
	FixStates   []string `json:"fixStates,omitempty"`
	FixVersions []string `json:"fixVersions,omitempty"`
	Constraints []string `json:"constraints,omitempty"`
}

// Query is the vulnerabilities and packages (names, or CPEs) searched together, and the rows
// they were searched for.
type Query struct {
	Rows            []string `json:"rows"`
	Vulnerabilities []string `json:"vulnerabilities"`
	Packages        []string `json:"packages"`
	// BroadCPEMatching lets a CPE's specific attributes match a record's wildcards, as grype's CPE
	// matcher does; set for CPE queries.
	BroadCPEMatching bool `json:"broadCpeMatching,omitempty"`
}

// Row is a match only one setup reported, by its row id.
type Row struct {
	ID    string
	Match *pairing.Match
}

// Grype runs one setup's grype, pinned to its DB, and returns stdout.
type Grype func(ctx context.Context, args ...string) ([]byte, error)

// batch sizes keep each `grype db search` command line a reasonable length
const (
	statusBatch   = 500
	affectedBatch = 50
)

// Search asks the DB of setup, through its grype, about the rows: every row's ids for their
// record status, and for the rows the other setup reported, the records for their ids and
// packages (or the CPEs grype searched with, for a CPE match).
func Search(ctx context.Context, grype Grype, setup string, rows []Row) (*File, error) {
	var ids []string
	var byName, byCPE []Row
	for _, r := range rows {
		ids = appendUnique(ids, IDs(r.Match)...)
		found := r.Match.Details[other(setup)]
		switch {
		case found == nil:
		case found.CPEOnly():
			if len(found.CPEs) > 0 {
				byCPE = append(byCPE, r)
			}
		default:
			byName = append(byName, r)
		}
	}
	sort.Strings(ids)
	log.Infof("looking up %d vulnerabilities and %d rows' records in the %s DB", len(ids), len(byName)+len(byCPE), setup)
	f := &File{Queries: append(queries(byName, Names, false), queries(byCPE, func(m *pairing.Match) []string { return m.Details[other(setup)].CPEs }, true)...)}
	var err error
	if f.Statuses, err = statuses(ctx, grype, ids); err != nil {
		return nil, err
	}
	if f.Records, err = records(ctx, grype, f.Queries); err != nil {
		return nil, err
	}
	return f, nil
}

// statuses is each id's record status in the DB, NotInDB for one it has no record of.
func statuses(ctx context.Context, grype Grype, ids []string) (map[string]string, error) {
	out := map[string]string{}
	for _, id := range ids {
		out[id] = NotInDB
	}
	for start := 0; start < len(ids); start += statusBatch {
		data, err := grype(ctx, append([]string{"db", "search", "vuln", "-o", "json", "--limit", "0"}, ids[start:min(start+statusBatch, len(ids))]...)...)
		if err != nil {
			return nil, err
		}
		if err := parseStatuses(data, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// records is every record the queries find, once each.
func records(ctx context.Context, grype Grype, qs []Query) ([]Affected, error) {
	var out []Affected
	seen := map[string]bool{}
	for _, q := range qs {
		args := []string{"db", "search", "-o", "json", "--limit", "0"}
		for _, v := range q.Vulnerabilities {
			args = append(args, "--vuln", v)
		}
		for _, p := range q.Packages {
			args = append(args, "--pkg", p)
		}
		if q.BroadCPEMatching {
			args = append(args, "--broad-cpe-matching")
		}
		data, err := grype(ctx, args...)
		if err != nil {
			return nil, err
		}
		recs, err := parseAffected(data)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if k := r.Vulnerability + "|" + r.Namespace + "|" + r.Package + "|" + r.CPE; !seen[k] {
				seen[k] = true
				out = append(out, r)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Vulnerability != b.Vulnerability {
			return a.Vulnerability < b.Vulnerability
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.CPE != b.CPE {
			return a.CPE < b.CPE
		}
		return a.Namespace < b.Namespace
	})
	return out, nil
}

func other(setup string) string {
	if setup == pairing.Candidate {
		return pairing.Reference
	}
	return pairing.Candidate
}

// queries groups rows into batches searching their ids and packages together.
func queries(rows []Row, packages func(*pairing.Match) []string, cpes bool) []Query {
	var out []Query
	for start := 0; start < len(rows); start += affectedBatch {
		q := Query{BroadCPEMatching: cpes}
		for _, r := range rows[start:min(start+affectedBatch, len(rows))] {
			q.Rows = append(q.Rows, r.ID)
			q.Vulnerabilities = appendUnique(q.Vulnerabilities, IDs(r.Match)...)
			q.Packages = appendUnique(q.Packages, packages(r.Match)...)
		}
		sort.Strings(q.Vulnerabilities)
		sort.Strings(q.Packages)
		out = append(out, q)
	}
	return out
}

// IDs is every vulnerability id a match is known by.
func IDs(m *pairing.Match) []string {
	return appendUnique([]string{m.Vulnerability, m.Group}, m.Aliases...)
}

// Names is a match's package name, its source packages, and the package its fix ships in.
func Names(m *pairing.Match) []string {
	names := []string{m.Package.Name}
	for _, d := range m.Details {
		names = appendUnique(names, d.Upstreams...)
	}
	return appendUnique(names, m.SourcePackage())
}

// Load reads a lookups file.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

// statusRank orders record statuses by how much they say about whether a vulnerability is real:
// when a DB has several records for one id (NVD and distros for a CVE), the strongest wins, so a
// CVE its CNA rejected reads as rejected while some distro record is still active.
var statusRank = map[string]int{"rejected": 4, "disputed": 3, "analyzing": 2, "active": 1}

func parseStatuses(data []byte, into map[string]string) error {
	var records []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("unable to parse `grype db search vuln` output: %w", err)
	}
	for _, r := range records {
		status := r.Status
		if status == "" {
			status = "active" // providers that don't track status
		}
		if cur, ok := into[r.ID]; !ok || cur == NotInDB || statusRank[status] > statusRank[cur] {
			into[r.ID] = status
		}
	}
	return nil
}

func parseAffected(data []byte) ([]Affected, error) {
	var results []struct {
		Vulnerability struct {
			ID string `json:"id"`
		} `json:"vulnerability"`
		Packages []struct {
			Namespace string `json:"namespace"`
			CPE       string `json:"cpe"`
			Package   struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Detail struct {
				Ranges []struct {
					Version struct {
						Constraint string `json:"constraint"`
					} `json:"version"`
					Fix *struct {
						Version string `json:"version"`
						State   string `json:"state"`
					} `json:"fix"`
				} `json:"ranges"`
			} `json:"detail"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("unable to parse `grype db search` output: %w", err)
	}
	var out []Affected
	for _, res := range results {
		for _, pkg := range res.Packages {
			a := Affected{Vulnerability: res.Vulnerability.ID, Namespace: pkg.Namespace, Package: pkg.Package.Name, Ecosystem: pkg.Package.Ecosystem, CPE: pkg.CPE}
			for _, r := range pkg.Detail.Ranges {
				a.Constraints = appendUnique(a.Constraints, r.Version.Constraint)
				if r.Fix != nil {
					a.FixStates = appendUnique(a.FixStates, r.Fix.State)
					a.FixVersions = appendUnique(a.FixVersions, r.Fix.Version)
				}
			}
			out = append(out, a)
		}
	}
	return out, nil
}

func appendUnique(list []string, vs ...string) []string {
	for _, v := range vs {
		if v != "" && !slices.Contains(list, v) {
			list = append(list, v)
		}
	}
	return list
}
