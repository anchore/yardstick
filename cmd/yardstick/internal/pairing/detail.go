package pairing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
)

// Detail is the record one setup's grype matched, as delta's report names it, so the skills and
// the map UI read either. Copied from delta's scan.Detail, less the package locations and the
// descriptions and URLs, which nothing reading a report uses and which grow it several times over.
type Detail struct {
	Severity    string   `json:"severity,omitempty"`
	Namespace   string   `json:"namespace,omitempty"`
	DataSource  string   `json:"dataSource,omitempty"`
	FixState    string   `json:"fixState,omitempty"`
	FixVersions []string `json:"fixVersions,omitempty"`
	// Constraints are the version constraints that matched, as grype reports them, e.g.
	// "< 1.2-3 (deb)".
	Constraints []string `json:"constraints,omitempty"`
	MatchTypes  []string `json:"matchTypes,omitempty"`
	Matchers    []string `json:"matchers,omitempty"`
	// CPEs are the package CPEs grype searched by, for a CPE match.
	CPEs []string `json:"cpes,omitempty"`
	// Upstreams are the package's source packages, e.g. glibc for libc6.
	Upstreams []string `json:"upstreams,omitempty"`
	// Distro is the scanned distro, e.g. "debian 12".
	Distro  string    `json:"distro,omitempty"`
	Related []Related `json:"relatedRecords,omitempty"`
}

// Related is another record grype linked to the match, such as the NVD entry of a distro CVE.
type Related struct {
	ID         string `json:"id"`
	Namespace  string `json:"namespace,omitempty"`
	DataSource string `json:"dataSource,omitempty"`
}

// CPEOnly says whether grype found the match only by CPE.
func (d *Detail) CPEOnly() bool {
	return len(d.MatchTypes) > 0 && !slices.ContainsFunc(d.MatchTypes, func(t string) bool { return t != "cpe-match" })
}

func detail(gm models.Match, doc *models.Document) *Detail {
	v := gm.Vulnerability
	d := &Detail{Severity: v.Severity, Namespace: v.Namespace, DataSource: v.DataSource,
		FixState: v.Fix.State, FixVersions: v.Fix.Versions, Distro: strings.TrimSpace(doc.Distro.Name + " " + doc.Distro.Version)}
	for _, r := range gm.RelatedVulnerabilities {
		d.Related = append(d.Related, Related{ID: r.ID, Namespace: r.Namespace, DataSource: r.DataSource})
	}
	for _, md := range gm.MatchDetails {
		d.MatchTypes = AppendUnique(d.MatchTypes, md.Type)
		d.Matchers = AppendUnique(d.Matchers, md.Matcher)
		// searchedBy and found are free-form in grype's models, so they are read through JSON
		var searched struct {
			CPEs []string `json:"cpes"`
		}
		var found struct {
			VersionConstraint string `json:"versionConstraint"`
		}
		remarshal(md.SearchedBy, &searched)
		remarshal(md.Found, &found)
		d.CPEs = AppendUnique(d.CPEs, searched.CPEs...)
		d.Constraints = AppendUnique(d.Constraints, found.VersionConstraint)
	}
	for _, u := range gm.Artifact.Upstreams {
		d.Upstreams = AppendUnique(d.Upstreams, u.Name)
	}
	return d
}

// remarshal reads a decoded free-form value into a struct, leaving it zero when the shape differs.
func remarshal(from, into any) {
	if data, err := json.Marshal(from); err == nil {
		_ = json.Unmarshal(data, into)
	}
}

// AppendUnique appends each non-empty value not already in list.
func AppendUnique(list []string, vs ...string) []string {
	for _, v := range vs {
		if v != "" && !slices.Contains(list, v) {
			list = append(list, v)
		}
	}
	return list
}

// SourcePackage is the package a fix ships in: grype's upstream (glibc for libc6), else for maven
// the groupId (jetty-server and jetty-http are released together as org.eclipse.jetty), else the
// package name. The map UI groups rows by it.
func (m *Match) SourcePackage() string {
	for _, setup := range []string{gatefile.Candidate, gatefile.Reference} {
		if d := m.Details[setup]; d != nil && len(d.Upstreams) > 0 {
			return d.Upstreams[0]
		}
	}
	if m.pkg.Type == "maven" && m.pkg.Namespace != "" {
		return m.pkg.Namespace
	}
	return m.Package.Name
}

// RowID names a match across a gate: 16 hex of the sha256 of its subject and match id, so it is
// stable across re-scoring the same scans and unique within the gate.
func RowID(subject, matchID string) string {
	sum := sha256.Sum256([]byte(subject + "\x00" + matchID))
	return hex.EncodeToString(sum[:8])
}

// Scanned pairs each subject's scans with no labels over one gate-wide alias set. A label only
// ever adds its id as a group of its own, so the matches and their ids are the ones scoring gives.
func Scanned(subjects []Subject, isAdvisory func(string) bool) []*Result {
	a := NewAliases(isAdvisory)
	for _, s := range subjects {
		for _, doc := range s.Scans {
			a.AddScan(doc)
		}
	}
	out := make([]*Result, len(subjects))
	for i, s := range subjects {
		s.Labels = nil
		out[i] = Pair(a, s)
	}
	return out
}
