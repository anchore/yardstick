package pairing

import (
	"slices"
	"strconv"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
)

// keeps says whether the gate's vulnerabilities filter keeps a reported match: its namespace is
// listed, and its year is no later than the max year or unknown.
func (r *Result) keeps(gm models.Match) bool {
	f := r.filter
	if f == nil {
		return true
	}
	if len(f.Namespaces) > 0 && !slices.Contains(f.Namespaces, gm.Vulnerability.Namespace) {
		return false
	}
	return f.MaxYear == 0 || matchYear(gm) <= f.MaxYear
}

// keepsLabel says whether the filter keeps a label: the year of its id or of any of its aliases,
// so an advisory label stays with the CVE match it pairs under --by-cve.
func (r *Result) keepsLabel(l claims.Label) bool {
	if r.keepsID(l.Vulnerability) {
		return true
	}
	return slices.ContainsFunc(l.Aliases, r.keepsID)
}

// keepsID says whether an id's year, from the id or else from the CVE in its alias group some
// setup reported, is no later than the max year or unknown.
func (r *Result) keepsID(id string) bool {
	if r.filter == nil || r.filter.MaxYear == 0 {
		return true
	}
	y := idYear(id)
	if y == 0 {
		y = r.years[r.aliases.Group(id)]
	}
	return y <= r.filter.MaxYear
}

// noteYears records the year of each alias group a reported match names a CVE in, for labels
// whose own id has no year.
func (r *Result) noteYears(gm models.Match) {
	if r.filter == nil || r.filter.MaxYear == 0 {
		return
	}
	ids := []string{gm.Vulnerability.ID}
	for _, rel := range gm.RelatedVulnerabilities {
		ids = append(ids, rel.ID)
	}
	for _, id := range ids {
		if y := cveYear(id); y != 0 {
			if g := r.aliases.Group(id); g != "" {
				r.years[g] = y
			}
		}
	}
}

// matchYear is a reported match's year: from its id, else from the first CVE related to it; zero
// when neither has one.
func matchYear(gm models.Match) int {
	if y := idYear(gm.Vulnerability.ID); y != 0 {
		return y
	}
	for _, rel := range gm.RelatedVulnerabilities {
		if y := cveYear(rel.ID); y != 0 {
			return y
		}
	}
	return 0
}

func cveYear(id string) int {
	if !strings.HasPrefix(strings.ToLower(id), "cve-") {
		return 0
	}
	return idYear(id)
}

// idYear is the year in a CVE, ALAS or ELSA id, e.g. CVE-2023-1234, or in an Amazon Linux extras
// id such as ALASRUBY3.0-2023-003, where it is the second to last part; zero for any other id.
// Ported from python yardstick's parse_year_from_id.
func idYear(id string) int {
	parts := strings.Split(id, "-")
	first := strings.ToLower(parts[0])
	switch {
	case len(parts) == 3 && (first == "cve" || first == "alas" || first == "elsa"):
		return year(parts[1])
	case strings.HasPrefix(first, "alas") && len(parts) >= 3:
		return year(parts[len(parts)-2])
	}
	return 0
}

func year(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil || v < 1990 || v > 9999 {
		return 0
	}
	return v
}
