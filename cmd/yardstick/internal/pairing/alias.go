package pairing

import (
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
)

// Aliases groups vulnerability ids that name one vulnerability. It is built from every relation
// either setup's DB reported plus every label's id, so two ids are one group if any DB of the gate
// says so: a candidate DB that drops a CVE to GHSA link does not turn a match into a miss.
// Advisory ids never join a group, since one advisory can name several CVEs. Copied from delta's
// union-find.
type Aliases struct {
	parent   map[string]string
	advisory func(id string) bool
}

// NewAliases starts empty; isAdvisory tells advisory ids apart (the corpus's advisory-ids).
func NewAliases(isAdvisory func(id string) bool) *Aliases {
	if isAdvisory == nil {
		isAdvisory = func(string) bool { return false }
	}
	return &Aliases{parent: map[string]string{}, advisory: isAdvisory}
}

// AddScan adds every id a setup reported and every relation it reported for them.
func (a *Aliases) AddScan(doc *models.Document) {
	if doc == nil {
		return
	}
	for _, m := range doc.Matches {
		ids := []string{m.Vulnerability.ID}
		for _, r := range m.RelatedVulnerabilities {
			ids = append(ids, r.ID)
		}
		if a.advisory(m.Vulnerability.ID) {
			// an advisory's related ids are what it names, not aliases of one another
			for _, id := range ids[1:] {
				a.add(id)
			}
			continue
		}
		a.add(ids...)
	}
}

// AddLabels adds each label's id, and each of its aliases, as a group of its own until a scan
// relates it.
func (a *Aliases) AddLabels(ls []claims.Label) {
	for _, l := range ls {
		a.add(l.Vulnerability)
		for _, id := range l.Aliases {
			a.add(id)
		}
	}
}

// add puts the non-advisory ids into one group.
func (a *Aliases) add(ids ...string) {
	var keep []string
	for _, id := range ids {
		if a.advisory(id) {
			continue
		}
		keep = append(keep, id)
		if _, ok := a.parent[id]; !ok {
			a.parent[id] = id
		}
	}
	for _, id := range keep[min(1, len(keep)):] {
		a.union(keep[0], id)
	}
}

// Group is the id naming an id's group, the lexically smallest in it; empty for an advisory. It
// never changes the set, so groups can be read from any number of goroutines once built.
func (a *Aliases) Group(id string) string {
	if a.advisory(id) {
		return ""
	}
	return a.find(id)
}

// find walks to an id's root without compressing the path, so Group only reads: alias groups are
// a CVE and a few advisories, and the chains stay short.
func (a *Aliases) find(id string) string {
	for {
		p, ok := a.parent[id]
		if !ok || p == id {
			return id
		}
		id = p
	}
}

// union keeps the lexically smallest id as the root, so group names are stable across runs.
func (a *Aliases) union(x, y string) {
	rx, ry := a.find(x), a.find(y)
	switch {
	case rx == ry:
		return
	case rx < ry:
		a.parent[ry] = rx
	default:
		a.parent[rx] = ry
	}
}
