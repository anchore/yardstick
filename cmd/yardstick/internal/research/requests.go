package research

import (
	"fmt"

	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
)

// jobKey is what the rows one job researches share: a subject, an alias group and a source package.
type jobKey struct {
	subject       int
	group, source string
}

// Requests turns row ids into one request per finding group (subject x vulnerability alias group x
// source package), so sibling packages are researched once.
func Requests(g report.Gate, rowIDs []string) ([]Request, error) {
	byKey := map[jobKey]*Request{}
	var order []jobKey
	for _, id := range rowIDs {
		found := false
		for si, s := range g.Subjects {
			for _, m := range s.Matches {
				if m.Row != id {
					continue
				}
				found = true
				k := jobKey{si, m.Group, m.SourcePackage}
				if _, ok := byKey[k]; ok {
					continue
				}
				req := &Request{Vulnerability: m.Vulnerability, Package: m.Package, Rows: []string{m.Row}}
				for _, sib := range s.Matches {
					if sib.Row != m.Row && sib.Group == m.Group && sib.SourcePackage == m.SourcePackage {
						req.Rows = append(req.Rows, sib.Row)
					}
				}
				byKey[k] = req
				order = append(order, k)
			}
		}
		if !found {
			return nil, fmt.Errorf("no row %q in the gate", id)
		}
	}
	out := make([]Request, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out, nil
}

// Siblings is, by row, the rows one job would research with it (itself included, in report
// order), for every row that shares its job with another.
func Siblings(g report.Gate) map[string][]string {
	byKey := map[jobKey][]string{}
	for si, s := range g.Subjects {
		for _, m := range s.Matches {
			k := jobKey{si, m.Group, m.SourcePackage}
			byKey[k] = append(byKey[k], m.Row)
		}
	}
	out := map[string][]string{}
	for _, rows := range byKey {
		if len(rows) > 1 {
			for _, id := range rows {
				out[id] = rows
			}
		}
	}
	return out
}
