package research

import (
	"fmt"

	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
)

// Requests turns row ids into one request per finding group (subject x vulnerability alias group x
// source package), so sibling packages are researched once.
func Requests(g report.Gate, rowIDs []string) ([]Request, error) {
	type groupKey struct {
		subject       int
		group, source string
	}
	byKey := map[groupKey]*Request{}
	var order []groupKey
	for _, id := range rowIDs {
		found := false
		for si, s := range g.Subjects {
			for _, m := range s.Matches {
				if m.Row != id {
					continue
				}
				found = true
				k := groupKey{si, m.Group, m.SourcePackage}
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
