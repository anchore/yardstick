package report

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
)

// Focus is what --vulnerability and --package narrow a report to, each list as given. Values in
// one list combine as any-of, and the two lists as both. A focus narrows the rows a report shows
// and nothing else: every count, check value and state, outcome and the exit code stay the whole
// gate's, so narrowing what a run looks at can never turn a gate green.
type Focus struct {
	Vulnerabilities []string `json:"vulnerabilities"`
	Packages        []string `json:"packages"`
}

// NewFocus is the focus the flags give, nil when they give none.
func NewFocus(vulnerabilities, packages []string) *Focus {
	if len(vulnerabilities) == 0 && len(packages) == 0 {
		return nil
	}
	// empty lists rather than nil, so json names both
	return &Focus{Vulnerabilities: append([]string{}, vulnerabilities...), Packages: append([]string{}, packages...)}
}

// Narrow is a built gate with only the rows in focus: match rows, misses, loose labels, effects,
// and each check's failing rows, unlabeled rows and unmet expectations. Counts, check values and
// states, the outcome and Passed are left as they are. A vulnerability is compared by its alias
// group, so a GHSA id selects the row grype reported under its CVE. A nil focus narrows nothing.
func (f *Focus) Narrow(g Gate, aliases *pairing.Aliases) Gate {
	if f == nil {
		return g
	}
	want := map[string]bool{}
	for _, v := range f.Vulnerabilities {
		want[v] = true
		if group := aliases.Group(v); group != "" {
			want[group] = true
		}
	}
	// of says whether an id is in focus, as given or by its alias group; an advisory id has no
	// group, so it is in focus only as given
	of := func(id string) bool {
		if len(f.Vulnerabilities) == 0 || want[id] {
			return true
		}
		group := aliases.Group(id)
		return group != "" && want[group]
	}

	// match ids are unique within a subject, so what else is narrowed is looked up by them
	in := map[string]map[string]bool{}
	anywhere := map[string]bool{}
	subjects := make([]Subject, len(g.Subjects))
	for i, s := range g.Subjects {
		ids := map[string]bool{}
		var ms []Match
		for _, m := range s.Matches {
			// a match id ends in its alias group, the CVE where grype reported a single-CVE advisory
			_, group, _ := strings.Cut(m.ID, "/")
			if (of(group) || of(m.Vulnerability)) && f.on(m.Package) {
				ms = append(ms, m)
				ids[m.ID], anywhere[m.Row] = true, true
			}
		}
		s.Matches = ms
		s.Misses = keep(s.Misses, func(x Miss) bool { return of(x.Label.Vulnerability) && f.on(x.Label.Package) })
		// a loose label is in focus with any of its matches, and keeps them all, since they are
		// what shows it loose
		s.Loose = keep(s.Loose, func(l Loose) bool { return slices.ContainsFunc(l.Matches, func(id string) bool { return ids[id] }) })
		in[s.Name] = ids
		subjects[i] = s
	}
	g.Subjects = subjects
	g.Effects = keep(g.Effects, func(e analysis.Effect) bool { return in[e.Subject][e.Match] })

	checks := make([]analysis.Check, len(g.Checks))
	for i, c := range g.Checks {
		// a check's own FailsOn gathers every subject's as row ids, so it is narrowed by any subject's rows
		c.FailsOn = keep(c.FailsOn, func(id string) bool { return anywhere[id] })
		c.Unmet = keep(c.Unmet, func(x analysis.Expectation) bool { return of(x.Vulnerability) && f.on(x.Package) })
		c.Subjects = slices.Clone(c.Subjects)
		for j := range c.Subjects {
			sc := &c.Subjects[j]
			sc.FailsOn = keep(sc.FailsOn, func(id string) bool { return in[sc.Subject][id] })
			sc.Rows = keep(sc.Rows, func(id string) bool { return in[sc.Subject][id] })
		}
		checks[i] = c
	}
	g.Checks = checks
	return g
}

// on says whether a package purl is in focus: a pkg: value is a purl prefix, any other value the
// purl's name.
func (f *Focus) on(pkg string) bool {
	if len(f.Packages) == 0 {
		return true
	}
	name := purl.Package(pkg, "").Name
	for _, p := range f.Packages {
		if (strings.HasPrefix(p, "pkg:") && strings.HasPrefix(pkg, p)) || p == name {
			return true
		}
	}
	return false
}

// keep is the items ok selects, in a new slice, so narrowing never writes through to the gate it
// was given.
func keep[T any](xs []T, ok func(T) bool) []T {
	var out []T
	for _, x := range xs {
		if ok(x) {
			out = append(out, x)
		}
	}
	return out
}

// noFocusRows is what a layout prints for a gate with no row in focus, rather than nothing.
const noFocusRows = "no rows match the focus"

// missed says a focus left a gate's subjects without a single row. A gate with no subjects, such as
// one with stale scans, had no rows to narrow.
func (f *Focus) missed(g Gate) bool {
	if f == nil || len(g.Subjects) == 0 {
		return false
	}
	for _, s := range g.Subjects {
		if len(s.Matches)+len(s.Misses)+len(s.Loose) > 0 {
			return false
		}
	}
	for _, c := range g.Checks {
		if len(c.Unmet) > 0 {
			return false
		}
	}
	return true
}

// writeMissed is the line a layout prints under a gate's outcome when nothing of it is in focus.
func writeMissed(w io.Writer, f *Focus, g Gate, st styles) {
	if f.missed(g) {
		fmt.Fprintln(w, "  "+st.dim(noFocusRows))
	}
}

// writeFocus is the layouts' focus line, after the gates' headers, e.g.
//
//	focus  rows of CVE-2024-1234 on openssl; counts, values and outcomes are the whole gate's
func writeFocus(w io.Writer, f *Focus, st styles) {
	if f == nil {
		return
	}
	line := "rows"
	if len(f.Vulnerabilities) > 0 {
		line += " of " + strings.Join(f.Vulnerabilities, " or ")
	}
	if len(f.Packages) > 0 {
		line += " on " + strings.Join(f.Packages, " or ")
	}
	fmt.Fprintln(w, st.id("focus")+"  "+line+st.dim("; counts, values and outcomes are the whole gate's"))
	fmt.Fprintln(w)
}
