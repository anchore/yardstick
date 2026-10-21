package report

import (
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
)

// byCheck is the check-first layout: each gate's outcome, then its checks in verdict order, each
// with the subjects behind it and their rows in groups. A group of rows printed under one check is
// referred back to from any later check instead of printed again.
func byCheck(w io.Writer, s Set, o Options) error {
	st := newStyles(o.Color)
	if !o.Quiet {
		for _, g := range s.Gates {
			writeRunHeader(w, g, st)
			fmt.Fprintln(w)
		}
		writeFocus(w, s.Focus, st)
	}
	for _, g := range checkSorted(s.Gates, func(g Gate) analysis.State { return g.Outcome }) {
		if o.Quiet && g.Outcome == analysis.Pass {
			continue
		}
		checkGate(w, g, s.Focus, o, st)
	}
	_, err := fmt.Fprintln(w, summaryLine(s.Summary, st))
	return err
}

var checkRank = map[analysis.State]int{analysis.Fail: 0, analysis.Undecided: 1, analysis.Pass: 2}

// checkSorted orders failing first, then undecided, then passing, keeping the order within each.
func checkSorted[T any](xs []T, state func(T) analysis.State) []T {
	out := slices.Clone(xs)
	sort.SliceStable(out, func(i, j int) bool { return checkRank[state(out[i])] < checkRank[state(out[j])] })
	return out
}

func checkGate(w io.Writer, g Gate, f *Focus, o Options, st styles) {
	line := st.state(g.Outcome, stateWord[g.Outcome]) + " gate " + st.id(g.Name)
	if g.Outcome == analysis.Undecided {
		line += fmt.Sprintf(" (undecided: %s, so it %s)", g.Undecided, checkGateVerb[map[bool]analysis.State{true: analysis.Pass, false: analysis.Fail}[g.Passed]])
	}
	if t := tally(g); t != "" {
		line += "  " + t
	}
	if g.Message != "" {
		line += ": " + g.Message
	}
	fmt.Fprintln(w, line)
	writeMissed(w, f, g, st)
	if g.Outcome != analysis.Pass || o.showPassing() {
		cols := newCheckColumns(g)
		cw := checkWriter{w: w, st: st, rows: o.showRows(), seen: map[string]string{}}
		for _, c := range checkSorted(g.Checks, func(c analysis.Check) analysis.State { return c.State }) {
			if c.State == analysis.Pass && !o.showPassing() {
				continue
			}
			fmt.Fprintln(w)
			fmt.Fprintln(w, cols.check(c, st))
			if !o.Quiet {
				cw.subjects(g, c, o, cols)
			}
		}
	}
	fmt.Fprintln(w)
}

// checkColumns are the widths a gate's lines align to. They are taken over every check and subject,
// printed or not, so a higher details level never moves a column.
type checkColumns struct {
	left, span int
}

func newCheckColumns(g Gate) checkColumns {
	var cc checkColumns
	for _, c := range g.Checks {
		cc.left = max(cc.left, utf8.RuneCountInString(checkLeft(c)))
		for _, sc := range c.Subjects {
			cc.span = max(cc.span, len(span(sc.Value)))
		}
	}
	return cc
}

func checkLeft(c analysis.Check) string {
	return stateWord[c.State] + " " + c.Name + "  " + checkParams(c)
}

func checkParams(c analysis.Check) string {
	if len(c.Params) > 0 {
		return params(c)
	}
	return "threshold " + num(c.Threshold)
}

// checkUnits name what a check's value counts.
var checkUnits = map[string]string{
	analysis.F1NotWorse:             " F1 drop",
	analysis.NoNewFalseNegatives:    " tp dropped",
	analysis.NoNewFalsePositives:    " fp added",
	analysis.UnjudgedChangesAtMost:  " unjudged",
	analysis.UnlabeledPercentAtMost: " percent unlabeled",
	analysis.ExpectationsMetAtLeast: " expectations met",
	analysis.NoNewMisses:            " expectations lost",
	analysis.MatchesAtLeast:         " matches",
}

// check is a check's line, e.g. "FAIL noNewFalseNegatives  max 0   worst subject 3..73 tp dropped".
func (cc checkColumns) check(c analysis.Check, st styles) string {
	scope := "worst subject"
	if c.Scope == analysis.PerGate {
		scope = "gate total"
	}
	pad := strings.Repeat(" ", cc.left-utf8.RuneCountInString(checkLeft(c))+3)
	line := st.state(c.State, stateWord[c.State]) + " " + st.id(c.Name) + "  " + st.dim(checkParams(c)) + pad +
		st.dim(scope) + " " + span(c.Value) + checkUnits[c.Name]
	if c.Message != "" {
		line += "; " + c.Message
	}
	return line
}

// subject is a subject's line under a check: its state, its value and its name.
func (cc checkColumns) subject(sc analysis.SubjectCheck, st styles) string {
	word, v, name := stateWord[sc.State], span(sc.Value), st.id(subjectName(sc.Subject))
	if sc.State == analysis.Pass {
		name = st.dim(subjectName(sc.Subject))
	}
	line := "  " + st.state(sc.State, word) + strings.Repeat(" ", len("UNDECIDED")-len(word)+2) +
		v + strings.Repeat(" ", cc.span-len(v)+2) + name
	if sc.Message != "" {
		line += "; " + sc.Message
	}
	return line
}

// checkWriter writes a gate's row groups, remembering which check printed each group first.
type checkWriter struct {
	w    io.Writer
	st   styles
	rows bool
	// seen maps a group's rows to the check that printed them
	seen map[string]string
}

// subjects prints the subjects behind a check, failing and undecided ones with their rows. The
// passing ones are a count with --details passing, and listed with --details rows.
func (cw checkWriter) subjects(g Gate, c analysis.Check, o Options, cols checkColumns) {
	relative := analysis.Registry[c.Name].ReadsReference
	var passing []analysis.SubjectCheck
	for _, sc := range c.Subjects {
		if sc.State == analysis.Pass {
			passing = append(passing, sc)
			continue
		}
		fmt.Fprintln(cw.w, cols.subject(sc, cw.st))
		gs, causes := checkGroups(g, sc, relative, cw.st)
		cw.groups(gs, sc.Subject, c.Name, true, causes)
	}
	cw.unmet(g, c)
	if !o.showPassing() || len(passing) == 0 {
		return
	}
	noun := map[bool]string{true: "subject passes", false: "subjects pass"}[len(passing) == 1]
	fmt.Fprintln(cw.w, "  "+cw.st.dim(fmt.Sprintf("%d %s", len(passing), noun)))
	if !o.showRows() {
		return
	}
	for _, sc := range passing {
		fmt.Fprintln(cw.w, cols.subject(sc, cw.st))
		gs, causes := checkGroups(g, sc, relative, cw.st)
		// only what the default output prints is referred back to, so these never register
		cw.groups(gs, sc.Subject, c.Name, false, causes)
	}
}

// checkGroups are a subject's rows under a check, grouped, with the cause line of each row the
// candidate's miss of a label explains.
func checkGroups(g Gate, sc analysis.SubjectCheck, relative bool, st styles) (groups, map[string]string) {
	sub := g.subject(sc.Subject)
	var gs groups
	causes := map[string]string{}
	for _, id := range sc.FailsOn {
		if m := sub.match(id); m != nil {
			k := matchKey(*m, relative)
			if miss := sub.missFor(m); miss != nil {
				k.cause = causeSummary(*miss)
				// the group carries the cause; a row adds only what a near miss pairs instead
				if len(miss.NearMiss) > 0 {
					causes[id] = causeLine(*miss, st)
				}
			}
			gs.addMatch(k, *m)
		}
	}
	for _, id := range sc.Rows {
		if m := sub.match(id); m != nil {
			k := matchKey(*m, relative)
			if eff := g.effect(sc.Subject, id); eff != nil {
				k.effect = checkEffect(*eff)
			}
			gs.addMatch(k, *m)
		}
	}
	return gs, causes
}

var checkGateVerb = map[analysis.State]string{analysis.Pass: "passes", analysis.Fail: "fails", analysis.Undecided: "is undecided"}

// checkEffect is what labeling one row does to the gate. It does not depend on the check, so a
// group referred back to loses nothing.
func checkEffect(e analysis.Effect) string {
	tp, fp := e.Outcome[claimsv1.TP], e.Outcome[claimsv1.FP]
	if tp == fp {
		return "the gate " + checkGateVerb[tp] + " however one is labeled"
	}
	return fmt.Sprintf("one labeled tp: the gate %s; fp: it %s", checkGateVerb[tp], checkGateVerb[fp])
}

// unmet prints the expectations a per-gate check found unmet, grouped.
func (cw checkWriter) unmet(g Gate, c analysis.Check) {
	var gs groups
	for _, x := range c.Unmet {
		k := groupKey{state: string(x.Verdict), delta: "unmet on " + subjectName(x.Subject), pkg: basePURL(x.Package)}
		lines := []string{"      " + cw.st.id(x.Vulnerability) + on(x.Package)}
		if miss := g.subject(x.Subject).missOn(x.Package, x.Vulnerability); miss != nil && x.Verdict == claimsv1.TP {
			k.cause = causeSummary(*miss)
			lines = append(lines, causeLine(*miss, cw.st))
		}
		gs.add(k, x.Vulnerability, x.Package, x.Package, lines...)
	}
	cw.groups(gs, "", c.Name, false, nil)
}

// groups prints each group, or a reference to the check that printed the same rows. register
// records a group as printed, for the groups every details level prints.
func (cw checkWriter) groups(gs groups, subject, check string, register bool, causes map[string]string) {
	for _, g := range gs {
		key := checkRowsKey(subject, g)
		if first, ok := cw.seen[key]; ok && key != "" {
			fmt.Fprintln(cw.w, "    "+checkHead(g, true, cw.st)+"  "+cw.st.dim("same rows as "+first))
			continue
		}
		if register && key != "" {
			cw.seen[key] = check
		}
		cw.group(g, causes)
	}
}

// checkRowsKey names a group by its subject and match ids; empty for a group of no matches.
func checkRowsKey(subject string, g *group) string {
	if len(g.matches) == 0 {
		return ""
	}
	ids := make([]string, len(g.matches))
	for i, m := range g.matches {
		ids[i] = m.ID
	}
	slices.Sort(ids)
	return subject + "\x00" + strings.Join(ids, "\x00")
}

// checkHead is a group's first line, e.g. "3 tp, dropped by the candidate", colored by whether the
// change helps the candidate. short drops "by the candidate", for a reference.
func checkHead(g *group, short bool, st styles) string {
	text := fmt.Sprintf("%d %s", g.rows, strings.TrimPrefix(g.state, "labeled "))
	if d := g.delta; d != "" {
		if short {
			d = strings.TrimSuffix(d, " by the candidate")
		}
		text += ", " + d
	}
	switch {
	case len(g.matches) == 0:
		return st.fail(text)
	case g.delta != "" && g.matches[0].Direction != "":
		return st.state(directionState[g.matches[0].Direction], text)
	case g.state == stateUnlabeled:
		return st.undecided(text)
	}
	return text
}

// checkWidth is the column a group's lines wrap before.
const checkWidth = 80

// group prints a group in full: what and where, then faint how it was matched, why it was missed or
// what labeling it does. --details rows adds every row, told apart by location.
func (cw checkWriter) group(g *group, causes map[string]string) {
	st := cw.st
	fmt.Fprintln(cw.w, "    "+checkHead(g, false, st))
	what, n := checkVulns(g, st)
	if where := checkPackages(g); where != "" {
		if 6+n+4+utf8.RuneCountInString(where) > checkWidth {
			fmt.Fprintln(cw.w, "      "+what)
			what = "on " + where
		} else {
			what += " on " + where
		}
	}
	fmt.Fprintln(cw.w, "      "+what)
	var notes []string
	if g.matchType != "" {
		notes = append(notes, st.dim(g.matchType))
	}
	if g.cause != "" {
		notes = append(notes, st.undecided(g.cause))
	}
	if g.effect != "" {
		notes = append(notes, st.dim(g.effect))
	}
	if len(notes) > 0 {
		fmt.Fprintln(cw.w, "      "+strings.Join(notes, st.dim("; ")))
	}
	if cw.rows {
		cw.groupRows(g, causes)
	}
}

func (cw checkWriter) groupRows(g *group, causes map[string]string) {
	if len(g.matches) == 0 {
		for _, l := range g.lines {
			fmt.Fprintln(cw.w, l)
		}
		return
	}
	var files []string
	for i, l := range rowLines(g.matches, "      ", cw.st) {
		fmt.Fprintln(cw.w, l)
		m := g.matches[i]
		if c, ok := causes[m.ID]; ok {
			fmt.Fprintln(cw.w, c)
		}
		if m.Label != nil && !slices.Contains(files, checkLabelFile(m.Label.File)) {
			files = append(files, checkLabelFile(m.Label.File))
		}
	}
	if len(files) > 0 {
		fmt.Fprintln(cw.w, "      "+cw.st.dim("labels: "+strings.Join(files, ", ")))
	}
}

var checkDigest = regexp.MustCompile(`([0-9a-f]{12})[0-9a-f]{52}`)

// checkLabelFile is a label file as a hint prints it: its last three path elements, a digest in
// them cut to 12 hex characters.
func checkLabelFile(p string) string {
	p = checkDigest.ReplaceAllString(p, "$1...")
	if parts := strings.Split(p, "/"); len(parts) > 3 {
		p = ".../" + strings.Join(parts[len(parts)-3:], "/")
	}
	return p
}

// checkVulns names a group's vulnerabilities, or counts them when there are more than a line
// holds, and gives the unstyled length.
func checkVulns(g *group, st styles) (string, int) {
	// "+1 more" would take the room of the id it stands for
	if len(g.vulns) <= listed+1 {
		ids := make([]string, len(g.vulns))
		for i, v := range g.vulns {
			ids[i] = st.id(v)
		}
		plain := strings.Join(g.vulns, ", ")
		return strings.Join(ids, ", "), utf8.RuneCountInString(plain)
	}
	noun := nounCVEs
	for _, v := range g.vulns {
		if !strings.HasPrefix(v, "CVE-") {
			noun = nounVulns
		}
	}
	s := fmt.Sprintf("%d %s", len(g.vulns), noun)
	return s, len(s)
}

// checkPackages names a group's package, or for several their shared purl and each one's version,
// e.g. "3 pkg:golang/stdlib packages (1.16.9, 1.18.4 x2)".
func checkPackages(g *group) string {
	if len(g.pkgs) <= 1 {
		return g.named
	}
	var versions []string
	count := map[string]int{}
	seen := map[string]bool{}
	for _, m := range g.matches {
		id := pkgID(m)
		if seen[id] {
			continue
		}
		seen[id] = true
		_, v, _ := strings.Cut(strings.SplitN(m.Package, "?", 2)[0], "@")
		if count[v] == 0 {
			versions = append(versions, v)
		}
		count[v]++
	}
	for i, v := range versions {
		if count[v] > 1 {
			versions[i] = fmt.Sprintf("%s x%d", v, count[v])
		}
	}
	s := fmt.Sprintf("%d %s packages", len(g.pkgs), g.pkg)
	if len(versions) > 0 && versions[0] != "" {
		s += " (" + strings.Join(versions, ", ") + ")"
	}
	return s
}
