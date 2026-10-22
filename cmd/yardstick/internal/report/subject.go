package report

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
)

// bySubject is the subject-first layout: each gate's outcome and a line per check, then each
// subject a check does not pass on, with its counts in both setups, what each check says about it
// and the rows behind them, printed once. Subjects every check passes on collapse to one line.
func bySubject(w io.Writer, s Set, o Options) error {
	st := newStyles(o.Color)
	if !o.Quiet {
		for _, g := range s.Gates {
			writeRunHeader(w, g, st)
			fmt.Fprintln(w)
		}
		writeFocus(w, s.Focus, st)
	}
	gates := append([]Gate(nil), s.Gates...)
	sort.SliceStable(gates, func(i, j int) bool { return gates[i].Outcome.Rank() > gates[j].Outcome.Rank() })
	for _, g := range gates {
		if o.Quiet && g.Outcome == analysis.Pass {
			continue
		}
		subjectGate(w, g, s.Focus, o, st)
	}
	_, err := fmt.Fprintln(w, summaryLine(s.Summary, st))
	return err
}

// the verbs a gate's outcome takes
const (
	subjectPasses = "passes"
	subjectFails  = "fails"
)

// subjectGate is one gate: its outcome, its checks, then its subjects. A passing gate is its
// outcome line alone until --details passing.
func subjectGate(w io.Writer, g Gate, f *Focus, o Options, st styles) {
	line := st.state(g.Outcome, stateWord[g.Outcome]) + " " + st.id(g.Name)
	if g.Outcome == analysis.Undecided && g.Message == "" {
		line += fmt.Sprintf(" (undecided: %s, so it %s)", g.Undecided, map[bool]string{true: subjectPasses, false: subjectFails}[g.Passed])
	}
	if t := tally(g); t != "" {
		line += "  " + t
	}
	if g.Message != "" {
		line += ": " + g.Message
	}
	fmt.Fprintln(w, line)
	writeMissed(w, f, g, st)
	if g.Outcome == analysis.Pass && !o.showPassing() {
		fmt.Fprintln(w)
		return
	}
	var lines []subjectLine
	for _, c := range g.Checks {
		if c.State == analysis.Pass && !o.showPassing() {
			continue
		}
		lines = append(lines, subjectLine{c.State, []string{c.Name, params(c), subjectSpread(c)}})
	}
	subjectColumns(w, lines, st)
	fmt.Fprintln(w)
	if o.Quiet {
		return
	}
	var quiet []*Subject
	for _, sub := range subjectOrder(g) {
		if subjectState(g, sub.Name) == analysis.Pass {
			quiet = append(quiet, sub)
			continue
		}
		subjectBlock(w, g, sub, o, st)
	}
	subjectQuiet(w, g, quiet, o, st)
}

// subjectSpread is where a check stands across subjects, e.g. "on 1 subject, undecided on 1". A
// check over the whole gate gives its value instead.
func subjectSpread(c analysis.Check) string {
	if len(c.Subjects) == 0 {
		return span(c.Value)
	}
	n := map[analysis.State]int{}
	for _, sc := range c.Subjects {
		n[sc.State]++
	}
	out := "on " + subjectPlural(n[c.State], "subject")
	for _, other := range []analysis.State{analysis.Fail, analysis.Undecided} {
		if other != c.State && n[other] > 0 {
			out += fmt.Sprintf(", %s on %d", strings.ToLower(stateWord[other]), n[other])
		}
	}
	return out
}

func subjectPlural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// subjectLine is a check's line: its state, then columns.
type subjectLine struct {
	state analysis.State
	cells []string
}

// subjectColumns prints check lines failing first, each column but the last padded to its widest
// before it is styled.
func subjectColumns(w io.Writer, lines []subjectLine, st styles) {
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].state.Rank() > lines[j].state.Rank() })
	var widths []int
	for _, l := range lines {
		for i, c := range l.cells {
			if i == len(widths) {
				widths = append(widths, 0)
			}
			widths[i] = max(widths[i], utf8.RuneCountInString(c))
		}
	}
	for _, l := range lines {
		word := stateWord[l.state]
		line := "  " + st.state(l.state, word) + strings.Repeat(" ", 11-len(word))
		for i, c := range l.cells {
			if i < len(l.cells)-1 {
				c += strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c)+2)
			}
			line += c
		}
		fmt.Fprintln(w, line)
	}
}

// subjectOrder is a gate's subjects, failing first, each state in the gate's order.
func subjectOrder(g Gate) []*Subject {
	out := make([]*Subject, len(g.Subjects))
	for i := range g.Subjects {
		out[i] = &g.Subjects[i]
	}
	sort.SliceStable(out, func(i, j int) bool {
		return subjectState(g, out[i].Name).Rank() > subjectState(g, out[j].Name).Rank()
	})
	return out
}

// subjectState is the worst state any check gives a subject, an unmet expectation counting
// against it in its check's state.
func subjectState(g Gate, name string) analysis.State {
	worst := analysis.Pass
	for _, c := range g.Checks {
		for _, sc := range c.Subjects {
			if sc.Subject == name && sc.State.Rank() > worst.Rank() {
				worst = sc.State
			}
		}
		for _, x := range c.Unmet {
			if x.Subject == name && c.State.Rank() > worst.Rank() {
				worst = c.State
			}
		}
	}
	return worst
}

// subjectBlock is everything about one subject: its counts in both setups, each check's value on
// it and the rows behind them.
func subjectBlock(w io.Writer, g Gate, sub *Subject, o Options, st styles) {
	state := subjectState(g, sub.Name)
	fmt.Fprintln(w, st.state(state, stateWord[state])+" "+st.id(subjectName(sub.Name)))
	fmt.Fprintln(w, "  "+subjectCounts(g, sub, st))
	var lines []subjectLine
	var unmet []analysis.Expectation
	for _, c := range g.Checks {
		for _, sc := range c.Subjects {
			if sc.Subject != sub.Name || (sc.State == analysis.Pass && !o.showPassing()) {
				continue
			}
			v := span(sc.Value)
			if sc.Message != "" {
				v += "; " + sc.Message
			}
			lines = append(lines, subjectLine{sc.State, []string{c.Name, v}})
		}
		n := 0
		for _, x := range c.Unmet {
			if x.Subject == sub.Name {
				n++
				unmet = append(unmet, x)
			}
		}
		if n > 0 {
			lines = append(lines, subjectLine{c.State, []string{c.Name, subjectPlural(n, "expectation") + " unmet"}})
		}
	}
	subjectColumns(w, lines, st)
	for _, x := range unmet {
		fmt.Fprintf(w, "    %s %s%s\n", x.Verdict, st.id(x.Vulnerability), on(x.Package))
	}
	subjectGroups(w, g, sub, "  ", o, st)
	fmt.Fprintln(w)
}

// subjectCounts is a subject's F1 and counts, reference -> candidate, e.g. "F1 0.79 -> 0.72   tp
// 17 -> 14   fp 9 -> 9   unlabeled 785 -> 715". What changed is bold.
func subjectCounts(g Gate, sub *Subject, st styles) string {
	c, r := sub.Counts[gatefile.Candidate], sub.Counts[gatefile.Reference]
	pair := func(name, ref, cand string) string {
		if g.Header.OneSetup {
			return name + " " + cand
		}
		text := name + " " + ref + " -> " + cand
		if ref == cand {
			return st.dim(text)
		}
		return st.id(text)
	}
	out := strings.Join([]string{
		pair("F1", fmt.Sprintf("%.2f", r.F1), fmt.Sprintf("%.2f", c.F1)),
		pair("tp", fmt.Sprint(r.TP), fmt.Sprint(c.TP)),
		pair("fp", fmt.Sprint(r.FP), fmt.Sprint(c.FP)),
		pair("unlabeled", fmt.Sprint(r.Unlabeled), fmt.Sprint(c.Unlabeled)),
	}, "   ")
	if c.Labels == 0 && (g.Header.OneSetup || r.Labels == 0) {
		out += st.dim("  (no tp labels)")
	}
	return out
}

// subjectQuiet is the subjects every check passes on: one line, and with --details passing one
// line each.
func subjectQuiet(w io.Writer, g Gate, quiet []*Subject, o Options, st styles) {
	if len(quiet) == 0 {
		return
	}
	noun := "subjects pass"
	if len(quiet) == 1 {
		noun = "subject passes"
	}
	fmt.Fprintln(w, st.pass(fmt.Sprintf("%d %s every check", len(quiet), noun)))
	if !o.showPassing() {
		fmt.Fprintln(w)
		return
	}
	for _, sub := range quiet {
		c, r := sub.Counts[gatefile.Candidate], sub.Counts[gatefile.Reference]
		f1 := fmt.Sprintf("F1 %.2f -> %.2f", r.F1, c.F1)
		if g.Header.OneSetup {
			f1 = fmt.Sprintf("F1 %.2f", c.F1)
		}
		fmt.Fprintf(w, "  %s  %s  %s\n", st.pass("PASS"), f1, st.dim(subjectName(sub.Name)))
		if o.showRows() {
			subjectGroups(w, g, sub, "    ", o, st)
		}
	}
	fmt.Fprintln(w)
}

// subjectKey is what the rows of a subject group by: which setups report them, their label state,
// and the cause and effect of labeling them when a row has one.
type subjectKey struct {
	side, state, cause, effect string
	direction                  string
}

// subjectGroups prints a subject's rows, each once: by which setups report them, then in groups by
// label state, cause and effect. --details rows prints every row.
func subjectGroups(w io.Writer, g Gate, sub *Subject, indent string, o Options, st styles) {
	keys, byKey := subjectGrouped(g, sub)
	side := ""
	for _, k := range keys {
		if k.side != side {
			side = k.side
			fmt.Fprintln(w, indent+subjectSideLine(keys, byKey, side, st))
		}
		ms := byKey[k]
		fmt.Fprintf(w, "%s  %s: %s\n", indent, st.state(directionState[k.direction], fmt.Sprintf("%d %s", len(ms), k.state)), subjectVulns(ms, st))
		at := indent + "    on " + subjectPackages(ms)
		if k.cause != "" {
			at += "; " + st.undecided(k.cause)
		}
		fmt.Fprintln(w, at)
		if k.effect != "" {
			fmt.Fprintln(w, indent+"    "+st.dim(k.effect))
		}
		if o.showRows() {
			for _, l := range rowLines(ms, indent+"    ", st) {
				fmt.Fprintln(w, l)
			}
			for _, f := range subjectFiles(ms) {
				fmt.Fprintln(w, indent+"    "+st.dim("labels: "+f))
			}
		}
	}
}

// subjectGrouped are a subject's rows by key, labeled before unlabeled, each side together in the
// order first seen.
func subjectGrouped(g Gate, sub *Subject) ([]subjectKey, map[subjectKey][]Match) {
	var keys []subjectKey
	byKey := map[subjectKey][]Match{}
	for _, m := range subjectBehind(g, sub) {
		k := subjectKey{side: subjectSide(g, m), state: stateUnlabeled, direction: m.Direction}
		if m.Label != nil {
			k.state = string(m.Label.Verdict)
		}
		if miss := sub.missFor(&m); miss != nil {
			k.cause = causeSummary(*miss)
		}
		if eff := g.effect(sub.Name, m.ID); eff != nil {
			k.effect = subjectEffect(g, eff)
		}
		if _, ok := byKey[k]; !ok {
			keys = append(keys, k)
		}
		byKey[k] = append(byKey[k], m)
	}
	sides := map[string]int{}
	for _, k := range keys {
		if _, ok := sides[k.side]; !ok {
			sides[k.side] = len(sides)
		}
	}
	rank := map[string]int{string(claimsv1.TP): 0, string(claimsv1.FP): 1}
	sort.SliceStable(keys, func(i, j int) bool {
		if sides[keys[i].side] != sides[keys[j].side] {
			return sides[keys[i].side] < sides[keys[j].side]
		}
		ri, okI := rank[keys[i].state]
		rj, okJ := rank[keys[j].state]
		return okI && (!okJ || ri < rj)
	})
	return keys, byKey
}

// subjectBehind are a subject's rows: those only one setup reports and those any check names, in
// the subject's order.
func subjectBehind(g Gate, sub *Subject) []Match {
	ids := map[string]bool{}
	for _, c := range g.Checks {
		for _, sc := range c.Subjects {
			if sc.Subject != sub.Name {
				continue
			}
			for _, id := range append(slices.Clone(sc.FailsOn), sc.Rows...) {
				ids[id] = true
			}
		}
	}
	var out []Match
	for _, m := range sub.Matches {
		if ids[m.ID] || (!g.Header.OneSetup && m.InCandidate != m.InReference) {
			out = append(out, m)
		}
	}
	return out
}

func subjectSide(g Gate, m Match) string {
	switch {
	case g.Header.OneSetup:
		return "reported"
	case m.InCandidate && m.InReference:
		return "both setups report"
	case m.InReference:
		return "only the reference reports"
	}
	return "only the candidate reports"
}

// subjectSideLine heads the rows one side reports, e.g. "73 matches only the reference reports,
// all nvd:cpe cpe-match".
func subjectSideLine(keys []subjectKey, byKey map[subjectKey][]Match, side string, st styles) string {
	var ms []Match
	for _, k := range keys {
		if k.side == side {
			ms = append(ms, byKey[k]...)
		}
	}
	line := fmt.Sprintf("%d matches %s", len(ms), side)
	if len(ms) == 1 {
		line = "1 match " + side
	}
	types := map[string]bool{}
	for _, m := range ms {
		types[m.MatchType] = true
	}
	if len(types) == 1 && ms[0].MatchType != "" {
		line += st.dim(", all " + ms[0].MatchType)
	}
	return line
}

// subjectVulns names a group's vulnerabilities, the first two of a long list and an exact count.
func subjectVulns(ms []Match, st styles) string {
	var ids []string
	noun := nounCVEs
	for _, m := range ms {
		if !slices.Contains(ids, m.Vulnerability) {
			ids = append(ids, m.Vulnerability)
		}
		if !strings.HasPrefix(m.Vulnerability, "CVE-") {
			noun = nounVulns
		}
	}
	styled := make([]string, len(ids))
	for i, id := range ids {
		styled[i] = st.id(id)
	}
	if len(ids) <= 3 {
		return strings.Join(styled, ", ")
	}
	return fmt.Sprintf("%d %s (%s, %s)", len(ids), noun, strings.Join(styled[:2], ", "), st.dim(fmt.Sprintf("+%d more", len(ids)-2)))
}

// subjectPackages names a group's packages, counting the ones a short name leaves the same, e.g.
// "3 packages: stdlib@1.16.9, stdlib@1.18.4 x2".
func subjectPackages(ms []Match) string {
	var names, seen []string
	count := map[string]int{}
	for _, m := range ms {
		if id := pkgID(m); !slices.Contains(seen, id) {
			seen = append(seen, id)
			name := shortPackage(m.Package)
			if count[name] == 0 {
				names = append(names, name)
			}
			count[name]++
		}
	}
	if len(seen) == 1 {
		return names[0]
	}
	var parts []string
	for i, n := range names {
		if i == 2 && len(names) > 3 {
			parts = append(parts, fmt.Sprintf("+%d more", len(names)-2))
			break
		}
		if count[n] > 1 {
			n += fmt.Sprintf(" x%d", count[n])
		}
		parts = append(parts, n)
	}
	return fmt.Sprintf("%d packages: %s", len(seen), strings.Join(parts, ", "))
}

// subjectEffect says what labeling one of a group's rows does: to the gate, and to any check it
// moves when the gate's outcome does not.
func subjectEffect(g Gate, e *analysis.Effect) string {
	word := map[analysis.State]string{analysis.Pass: subjectPasses, analysis.Fail: subjectFails, analysis.Undecided: "is undecided"}
	tp, fp := e.Outcome[claimsv1.TP], e.Outcome[claimsv1.FP]
	if tp != fp {
		return fmt.Sprintf("if any one is labeled tp the gate %s, if fp it %s", word[tp], word[fp])
	}
	var moves []string
	for _, v := range []claimsv1.Verdict{claimsv1.TP, claimsv1.FP} {
		var moved []string
		for _, c := range g.Checks {
			if s, ok := e.States[v][c.Name]; ok && s != c.State {
				moved = append(moved, fmt.Sprintf("%s to %s", c.Name, s))
			}
		}
		if len(moved) > 0 {
			moves = append(moves, fmt.Sprintf("labeled %s moves %s", v, strings.Join(moved, ", ")))
		}
	}
	if len(moves) == 0 {
		return "the gate " + word[tp] + " whichever way any one is labeled"
	}
	return "any one " + strings.Join(moves, ", one ") + "; the gate " + word[tp] + " either way"
}

// subjectFiles are the label files deciding a group's rows.
func subjectFiles(ms []Match) []string {
	var out []string
	for _, m := range ms {
		if m.Label != nil && !slices.Contains(out, m.Label.File) {
			out = append(out, m.Label.File)
		}
	}
	return out
}
