package report

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
)

// byCause is the cause-first layout: each gate's checks and the changes driving them, then each
// change between the setups, every row printed once under the change that produced it. A change
// is the rows that share a direction, a matcher and a match type, across every subject.
func byCause(w io.Writer, s Set, o Options) error {
	st := newStyles(o.Color)
	if !o.Quiet {
		for _, g := range s.Gates {
			writeRunHeader(w, g, st)
			fmt.Fprintln(w)
		}
		writeFocus(w, s.Focus, st)
	}
	// failing and undecided gates first, each one's outcome before any detail about it
	gates := append([]Gate(nil), s.Gates...)
	sort.SliceStable(gates, func(i, j int) bool { return gates[i].Outcome.Rank() > gates[j].Outcome.Rank() })
	for _, g := range gates {
		if o.Quiet && g.Outcome == analysis.Pass {
			continue
		}
		causeWriteGate(w, g, s.Focus, o, st)
	}
	_, err := fmt.Fprintln(w, summaryLine(s.Summary, st))
	return err
}

// causeWidth is the column the layout wraps its prose at.
const causeWidth = 80

// causeListed is how many vulnerabilities a group names before giving only their count.
const causeListed = 5

// causeChange is one change between the setups and its rows, by subject.
type causeChange struct {
	dropped            bool
	matcher, matchType string
	subjects           []string
	// groups are each subject's rows by direction
	groups map[string]groups
	// rank is the worst state of a check behind its rows, by State.Rank; -1 for none
	rank int
}

func (c *causeChange) matches() []Match {
	var out []Match
	for _, s := range c.subjects {
		for _, g := range c.groups[s] {
			out = append(out, g.matches...)
		}
	}
	return out
}

// causeChanges groups a gate's deltas into changes, the ones behind the worst checks first.
func causeChanges(g Gate) []*causeChange {
	var out []*causeChange
	for _, sub := range g.Subjects {
		for _, m := range sub.Matches {
			if m.InCandidate == m.InReference {
				continue
			}
			var c *causeChange
			for _, have := range out {
				if have.dropped == m.InReference && have.matcher == m.Matcher && have.matchType == m.MatchType {
					c = have
				}
			}
			if c == nil {
				c = &causeChange{dropped: m.InReference, matcher: m.Matcher, matchType: m.MatchType, groups: map[string]groups{}, rank: -1}
				out = append(out, c)
			}
			if _, ok := c.groups[sub.Name]; !ok {
				c.subjects = append(c.subjects, sub.Name)
			}
			gs := c.groups[sub.Name]
			gs.addMatch(groupKey{state: m.Direction}, m)
			c.groups[sub.Name] = gs
		}
	}
	// within a subject, what the candidate made worse first, then what it fixed, then the unlabeled
	order := map[string]int{Introduced: 0, Fixed: 1, Review: 2}
	for _, c := range out {
		for _, gs := range c.groups {
			sort.SliceStable(gs, func(i, j int) bool { return order[gs[i].state] < order[gs[j].state] })
		}
	}
	for _, chk := range g.Checks {
		for _, c := range causeBehind(chk, out) {
			c.rank = max(c.rank, chk.State.Rank())
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].rank > out[j].rank })
	return out
}

// causeBehind are the changes holding a check's rows, in the order given.
func causeBehind(chk analysis.Check, changes []*causeChange) []*causeChange {
	var out []*causeChange
	for _, sc := range chk.Subjects {
		for _, id := range append(slices.Clone(sc.FailsOn), sc.Rows...) {
			if c := causeOf(changes, sc.Subject, id); c != nil && !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

// causeOf is the change holding a subject's match.
func causeOf(cs []*causeChange, subject, id string) *causeChange {
	for _, c := range cs {
		for _, g := range c.groups[subject] {
			for _, m := range g.matches {
				if m.ID == id {
					return c
				}
			}
		}
	}
	return nil
}

func causeWriteGate(w io.Writer, g Gate, f *Focus, o Options, st styles) {
	line := st.state(g.Outcome, stateWord[g.Outcome]) + " " + st.id(g.Name)
	if t := tally(g); t != "" {
		line += "  " + t
	}
	if g.Outcome == analysis.Undecided {
		line += fmt.Sprintf(" (undecided counts as %s)", g.Undecided)
	}
	if g.Message != "" {
		line += ": " + g.Message
	}
	fmt.Fprintln(w, line)
	writeMissed(w, f, g, st)
	if g.Outcome == analysis.Pass && !o.showPassing() {
		return
	}
	changes := causeChanges(g)
	causeWriteChecks(w, g, changes, o, st)
	// with nothing in focus there is no change to count or list
	if o.Quiet || f.missed(g) {
		return
	}
	causeWriteSummary(w, g, f, o, st)
	for i, c := range changes {
		fmt.Fprintln(w)
		causeWriteChange(w, g, i+1, c, o, st)
	}
	fmt.Fprintln(w)
}

// causeWriteChecks is the verdict block: a line per check, with its value and the changes behind
// it. Columns are as wide as every check needs, shown or not, so --details passing only adds lines.
func causeWriteChecks(w io.Writer, g Gate, changes []*causeChange, o Options, st styles) {
	cols := make([][4]string, len(g.Checks))
	var widths [4]int
	perSubject := true
	for i, c := range g.Checks {
		cols[i] = [4]string{stateWord[c.State], c.Name, params(c), span(c.Value)}
		for j, cell := range cols[i] {
			widths[j] = max(widths[j], len(cell))
		}
		perSubject = perSubject && c.Scope != analysis.PerGate
	}
	if len(g.Checks) == 0 {
		return
	}
	valueHead := "value"
	if perSubject {
		valueHead = "worst subject"
	}
	fmt.Fprintln(w, strings.Repeat(" ", 2+widths[0]+widths[1]+widths[2]+6)+st.dim(valueHead))
	// failing checks first, then undecided, then passing
	order := make([]int, len(g.Checks))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return g.Checks[order[a]].State.Rank() > g.Checks[order[b]].State.Rank()
	})
	for _, i := range order {
		c := g.Checks[i]
		if c.State == analysis.Pass && !o.showPassing() {
			continue
		}
		pad := func(j int) string { return strings.Repeat(" ", widths[j]-len(cols[i][j])+2) }
		line := "  " + st.state(c.State, cols[i][0]) + pad(0) + st.id(cols[i][1]) + pad(1) + cols[i][2] + pad(2) + cols[i][3] + pad(3) + causeNumbers(c, changes)
		if c.Message != "" {
			line += st.dim("; " + c.Message)
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
		for _, sc := range c.Subjects {
			if sc.Message != "" && sc.State != analysis.Pass {
				fmt.Fprintln(w, "    "+st.dim(subjectName(sc.Subject)+": "+sc.Message))
			}
		}
		if len(c.Unmet) > 0 && !o.Quiet {
			causeWriteUnmet(w, g, c, o, st)
		}
	}
	fmt.Fprintln(w)
}

// causeNumbers names the changes behind a check, e.g. "changes 1, 2".
func causeNumbers(c analysis.Check, changes []*causeChange) string {
	var nums []int
	for _, ch := range causeBehind(c, changes) {
		nums = append(nums, slices.Index(changes, ch)+1)
	}
	if len(nums) == 0 {
		return "no change"
	}
	slices.Sort(nums)
	s := make([]string, len(nums))
	for i, n := range nums {
		s[i] = fmt.Sprint(n)
	}
	return map[bool]string{true: "change ", false: "changes "}[len(nums) == 1] + strings.Join(s, ", ")
}

// causeWriteUnmet lists the expectations a per-gate check found unmet. They need no change between
// the setups, so they print under the check rather than under a change.
func causeWriteUnmet(w io.Writer, g Gate, c analysis.Check, o Options, st styles) {
	fmt.Fprintf(w, "    %d unmet\n", len(c.Unmet))
	if !o.showRows() {
		return
	}
	for _, x := range c.Unmet {
		line := fmt.Sprintf("      %s %s%s, %s", x.Verdict, st.id(x.Vulnerability), on(x.Package), subjectName(x.Subject))
		if miss := g.subject(x.Subject).missOn(x.Package, x.Vulnerability); miss != nil && x.Verdict == claimsv1.TP {
			line += "; " + st.undecided(causeSummary(*miss))
		}
		fmt.Fprintln(w, line)
	}
}

// causeWriteSummary counts the gate's matches, and with --details passing names the subjects
// nothing changed on. Under a focus it counts the rows in focus, and says so.
func causeWriteSummary(w io.Writer, g Gate, f *Focus, o Options, st styles) {
	total, dropped, added := 0, 0, 0
	var unchanged []string
	same := 0
	for _, sub := range g.Subjects {
		total += len(sub.Matches)
		changed := false
		for _, m := range sub.Matches {
			switch {
			case m.InReference && !m.InCandidate:
				dropped++
				changed = true
			case m.InCandidate && !m.InReference:
				added++
				changed = true
			}
		}
		if !changed {
			unchanged = append(unchanged, subjectName(sub.Name))
			same += len(sub.Matches)
		}
	}
	if len(g.Subjects) == 0 {
		return
	}
	inFocus := ""
	if f != nil {
		inFocus = " in focus"
	}
	if g.Header.OneSetup {
		fmt.Fprintf(w, "%s  %d matches, one setup scanned\n", st.id("what was reported"+inFocus), total)
	} else {
		fmt.Fprintf(w, "%s  %d of %d matches: %d dropped by the candidate, %d added\n", st.id("what changed"+inFocus), dropped+added, total, dropped, added)
	}
	// under a focus a subject with nothing in focus would read as unchanged
	if o.showPassing() && !g.Header.OneSetup && len(unchanged) > 0 && f == nil {
		fmt.Fprintf(w, "%s  %d subjects, %d matches, the same in both setups\n", st.pass("unchanged"), len(unchanged), same)
		for _, l := range causeWrap("  ", strings.Join(unchanged, ", ")) {
			fmt.Fprintln(w, st.dim(l))
		}
	}
}

func causeWriteChange(w io.Writer, g Gate, n int, c *causeChange, o Options, st styles) {
	verb := map[bool]string{true: "stopped reporting", false: "started reporting"}[c.dropped]
	if g.Header.OneSetup {
		// nothing is compared, so a change is only what the one setup reports
		verb = "reports"
	}
	matcher, matchType := c.matcher, c.matchType
	if matcher == "" {
		matcher = "a matcher"
	}
	if matchType == "" {
		matchType = "matches"
	}
	ms := c.matches()
	pkgs, vulns := 0, map[string]bool{}
	for _, s := range c.subjects {
		var ids []string
		for _, grp := range c.groups[s] {
			for _, id := range grp.pkgs {
				if !slices.Contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
		pkgs += len(ids)
	}
	var bases []string
	for _, m := range ms {
		vulns[m.Vulnerability] = true
		if b := strings.TrimPrefix(basePURL(m.Package), "pkg:"); !slices.Contains(bases, b) {
			bases = append(bases, b)
		}
	}
	// one package by name, or the one type they share, e.g. "golang/stdlib" or "rpm packages"
	what := "packages"
	types := map[string]bool{}
	for _, b := range bases {
		types[strings.SplitN(b, "/", 2)[0]] = true
	}
	switch {
	case len(bases) == 1:
		what = bases[0]
	case len(types) == 1:
		what = strings.SplitN(bases[0], "/", 2)[0] + " packages"
	}
	for i, l := range causeWrap("", fmt.Sprintf("%d %s %s %s on %s", n, matcher, verb, matchType, what)) {
		if i > 0 {
			l = "  " + l
		}
		fmt.Fprintln(w, st.id(l))
	}
	where := subjectName(c.subjects[0])
	if len(c.subjects) > 1 {
		where = fmt.Sprintf("%d subjects", len(c.subjects))
	}
	for _, l := range causeWrap("    ", fmt.Sprintf("%s, %s, %s, on %s", causeCount(len(ms), "match", "matches"), causeVulns(len(vulns), causeNoun(ms)), causeCount(pkgs, "package", "packages"), where)) {
		fmt.Fprintln(w, l)
	}
	indent := "    "
	for _, s := range c.subjects {
		if len(c.subjects) > 1 {
			fmt.Fprintln(w, "    "+st.id(subjectName(s)))
			indent = "      "
		}
		for _, grp := range c.groups[s] {
			causeWriteGroup(w, g, g.subject(s), grp, indent, o, st)
		}
	}
}

// causeWriteGroup is one direction's rows of a change on one subject: what they are, which checks
// they fail and why, what labeling one would do, and with --details rows each row.
func causeWriteGroup(w io.Writer, g Gate, sub *Subject, grp *group, indent string, o Options, st styles) {
	ms := grp.matches
	n := len(ms)
	head := map[string]string{Review: "review: %d unlabeled"}[grp.state]
	switch {
	case g.Header.OneSetup:
		head = "%d " + map[bool]string{true: stateUnlabeled, false: string(ms[0].Verdict)}[grp.state == Review]
	case head == "":
		verdict := ms[0].Verdict
		dropped := ms[0].InReference
		phrase := map[[2]bool]string{
			{true, true}: "now missed", {true, false}: "now found",
			{false, true}: "no longer reported", {false, false}: "newly reported",
		}[[2]bool{verdict == claimsv1.TP, dropped}]
		head = grp.state + ": %d " + string(verdict) + ", " + phrase
	}
	fmt.Fprintln(w, indent+st.state(directionState[grp.state], fmt.Sprintf(head, n)))

	inner := indent + "  "
	what := causeVulns(len(grp.vulns), causeNoun(ms))
	if len(grp.vulns) <= causeListed {
		what = strings.Join(grp.vulns, ", ")
	}
	for _, l := range causeWrap(inner, what+" on "+causePackages(ms)) {
		fmt.Fprintln(w, l)
	}

	if why := causeWhy(g, sub, ms, st); why != "" {
		fmt.Fprintln(w, inner+why)
	}
	// what labeling one row would do, stated once for the rows it is the same for
	var effects []string
	for _, m := range ms {
		if e := g.effect(sub.Name, m.ID); e != nil {
			effects = append(effects, causeEffect(g, e))
		}
	}
	for _, e := range causeDistinct(effects, "%d of them, %s") {
		for _, l := range causeWrap(inner, e) {
			fmt.Fprintln(w, st.dim(l))
		}
	}

	if !o.showRows() {
		return
	}
	for i, l := range rowLines(ms, inner, st) {
		fmt.Fprintln(w, l)
		if miss := sub.missFor(&ms[i]); miss != nil && len(miss.NearMiss) > 0 {
			fmt.Fprintln(w, causeLine(*miss, st))
		}
	}
}

// causeWhy names the checks some rows fail on their subject, and the causes of the tp labels
// they leave unpaired, e.g. "fails noNewFalseNegatives; NO CAUSE".
func causeWhy(g Gate, sub *Subject, ms []Match, st styles) string {
	var fails, causes, why []string
	for _, c := range g.Checks {
		for _, sc := range c.Subjects {
			if sc.Subject == sub.Name && sc.State == analysis.Fail && slices.ContainsFunc(ms, func(m Match) bool { return slices.Contains(sc.FailsOn, m.ID) }) {
				fails = append(fails, c.Name)
			}
		}
	}
	if len(fails) > 0 {
		why = append(why, st.fail("fails "+strings.Join(fails, ", ")))
	}
	for _, m := range ms {
		if miss := sub.missFor(&m); miss != nil && miss.InReference {
			causes = append(causes, causeSummary(*miss))
		}
	}
	for _, s := range causeDistinct(causes, "%d %s") {
		why = append(why, st.undecided(s))
	}
	return strings.Join(why, "; ")
}

// causeDistinct are the distinct items in the order first seen, each counted with format when
// there is more than one.
func causeDistinct(items []string, format string) []string {
	var out []string
	n := map[string]int{}
	for _, s := range items {
		if n[s] == 0 {
			out = append(out, s)
		}
		n[s]++
	}
	if len(out) > 1 {
		for i, s := range out {
			out[i] = fmt.Sprintf(format, n[s], s)
		}
	}
	return out
}

// causeEffect is what labeling one row does, e.g. "one labeled tp: f1NotWorse FAIL; fp: no
// change; the gate stays FAIL": each check whose state it changes, and the gate's outcome.
func causeEffect(g Gate, e *analysis.Effect) string {
	moved := func(v claimsv1.Verdict) string {
		var parts []string
		for _, c := range g.Checks {
			if s := e.States[v][c.Name]; s != c.State {
				parts = append(parts, c.Name+" "+stateWord[s])
			}
		}
		if len(parts) == 0 {
			return "no change"
		}
		return strings.Join(parts, ", ")
	}
	tp, fp := moved(claimsv1.TP), moved(claimsv1.FP)
	line := "one labeled tp: " + tp + "; fp: " + fp
	if tp == fp {
		line = "one labeled tp or fp: " + tp
	}
	switch out := e.Outcome[claimsv1.TP]; {
	case out != e.Outcome[claimsv1.FP]:
	case out == g.Outcome:
		line += "; the gate stays " + stateWord[out]
	default:
		line += "; the gate is " + stateWord[out] + " either way"
	}
	return line
}

// causePackages names the packages of some rows, e.g. "stdlib@1.16.9, stdlib@1.18.4 in 2 places":
// a package in several files is counted by its locations.
func causePackages(ms []Match) string {
	var names []string
	places := map[string]map[string]bool{}
	for _, m := range ms {
		n := shortPackage(m.Package)
		if places[n] == nil {
			names = append(names, n)
			places[n] = map[string]bool{}
		}
		places[n][pkgID(m)] = true
	}
	if len(names) > 3 {
		n := 0
		for _, p := range places {
			n += len(p)
		}
		return fmt.Sprintf("%d packages", n)
	}
	for i, n := range names {
		if k := len(places[n]); k > 1 {
			names[i] = fmt.Sprintf("%s in %d places", n, k)
		}
	}
	return strings.Join(names, ", ")
}

func causeNoun(ms []Match) [2]string {
	for _, m := range ms {
		if !strings.HasPrefix(m.Vulnerability, "CVE-") {
			return [2]string{"vulnerability", nounVulns}
		}
	}
	return [2]string{"CVE", nounCVEs}
}

func causeVulns(n int, noun [2]string) string { return causeCount(n, noun[0], noun[1]) }

func causeCount(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// causeWrap breaks text at spaces into lines of causeWidth columns, each starting with indent.
func causeWrap(indent, text string) []string {
	var out []string
	line := indent
	for _, word := range strings.Fields(text) {
		if line != indent && len(line)+1+len(word) > causeWidth {
			out = append(out, line)
			line = indent
		}
		if line != indent {
			line += " "
		}
		line += word
	}
	return append(out, line)
}
