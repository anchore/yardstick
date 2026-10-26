package ui

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
)

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const (
	cellWidth  = 15
	deltaWidth = 6
	// etaAfter is how many scans finish before an ETA is shown: fewer say little about the rest.
	etaAfter = 3
)

// styles carry meaning, never decoration: cyan runs, green is done, red failed, yellow differs.
type styles struct {
	bold, gate, dim, run, ok, bad, warn lipgloss.Style
}

func newStyles(r *lipgloss.Renderer) styles {
	fg := func(c string) lipgloss.Style { return r.NewStyle().Foreground(lipgloss.Color(c)) }
	return styles{
		bold: r.NewStyle().Bold(true),
		gate: r.NewStyle().Bold(true).Foreground(lipgloss.Color("5")),
		dim:  fg("8"),
		run:  fg("6"),
		ok:   fg("2"),
		bad:  fg("1"),
		warn: fg("3"),
	}
}

func (m *model) View() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	var lines []string
	for i, g := range m.gates {
		if m.final || i < len(m.gates)-1 {
			lines = append(lines, m.summary(g, w)...)
			continue
		}
		lines = append(lines, m.live(g, w)...)
	}
	if m.final {
		// bubbletea erases the line the cursor ends on; this keeps that line an empty one
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func (m *model) spin() string {
	return m.st.run.Render(spinner[m.frame%len(spinner)])
}

// live is a gate in progress: a title, what varies between its setups, its phases, and a row per
// subject with a cell per setup, over a progress bar.
func (m *model) live(g *gate, w int) []string {
	now := m.now()
	if g.name == "" {
		return m.loose(g, w)
	}
	elapsed := dur(now.Sub(g.start))
	title := m.st.bold.Render("yardstick") + m.st.dim.Render(" › ") + m.st.gate.Render(g.name)
	head := []string{
		title + "  " + m.st.dim.Render(elapsed),
		m.varies(g, w),
		m.phases(g),
	}
	preparing := len(g.resolved) < len(g.setups)
	nw := taskW(g.tasks, "    ", w)
	for _, t := range g.tasks {
		if preparing || !t.done || t.Err != nil {
			head = append(head, m.taskLines(t, "    ", nw, w)...)
		}
	}

	nameW := w - 2 - len(g.setups)*(cellWidth+2)
	if len(g.setups) == 2 {
		nameW -= deltaWidth
	}
	// no wider than the longest name, so the cells sit beside the names
	longest := 0
	for _, r := range g.rows {
		longest = max(longest, len([]rune(shortName(r.name))))
	}
	nameW = max(min(nameW, longest), 12)
	header := "  " + strings.Repeat(" ", nameW)
	for _, s := range g.setups {
		header += "  " + pad(s.Name, cellWidth)
	}
	if len(g.setups) == 2 {
		header += fmt.Sprintf("%*s", deltaWidth, "Δ")
	}
	head = append(head, m.st.dim.Render(header))

	// the bar spans the table, so its counts sit beside it rather than at the terminal's edge
	foot := append(m.failures(g, w), m.bar(g, lipgloss.Width(header)-2, w))

	rows := make([]string, len(g.rows))
	for i, r := range g.rows {
		rows[i] = m.row(g, r, nameW)
	}
	if m.height > 0 {
		rows = m.fit(g, rows, m.height-len(head)-len(foot)-1)
	}
	return append(append(head, rows...), foot...)
}

func (m *model) row(g *gate, r *row, nameW int) string {
	name := pad(shortName(r.name), nameW)
	if allQueued(r) {
		name = m.st.dim.Render(name)
	}
	line := "  " + name
	if r.build != nil {
		return line + "  " + m.spin() + m.st.run.Render(" building SBOM ") + m.st.dim.Render(dur(m.now().Sub(r.build.start)))
	}
	for _, s := range g.setups {
		line += "  " + m.cell(r.cells[s.Name])
	}
	if len(g.setups) == 2 {
		a, b := r.cells[g.setups[0].Name], r.cells[g.setups[1].Name]
		if a.state == done && b.state == done {
			d := a.matches - b.matches
			txt := fmt.Sprintf("%+*d", deltaWidth, d)
			if d == 0 {
				line += m.st.dim.Render(fmt.Sprintf("%*s", deltaWidth, "="))
			} else {
				line += m.st.warn.Render(txt)
			}
		}
	}
	return line
}

func allQueued(r *row) bool {
	for _, c := range r.cells {
		if c.state != queued {
			return false
		}
	}
	return true
}

// cell is one scan in cellWidth columns: its state, then its matches and how long it took.
func (m *model) cell(c *cell) string {
	switch c.state {
	case running:
		return m.spin() + " " + m.st.run.Render(pad(dur(m.now().Sub(c.start)), cellWidth-2))
	case done:
		if c.cached {
			return m.st.dim.Render("✔" + fmt.Sprintf(" %5d ", c.matches) + pad("cached", cellWidth-8))
		}
		return m.st.ok.Render("✔") + fmt.Sprintf(" %5d ", c.matches) + m.st.dim.Render(pad(dur(c.end.Sub(c.start)), cellWidth-8))
	case failed:
		return m.st.bad.Render(pad("✘ failed", cellWidth))
	case stopped:
		return m.st.warn.Render(pad("– stopped", cellWidth))
	}
	return m.st.dim.Render(pad("· queued", cellWidth))
}

// fit keeps rows within limit lines: subjects done with every setup collapse into one line first,
// then queued subjects past what fits collapse into a count.
func (m *model) fit(g *gate, rows []string, limit int) []string {
	if limit <= 0 || len(rows) <= limit {
		return rows
	}
	var out []string
	var active, waiting []int
	finished := 0
	for i, r := range g.rows {
		switch {
		case rowDone(r):
			finished++
		case allQueued(r):
			waiting = append(waiting, i)
		default:
			active = append(active, i)
		}
	}
	if finished > 0 {
		out = append(out, m.st.ok.Render("  ✔ ")+m.st.dim.Render(fmt.Sprintf("%d subjects scanned by every setup", finished)))
	}
	// running and failed subjects always show; queued ones fill what room is left, in order
	shown := len(waiting)
	if room := limit - len(out) - len(active); shown > room {
		shown = max(room-1, 0)
	}
	keep := append(slices.Clone(active), waiting[:shown]...)
	sort.Ints(keep)
	for _, i := range keep {
		out = append(out, rows[i])
	}
	if hidden := len(waiting) - shown; hidden > 0 {
		out = append(out, m.st.dim.Render(fmt.Sprintf("  · %d more queued", hidden)))
	}
	return out
}

func rowDone(r *row) bool {
	for _, c := range r.cells {
		if c.state != done {
			return false
		}
	}
	return true
}

// varies says what differs between the setups, and what they share.
func (m *model) varies(g *gate, w int) string {
	type field struct {
		label string
		value func(event.Setup, event.Setup) string
	}
	fields := []field{
		{"grype", func(s, r event.Setup) string { return grypeLabel(s.Grype, r.Grype) }},
		{"DB", func(s, r event.Setup) string { return dbLabel(s.DB, r.DB) }},
		{"config", func(s, _ event.Setup) string { return base(s.Config) }},
		{"env", func(s, _ event.Setup) string { return s.Env }},
	}
	var differ, same []string
	for _, f := range fields {
		var vals []string
		for _, s := range g.setups {
			vals = append(vals, f.value(s, g.resolved[s.Name]))
		}
		switch {
		case len(vals) > 1 && vals[0] != vals[1]:
			for i, v := range vals {
				if v == "" {
					vals[i] = "none"
				}
			}
			differ = append(differ, f.label+" "+strings.Join(vals, " vs "))
		case vals[0] != "":
			same = append(same, f.label+" "+vals[0])
		}
	}
	if len(g.setups) == 1 {
		return m.st.dim.Render(cut("  "+g.setups[0].Name+": "+strings.Join(same, " · "), w))
	}
	line := "  " + strings.Join(differ, " · ")
	if len(differ) == 0 {
		line = "  no difference"
	}
	out := m.st.bold.Render(cut(line, w))
	if len(same) > 0 && lipgloss.Width(line) < w-8 {
		out += m.st.dim.Render(cut("   same "+strings.Join(same, " · "), w-lipgloss.Width(line)))
	}
	return out
}

// phases is the run's three phases: preparing the setups, finding SBOMs, scanning.
func (m *model) phases(g *gate) string {
	var setup string
	switch {
	case anyFailed(g.tasks, event.Install, event.ResolveDB, event.ImportDB):
		setup = m.st.bad.Render("✘")
	case len(g.resolved) == len(g.setups):
		setup = m.st.ok.Render("✔") + m.st.dim.Render(" "+dur(g.prepared.Sub(g.start)))
	default:
		setup = m.spin()
	}

	from := map[string]int{}
	for _, r := range g.rows {
		if r.sbom != "" {
			from[r.sbom]++
		}
	}
	found := 0
	var kinds []string
	for _, k := range []string{"source", "cache", "built", "file"} {
		if from[k] > 0 {
			found += from[k]
			label := k
			if k == "source" {
				label = "claims"
			}
			kinds = append(kinds, fmt.Sprintf("%d %s", from[k], label))
		}
	}
	var sboms string
	switch {
	case anyFailed(g.tasks, event.BuildSBOM):
		sboms = m.st.bad.Render("✘") + fmt.Sprintf(" %d/%d", found, len(g.rows))
	case found == len(g.rows):
		sboms = m.st.ok.Render("✔") + fmt.Sprintf(" %d", found) + m.st.dim.Render(" ("+strings.Join(kinds, ", ")+")")
	case len(g.resolved) == len(g.setups):
		sboms = m.spin() + fmt.Sprintf(" %d/%d", found, len(g.rows))
	default:
		sboms = m.st.dim.Render(fmt.Sprintf("· %d/%d", found, len(g.rows)))
	}

	n, total := g.counts()
	var scans string
	switch {
	case n[failed] > 0:
		scans = m.st.bad.Render("✘") + fmt.Sprintf(" %d failed", n[failed])
	case n[done] == total:
		scans = m.st.ok.Render("✔") + fmt.Sprintf(" %d", total) + m.st.dim.Render(cachedNote(g.cached(), " (%d cached)"))
	case n[running] > 0:
		scans = m.spin() + fmt.Sprintf(" %d/%d", n[done], total)
	default:
		scans = m.st.dim.Render(fmt.Sprintf("· 0/%d", total))
	}
	label := m.st.dim.Render
	// setup padded to its widest, "✔ 1m02s", so the phases after it hold still as it settles
	setup += strings.Repeat(" ", max(7-lipgloss.Width(setup), 0))
	return "  " + label("setup ") + setup + label("   SBOMs ") + sboms + label("   scans ") + scans
}

func anyFailed(tasks []*task, kinds ...event.TaskKind) bool {
	for _, t := range tasks {
		for _, k := range kinds {
			if t.Kind == k && t.Err != nil {
				return true
			}
		}
	}
	return false
}

var checksum = regexp.MustCompile(`sha256[:-]([0-9a-f]{7})[0-9a-f]*`)

// taskName says a finished task's kind in the past tense: "downloaded claims", not "download claims".
func taskName(t *task) string {
	name := t.Name
	if t.Kind == event.BuildSBOM {
		name = shortName(name)
	}
	kind := string(t.Kind)
	if t.done && t.Err == nil {
		kind = t.Kind.Done()
	}
	return strings.TrimSpace(kind + " " + checksum.ReplaceAllString(name, "$1"))
}

// taskW is the width task names pad to, so their times sit in one column just past the longest name
// rather than across the terminal from it.
func taskW(tasks []*task, indent string, w int) int {
	n := 0
	for _, t := range tasks {
		// measured finished, so a time doesn't shift right when its task's verb turns past tense
		n = max(n, len([]rune(taskName(&task{Task: t.Task, done: true}))))
	}
	return max(min(n, w-len(indent)-10), 1)
}

// loose is work outside a gate: its tasks flush left, lined up with the result lines a command
// prints under them.
func (m *model) loose(g *gate, w int) []string {
	nw := taskW(g.tasks, "", w)
	var lines []string
	for _, t := range g.tasks {
		lines = append(lines, m.taskLines(t, "", nw, w)...)
	}
	return lines
}

// taskLines is a task's line and its details as a tree under it.
func (m *model) taskLines(t *task, indent string, nw, w int) []string {
	lines := []string{m.taskLine(t, indent, nw, w)}
	for _, d := range Tree(t.Details) {
		lines = append(lines, m.st.dim.Render(cut(indent+"  "+d, w)))
	}
	return lines
}

// Tree draws lines as branches of the line above them.
func Tree(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		branch := "├ "
		if i == len(lines)-1 {
			branch = "└ "
		}
		out[i] = branch + l
	}
	return out
}

func (m *model) taskLine(t *task, indent string, nw, w int) string {
	name := taskName(t)
	switch {
	case !t.done:
		return indent + m.spin() + " " + pad(cut(name, nw), nw+2) + m.st.dim.Render(dur(m.now().Sub(t.start)))
	case t.Err != nil:
		return m.st.bad.Render(indent+"✘ ") + cut(name+": "+brief(t.Err), w-len(indent)-2)
	}
	return m.st.ok.Render(indent+"✔ ") + pad(cut(name, nw), nw+2) + m.st.dim.Render(dur(t.end.Sub(t.start)))
}

// bar is the gate's progress: done, failed and running scans as shares of every scan, then counts
// and an ETA from the rate scans have finished at so far.
func (m *model) bar(g *gate, span, w int) string {
	n, total := g.counts()
	finished := n[done] + n[failed] + n[stopped]
	stats := fmt.Sprintf(" %d/%d", finished, total)
	if n[running] > 0 {
		stats += fmt.Sprintf(" · %d running", n[running])
	}
	if n[queued] > 0 {
		stats += fmt.Sprintf(" · %d queued", n[queued])
	}
	if eta, ok := m.eta(g, finished, total); ok {
		stats += " · eta " + eta
	}
	width := max(min(span, w-2-len([]rune(stats))), 10)
	if total == 0 {
		return "  " + m.st.dim.Render(strings.Repeat("─", width)) + stats
	}
	// cumulative, so rounding never leaves a finished run's bar short
	seg := func(k int) int { return k * width / total }
	ok := seg(n[done])
	bad := seg(finished) - ok
	run := seg(finished+n[running]) - ok - bad
	rest := width - ok - bad - run
	return "  " + m.st.ok.Render(strings.Repeat("━", ok)) + m.st.bad.Render(strings.Repeat("━", bad)) +
		m.st.run.Render(strings.Repeat("─", run)) + m.st.dim.Render(strings.Repeat("─", rest)) + stats
}

// eta is judged on the scans that ran: a reused one finishes at once and says nothing about the rest.
func (m *model) eta(g *gate, finished, total int) (string, bool) {
	ran := finished - g.cached()
	if ran < etaAfter || finished == total || g.scanned.IsZero() {
		return "", false
	}
	elapsed := m.now().Sub(g.scanned)
	left := time.Duration(float64(elapsed) / float64(ran) * float64(total-finished))
	if left < time.Minute {
		return fmt.Sprintf("~%ds", int(left.Round(time.Second).Seconds())), true
	}
	return "~" + dur(left.Round(time.Second)), true
}

// summary is a gate in one line, with any failure under it: how every gate reads once settled,
// and an earlier gate once the next starts.
func (m *model) summary(g *gate, w int) []string {
	if g.name == "" {
		return m.loose(g, w)
	}
	n, total := g.counts()
	end := g.end
	if end.IsZero() {
		end = m.now()
	}
	took := dur(end.Sub(g.start))
	var line string
	switch {
	case n[failed] > 0:
		line = m.st.bad.Render("✘ ") + m.st.gate.Render(g.name) + fmt.Sprintf("  %d of %d scans failed after %s", n[failed], total, took)
	case n[done] < total:
		line = m.st.warn.Render("– ") + m.st.gate.Render(g.name) + fmt.Sprintf("  stopped after %d of %d scans, %s", n[done], total, took)
	default:
		var per []string
		for _, s := range g.setups {
			sum := 0
			for _, r := range g.rows {
				sum += r.cells[s.Name].matches
			}
			per = append(per, fmt.Sprintf("%s %d", s.Name, sum))
		}
		// no check mark: whether the gate passed is the report's to say
		line = m.st.gate.Render(g.name) + m.st.ok.Render(fmt.Sprintf("  scanned %d in %s", total, took)) +
			m.st.dim.Render(cachedNote(g.cached(), " (%d cached)")+" · "+strings.Join(per, " · ")+" matches")
	}
	lines := []string{line}
	for _, t := range g.tasks {
		if t.Err != nil {
			lines = append(lines, m.taskLines(t, "    ", 0, w)...)
		}
	}
	return append(lines, m.failures(g, w)...)
}

// failures is a line per failed scan: the subject, the setup, and the error's telling line.
func (m *model) failures(g *gate, w int) []string {
	var lines []string
	for _, r := range g.rows {
		for _, s := range g.setups {
			if c := r.cells[s.Name]; c.state == failed {
				lines = append(lines, m.st.bad.Render("  ✘ ")+cut(shortName(r.name)+" · "+s.Name+": "+brief(c.err), w-4))
			}
		}
	}
	return lines
}

// dur is a duration at the precision worth reading: tenths under ten seconds, then seconds.
func dur(d time.Duration) string {
	switch {
	case d < 10*time.Second:
		return fmt.Sprintf("%.1fs", d.Seconds())
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}

var digest = regexp.MustCompile(`@sha256:([0-9a-f]{7})[0-9a-f]*`)

// shortName is an image subject's name without its scheme, registry, or all but seven characters of
// its digest: the report names it in full.
func shortName(s string) string {
	if strings.HasPrefix(s, "sbom:") {
		return filepath.Base(s)
	}
	s, ok := strings.CutPrefix(s, "oci:")
	if !ok {
		return s
	}
	if host, rest, ok := strings.Cut(s, "/"); ok && strings.ContainsAny(host, ".:") {
		s = rest
	}
	s = strings.TrimPrefix(s, "library/")
	return digest.ReplaceAllString(s, "@$1")
}

func grypeLabel(written, resolved string) string {
	s := written
	if resolved != "" {
		s = resolved
	}
	if strings.ContainsRune(s, filepath.Separator) {
		return filepath.Base(s)
	}
	return strings.TrimPrefix(s, "grype@")
}

func dbLabel(written, checksum string) string {
	s := base(strings.TrimPrefix(written, "dir:"))
	if _, sum, ok := strings.Cut(checksum, ":"); ok && len(sum) >= 7 {
		s += " " + sum[:7]
	}
	return s
}

func base(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

// brief is an error's most telling line: a tool's failure ends with its own stderr, so the last
// non-empty line.
func brief(err error) string {
	lines := strings.Split(strings.TrimSpace(err.Error()), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// trunc cuts plain text to n columns, keeping its end: the end of a name or path tells them apart.
func trunc(s string, n int) string {
	r := []rune(s)
	if n <= 0 {
		return ""
	}
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-n+1:])
}

// cut cuts plain text to n columns, keeping its start.
func cut(s string, n int) string {
	r := []rune(s)
	if n <= 0 {
		return ""
	}
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// pad truncates plain text to n columns and fills it out to them.
func pad(s string, n int) string {
	s = trunc(s, n)
	return s + strings.Repeat(" ", max(n-len([]rune(s)), 0))
}

// cachedNote is format filled with n, or nothing when no scan was reused.
func cachedNote(n int, format string) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(format, n)
}
