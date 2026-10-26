package report

// what every text layout shares: the headers, the verdict and summary lines, row groups and the
// lookups behind them. A layout keeps anything only it uses in its own file.

import (
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// the words the layouts share for an unlabeled group and for what a group of vulnerabilities is called
const (
	stateUnlabeled = "unlabeled"
	nounCVEs       = "CVEs"
	nounVulns      = "vulnerabilities"
)

func summaryLine(s Summary, st styles) string {
	if s.Failed > 0 {
		return st.fail(s.Line)
	}
	return st.pass(s.Line)
}

// num shows a value to two decimals, or to three significant digits when that would round a
// non-zero value to 0, so a failing F1 drop of 0.0005 never prints as 0; the json renderer keeps
// it whole.
func num(v float64) string {
	if v != 0 && math.Abs(v) < 0.005 {
		return strconv.FormatFloat(v, 'g', 3, 64)
	}
	return strconv.FormatFloat(math.Round(v*100)/100, 'f', -1, 64)
}

// writeHeader states what a gate's run compared, faint but for the gate's name, what varied, and
// anything worth a second look.
func writeHeader(w io.Writer, g Gate, st styles) {
	fmt.Fprintln(w, "gate "+st.id(g.Name)+st.dim(fmt.Sprintf(" (%s), scanned %s", g.Path, g.Header.Scanned)))
	h := g.Header
	for _, name := range []string{gatefile.Candidate, gatefile.Reference} {
		if in, ok := h.Setups[name]; ok {
			fmt.Fprintln(w, st.dim(fmt.Sprintf("  %s: %s, DB %s, config %s, env %s", name, in.Grype, in.DB, in.Config, in.Env)))
		}
	}
	switch {
	case h.OneSetup:
		fmt.Fprintln(w, "  one setup scanned: the candidate alone, so nothing is compared")
	case len(h.Varied) > 0:
		var parts []string
		for _, v := range h.Varied {
			parts = append(parts, fmt.Sprintf("%s (%s -> %s)", st.id(v.Input), v.Reference, v.Candidate))
		}
		fmt.Fprintln(w, "  varied: "+strings.Join(parts, ", ")+st.dim("; held: "+orNone(h.Held)))
	}
	if h.Attribution != "" {
		fmt.Fprintf(w, "  %s\n", st.undecided(h.Attribution))
	}
	for _, c := range h.Claims {
		line := fmt.Sprintf("  claims: %s at %s", c.Locator, c.Snapshot)
		if c.Commit != "" {
			line += ", commit " + c.Commit
		}
		fmt.Fprintln(w, st.dim(line))
	}
	if h.Bypassed {
		fmt.Fprintln(w, "  corpus SBOMs bypassed (--rebuild-sboms)")
	}
	for _, b := range h.Built {
		fmt.Fprintln(w, st.dim(fmt.Sprintf("  built: the SBOM of %s, with syft %s", b.Subject, b.Syft)))
	}
	for _, f := range h.Frozen {
		fmt.Fprintf(w, "  frozen: %s can no longer be pulled; its SBOM from a claims source was scanned\n", f)
	}
	if len(h.InheritedEnv) > 0 {
		fmt.Fprintf(w, "  inherited env: %s\n", strings.Join(h.InheritedEnv, ", "))
	}
	for _, warn := range g.Warnings {
		fmt.Fprintf(w, "  %s %s\n", st.undecided("warning:"), warn)
	}
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "nothing"
	}
	return strings.Join(s, ", ")
}

var stateWord = map[analysis.State]string{analysis.Pass: "PASS", analysis.Fail: "FAIL", analysis.Undecided: "UNDECIDED"}

// params are a check's parameters, e.g. "max 0".
func params(c analysis.Check) string {
	var ps []string
	for k, v := range c.Params {
		ps = append(ps, k+" "+num(v))
	}
	sort.Strings(ps)
	return strings.Join(ps, ", ")
}

// groupKey is what a summary line groups rows by.
type groupKey struct {
	state, delta, pkg, matchType, cause, effect string
}

func matchKey(m Match, relative bool) groupKey {
	k := groupKey{state: stateUnlabeled, pkg: basePURL(m.Package), matchType: m.MatchType}
	if m.Label != nil {
		k.state = "labeled " + string(m.Label.Verdict)
	}
	if relative && m.InCandidate != m.InReference {
		k.delta = map[bool]string{true: "added by the candidate", false: "dropped by the candidate"}[m.InCandidate]
	}
	return k
}

func causeSummary(m Miss) string {
	if m.Where == "" {
		return m.Cause
	}
	return m.Cause + ", look at " + m.Where
}

// group is the rows sharing a key: how many, their distinct vulnerabilities and packages, and
// every row's lines for --details rows.
type group struct {
	groupKey
	rows  int
	vulns []string
	pkgs  []string
	// named is the first row's package without its qualifiers, for a group of one package
	named string
	lines []string
	// matches are the group's match rows, for a layout that prints more of them than lines has
	matches []Match
}

// groups keep the order their keys are first seen in, which is the rows' order.
type groups []*group

func (gs *groups) add(k groupKey, vuln, pkgID, pkg string, lines ...string) *group {
	var g *group
	for _, have := range *gs {
		if have.groupKey == k {
			g = have
			break
		}
	}
	if g == nil {
		g = &group{groupKey: k, named: strings.SplitN(pkg, "?", 2)[0]}
		*gs = append(*gs, g)
	}
	g.rows++
	if !slices.Contains(g.vulns, vuln) {
		g.vulns = append(g.vulns, vuln)
	}
	if !slices.Contains(g.pkgs, pkgID) {
		g.pkgs = append(g.pkgs, pkgID)
	}
	g.lines = append(g.lines, lines...)
	return g
}

// addMatch adds a match row to the group of its key.
func (gs *groups) addMatch(k groupKey, m Match, lines ...string) {
	g := gs.add(k, m.Vulnerability, pkgID(m), m.Package, lines...)
	g.matches = append(g.matches, m)
}

// listed is how many vulnerabilities a summary names before "+N more".
const listed = 3

// pkgID is the package id a match id starts with. It tells apart two packages with one purl, such
// as the same stdlib in two binaries.
func pkgID(m Match) string {
	id, _, _ := strings.Cut(m.ID, "/")
	return id
}

// basePURL is a package without its version and qualifiers: what rows on one package at
// several versions share.
func basePURL(p string) string {
	p = strings.SplitN(p, "?", 2)[0]
	return strings.SplitN(p, "@", 2)[0]
}

func on(pkg string) string {
	if pkg == "" {
		return ""
	}
	return " on " + pkg
}

// direction colors say whether a delta helps the candidate
var directionState = map[string]analysis.State{Fixed: analysis.Pass, Introduced: analysis.Fail, Review: analysis.Undecided}

func causeLine(m Miss, st styles) string {
	line := "          " + st.undecided(m.Cause)
	for _, r := range m.NearMiss {
		line += fmt.Sprintf(": without %s it pairs %s (%s)", r.Field, r.Package, r.Match)
	}
	if m.Where != "" {
		line += "; look at " + m.Where
	}
	return line
}

func (g Gate) subject(name string) *Subject {
	for i := range g.Subjects {
		if g.Subjects[i].Name == name {
			return &g.Subjects[i]
		}
	}
	return &Subject{}
}

func (g Gate) effect(subject, id string) *analysis.Effect {
	for i, e := range g.Effects {
		if e.Subject == subject && e.Match == id {
			return &g.Effects[i]
		}
	}
	return nil
}

func (s *Subject) match(id string) *Match {
	for i := range s.Matches {
		if s.Matches[i].ID == id {
			return &s.Matches[i]
		}
	}
	return nil
}

// missFor is the candidate's miss of the label deciding a match, when there is one.
func (s *Subject) missFor(m *Match) *Miss {
	if m.Label == nil {
		return nil
	}
	return s.missOn(m.Label.Package, m.Label.Vulnerability)
}

func (s *Subject) missOn(pkg, vuln string) *Miss {
	for i, miss := range s.Misses {
		if miss.Label.Package == pkg && miss.Label.Vulnerability == vuln {
			return &s.Misses[i]
		}
	}
	return nil
}

// writeRunHeader is the layouts' header: the gate and its file, what varied and what was held,
// each claims source's snapshot, and anything worth a second look, one labeled line each, e.g.
//
//	grype-upgrade  config/gates/grype-upgrade.yaml, scanned 2026-10-15 15:26Z
//	  varied   grype  v0.100.0 (reference) -> v0.120.1 (candidate)
//	  held     DB 2f1597f25b50, config none, env none
//	  claims   ./claims at 71b8ca1211c7
func writeRunHeader(w io.Writer, g Gate, st styles) {
	h := g.Header
	fmt.Fprintln(w, st.id(g.Name)+"  "+st.dim(g.Path+", scanned "+scanned(h.Scanned)))
	// a label prints on the first of its lines only, padded before it is styled
	lines := func(label string, paint paint, texts ...string) {
		for i, t := range texts {
			if i > 0 {
				label = ""
			}
			fmt.Fprintf(w, "  %s%s\n", paint(fmt.Sprintf("%-9s", label)), t)
		}
	}
	plain := func(s string) string { return s }
	cand := h.Setups[gatefile.Candidate]
	switch {
	case h.OneSetup:
		lines("setup", plain, "one setup scanned, so nothing is compared: "+fmt.Sprintf("grype %s, DB %s, config %s, env %s",
			shortInput(cand.Grype), shortInput(cand.DB), cand.Config, cand.Env))
	case len(h.Varied) > 0:
		var varied []string
		for _, v := range h.Varied {
			varied = append(varied, fmt.Sprintf("%s  %s (reference) -> %s (candidate)", st.id(v.Input), shortInput(v.Reference), shortInput(v.Candidate)))
		}
		lines("varied", plain, varied...)
		held := map[string]string{"grype": cand.Grype, "DB": cand.DB, "config": cand.Config, "env": cand.Env}
		var parts []string
		for _, name := range h.Held {
			parts = append(parts, name+" "+shortInput(held[name]))
		}
		lines("held", st.dim, st.dim(orNone(parts)))
	}
	if h.Attribution != "" {
		lines("", plain, st.undecided(h.Attribution))
	}
	var sources []string
	for _, c := range h.Claims {
		s := c.Locator + " at " + shortInput(c.Snapshot)
		if c.Commit != "" {
			s += ", commit " + c.Commit
		}
		sources = append(sources, st.dim(s))
	}
	lines("claims", st.dim, sources...)
	if h.Bypassed {
		lines("sboms", plain, "corpus SBOMs bypassed (--rebuild-sboms)")
	}
	var built []string
	for _, b := range h.Built {
		built = append(built, st.dim(subjectName(b.Subject)+" with syft "+b.Syft))
	}
	lines("built", st.dim, built...)
	var frozen []string
	for _, f := range h.Frozen {
		frozen = append(frozen, subjectName(f)+" can no longer be pulled; its SBOM from a claims source was scanned")
	}
	lines("frozen", plain, frozen...)
	if len(h.InheritedEnv) > 0 {
		lines("env", plain, "inherited "+strings.Join(h.InheritedEnv, ", "))
	}
	for _, warn := range g.Warnings {
		lines("warning", st.undecided, warn)
	}
}

// scanned is a run's time to the minute, e.g. "2026-10-15 15:26Z".
func scanned(t string) string {
	at, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return t
	}
	return at.UTC().Format("2006-01-02 15:04Z")
}

// shortInput is a header value as the layouts print it: a grype version without its name, and a
// digest cut to 12 hex characters.
func shortInput(v string) string {
	v = strings.TrimPrefix(v, "grype@")
	if hex, ok := strings.CutPrefix(v, "sha256:"); ok && len(hex) > 12 {
		return hex[:12]
	}
	return v
}

// subjectName is how the layouts name a subject: no scheme, no registry host, and a digest cut to
// 12 hex characters, e.g.
// "anchore/test-images/grype-quality-golang:d89207b@7536ee345532". json names it whole.
func subjectName(name string) string {
	name = strings.TrimPrefix(name, string(ref.Image)+":")
	// the first path element is a registry host when it has a dot or a port, or is localhost
	if host, rest, ok := strings.Cut(name, "/"); ok && (strings.ContainsAny(host, ".:") || host == "localhost") {
		name = rest
	}
	if repo, digest, ok := strings.Cut(name, "@sha256:"); ok && len(digest) > 12 {
		name = repo + "@" + digest[:12]
	}
	return name
}

// span is a value as the layouts print it, best case first: "3..73" reads 3 for certain, 73 at
// most.
func span(v analysis.Value) string {
	return num(v.Best) + ".." + num(v.Worst)
}

// tally counts a gate's checks by state, failing first, e.g. "1 check fails, 2 undecided, 1
// passes".
func tally(g Gate) string {
	verbs := map[analysis.State][2]string{analysis.Fail: {"fails", "fail"}, analysis.Undecided: {"undecided", "undecided"}, analysis.Pass: {"passes", "pass"}}
	n := map[analysis.State]int{}
	for _, c := range g.Checks {
		n[c.State]++
	}
	var parts []string
	for _, s := range []analysis.State{analysis.Fail, analysis.Undecided, analysis.Pass} {
		if n[s] == 0 {
			continue
		}
		noun := ""
		if len(parts) == 0 {
			noun = map[bool]string{true: " check", false: " checks"}[n[s] == 1]
		}
		parts = append(parts, fmt.Sprintf("%d%s %s", n[s], noun, verbs[s][min(n[s], 2)-1]))
	}
	return strings.Join(parts, ", ")
}

// shortPackage is a package purl as a row prints it: its name and version, e.g. "stdlib@1.18.4".
// The row's location tells apart two packages it leaves the same.
func shortPackage(p string) string {
	p = strings.SplitN(p, "?", 2)[0]
	return p[strings.LastIndex(p, "/")+1:]
}

// rowLines are match rows in aligned columns, each line starting with indent: the vulnerability,
// the package and, faint, its location.
func rowLines(ms []Match, indent string, st styles) []string {
	var wv, wp int
	for _, m := range ms {
		wv = max(wv, utf8.RuneCountInString(m.Vulnerability))
		wp = max(wp, utf8.RuneCountInString(shortPackage(m.Package)))
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		pkg := shortPackage(m.Package)
		line := indent + st.id(m.Vulnerability) + strings.Repeat(" ", wv-utf8.RuneCountInString(m.Vulnerability)+3) + pkg
		if m.Location != "" {
			line += strings.Repeat(" ", wp-utf8.RuneCountInString(pkg)+3) + st.dim(m.Location)
		}
		out = append(out, line)
	}
	return out
}
