package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
)

// Formats are the renderers, the first the default. It is the one list -o is validated and
// described from. cause, check and subject are three layouts of the same report: what changed,
// each check in turn, and each subject in turn.
var Formats = []string{"cause", "check", "subject", "table", "json"}

// Options select how a verdict set is shown; none of them changes it.
type Options struct {
	Format string
	// Details adds to the default output: DetailsPassing the passing checks and their values,
	// DetailsRows also the rows behind them.
	Details string
	// Quiet prints only failing and undecided gates and their checks, and the summary line.
	Quiet bool
	// Color styles every format but json for a terminal. WriteOutputs sets it only for stdout.
	Color bool
}

// the Details levels, in increasing order. Empty is the default output.
const (
	DetailsPassing = "passing"
	DetailsRows    = "rows"
)

// DetailsLevels are the values --details takes, the one list it is validated and described from.
var DetailsLevels = []string{DetailsPassing, DetailsRows}

// CheckDetails refuses a details level that does not exist.
func CheckDetails(d string) error {
	if d == "" {
		return nil
	}
	return checkOneOf("details", d, DetailsLevels)
}

// checkOneOf refuses a value outside the list, naming every value in it.
func checkOneOf(flag, v string, valid []string) error {
	for _, ok := range valid {
		if v == ok {
			return nil
		}
	}
	return fmt.Errorf("unknown %s %q: use one of %s", flag, v, strings.Join(valid, ", "))
}

func (o Options) showPassing() bool { return o.Details != "" }
func (o Options) showRows() bool    { return o.Details == DetailsRows }

// CheckFormat refuses a renderer that does not exist, naming the valid ones.
func CheckFormat(f string) error { return checkOneOf("output", f, Formats) }

// Render writes the set. It changes no state, count or code in it; it only strips control
// characters from its text (stripControls), so every format shows the same text.
func Render(w io.Writer, s Set, o Options) error {
	stripControls(reflect.ValueOf(&s).Elem())
	switch o.Format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(s)
	case "table":
		return table(w, s, o)
	case "cause":
		return byCause(w, s, o)
	case "check":
		return byCheck(w, s, o)
	case "subject":
		return bySubject(w, s, o)
	}
	return CheckFormat(o.Format)
}

func table(w io.Writer, s Set, o Options) error {
	st := newStyles(o.Color)
	if !o.Quiet {
		for _, g := range s.Gates {
			writeHeader(w, g, st)
		}
		writeFocus(w, s.Focus, st)
	}
	gates := append([]Gate(nil), s.Gates...)
	sort.SliceStable(gates, func(i, j int) bool { return gates[i].Name < gates[j].Name })
	rows := [][]string{{"GATE", "CHECK", "SUBJECT", "STATE", "WORST", "BEST", "THRESHOLD", "NOTE"}}
	var states []analysis.State
	add := func(state analysis.State, cells ...string) {
		rows = append(rows, cells)
		states = append(states, state)
	}
	for _, g := range gates {
		if len(g.Checks) == 0 {
			add(g.Outcome, g.Name, "-", "-", string(g.Outcome), "", "", "", g.Message)
		}
		for _, c := range g.Checks {
			if len(c.Subjects) == 0 {
				add(c.State, g.Name, c.Name, "-", string(c.State), num(c.Value.Worst), num(c.Value.Best), num(c.Threshold), c.Message)
				continue
			}
			subjects := append([]analysis.SubjectCheck(nil), c.Subjects...)
			sort.SliceStable(subjects, func(i, j int) bool { return shortSubject(subjects[i].Subject) < shortSubject(subjects[j].Subject) })
			for _, sc := range subjects {
				add(sc.State, g.Name, c.Name, shortSubject(sc.Subject), string(sc.State), num(sc.Value.Worst), num(sc.Value.Best), num(c.Threshold), sc.Message)
			}
		}
	}
	// columns are padded before they are styled, so escape codes never count toward a width
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, cell := range r {
			widths[i] = max(widths[i], utf8.RuneCountInString(cell))
		}
	}
	for n, r := range rows {
		line := ""
		for i, cell := range r {
			pad := ""
			if i < len(r)-1 {
				pad = strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell)+2)
			}
			switch {
			case n == 0:
				cell = st.head(cell)
			case i == 3:
				cell = st.state(states[n-1], cell)
			}
			line += cell + pad
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
	_, err := fmt.Fprintln(w, summaryLine(s.Summary, st))
	return err
}

// stripControls removes control characters but tab and newline from every string the set holds,
// in place: package and vulnerability text from SBOMs, scans and claims sources, remote ones too,
// could otherwise move a terminal's cursor or restyle what a report shows. Only exported fields
// are walked, which json renders, so there is no cycle to follow.
func stripControls(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			stripControls(v.Elem())
		}
	case reflect.Interface:
		if !v.IsNil() && v.CanSet() {
			e := reflect.New(v.Elem().Type()).Elem()
			e.Set(v.Elem())
			stripControls(e)
			v.Set(e)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if f := v.Field(i); f.CanSet() {
				stripControls(f)
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := range v.Len() {
			stripControls(v.Index(i))
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			e := reflect.New(v.Type().Elem()).Elem()
			e.Set(v.MapIndex(k))
			stripControls(e)
			v.SetMapIndex(k, e)
		}
	case reflect.String:
		if v.CanSet() && strings.ContainsFunc(v.String(), control) {
			v.SetString(strings.Map(func(r rune) rune {
				if control(r) {
					return -1
				}
				return r
			}, v.String()))
		}
	}
}

func control(r rune) bool {
	return unicode.IsControl(r) && r != '\t' && r != '\n'
}

// shortSubject is how the table names a subject pinned by digest: its repository's last path
// element and the digest's first 12 hex characters, which still identify it and keep a row inside a
// terminal. json names it whole.
func shortSubject(subject string) string {
	repo, digest, ok := strings.Cut(subject, "@sha256:")
	if !ok || len(digest) <= 12 {
		return subject
	}
	return path.Base(repo) + "@sha256:" + digest[:12]
}

// byGate is what the cause and subject layouts share: each gate's header and the focus, then
// each gate through writeGate, and the summary line.
func byGate(w io.Writer, s Set, o Options, writeGate func(io.Writer, Gate, *Focus, Options, styles)) error {
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
		writeGate(w, g, s.Focus, o, st)
	}
	_, err := fmt.Fprintln(w, summaryLine(s.Summary, st))
	return err
}
