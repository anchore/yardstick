package report

import (
	"io"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
)

// Colorable says whether a report written to w is colored. NO_COLOR turns color off, and
// FORCE_COLOR or CLICOLOR_FORCE turn it on. Otherwise a terminal is colored, and so is a GitHub
// Actions log, which renders ANSI color though stdout is a pipe there. Other pipes stay plain.
func Colorable(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	switch {
	case !ok || os.Getenv("NO_COLOR") != "":
		return false
	case forced("FORCE_COLOR") || forced("CLICOLOR_FORCE") || os.Getenv("GITHUB_ACTIONS") == "true":
		return true
	}
	return term.IsTerminal(int(f.Fd()))
}

func forced(env string) bool {
	v := os.Getenv(env)
	return v != "" && v != "0" && v != "false"
}

type paint func(string) string

// styles carry meaning, as the live view's do: green passes, red fails, yellow is undecided, ids
// are bold and what only explains them is faint.
type styles struct {
	pass, fail, undecided, id, dim, head paint
}

func newStyles(color bool) styles {
	if !color {
		plain := func(s string) string { return s }
		return styles{plain, plain, plain, plain, plain, plain}
	}
	r := lipgloss.NewRenderer(io.Discard)
	r.SetColorProfile(termenv.ANSI)
	fg := func(c string) lipgloss.Style { return r.NewStyle().Foreground(lipgloss.Color(c)) }
	p := func(s lipgloss.Style) paint { return func(t string) string { return s.Render(t) } }
	return styles{
		pass:      p(fg("2")),
		fail:      p(fg("1").Bold(true)),
		undecided: p(fg("3")),
		id:        p(r.NewStyle().Bold(true)),
		dim:       p(r.NewStyle().Faint(true)),
		head:      p(r.NewStyle().Bold(true)),
	}
}

// state paints text in the color of a state.
func (st styles) state(s analysis.State, text string) string {
	switch s {
	case analysis.Pass:
		return st.pass(text)
	case analysis.Fail:
		return st.fail(text)
	}
	return st.undecided(text)
}
