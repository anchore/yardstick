package report

import (
	"io"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
)

// Colorable says whether a report written to w is colored: w is a terminal and NO_COLOR is unset.
// Files and pipes stay plain.
func Colorable(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	return ok && os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(f.Fd()))
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
