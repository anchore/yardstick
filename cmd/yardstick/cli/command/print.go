package command

import (
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
)

// printer writes a command's result the way the gate report does: a line per thing acted on,
// led by a mark saying how it went, with columns lined up across lines. Color carries meaning
// only (green done, red failed, yellow worth a look, faint detail) and only on a terminal.
type printer struct {
	w                        io.Writer
	ok, bad, warn, dim, bold func(string) string
	rows                     [][]string
}

func newPrinter(w io.Writer) *printer {
	plain := func(s string) string { return s }
	p := &printer{w: w, ok: plain, bad: plain, warn: plain, dim: plain, bold: plain}
	if !report.Colorable(w) {
		return p
	}
	r := lipgloss.NewRenderer(io.Discard)
	r.SetColorProfile(termenv.ANSI)
	paint := func(s lipgloss.Style) func(string) string { return func(t string) string { return s.Render(t) } }
	fg := func(c string) lipgloss.Style { return r.NewStyle().Foreground(lipgloss.Color(c)) }
	p.ok, p.bad, p.warn = paint(fg("2")), paint(fg("1")), paint(fg("3"))
	p.dim, p.bold = paint(r.NewStyle().Faint(true)), paint(r.NewStyle().Bold(true))
	return p
}

// the marks a result line leads with
func (p *printer) done() string    { return p.ok("✔") }
func (p *printer) failed() string  { return p.bad("✘") }
func (p *printer) notice() string  { return p.warn("!") }
func (p *printer) skipped() string { return p.dim("·") }

// row queues a line of cells, which may already be painted.
func (p *printer) row(cells ...string) {
	p.rows = append(p.rows, cells)
}

// flush writes the queued rows with each column as wide as its widest visible cell.
func (p *printer) flush() error {
	var widths []int
	for _, r := range p.rows {
		for i, c := range r {
			if i == len(widths) {
				widths = append(widths, 0)
			}
			widths[i] = max(widths[i], lipgloss.Width(c))
		}
	}
	var b strings.Builder
	for _, r := range p.rows {
		var line strings.Builder
		for i, c := range r {
			line.WriteString(c)
			if i < len(r)-1 {
				// a mark sits one space from what it marks, as in the live view
				gap := 2
				if i == 0 && widths[0] <= 1 {
					gap = 1
				}
				line.WriteString(strings.Repeat(" ", widths[i]-lipgloss.Width(c)+gap))
			}
		}
		b.WriteString(strings.TrimRight(line.String(), " ") + "\n")
	}
	p.rows = nil
	_, err := io.WriteString(p.w, b.String())
	return err
}
