package ui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
)

type state int

const (
	queued state = iota
	running
	done
	failed
	stopped
)

// cell is one setup's scan of one subject.
type cell struct {
	state      state
	matches    int
	err        error
	start, end time.Time
	// cached is a scan that finished by reusing a stored one: it never ran, so it has no elapsed time.
	cached bool
}

// row is one subject: where its SBOM came from, and a cell per setup.
type row struct {
	name  string
	sbom  string
	build *task // the SBOM build, while one runs
	cells map[string]*cell
}

type task struct {
	event.Task
	start, end time.Time
	done       bool
}

// gate is one gate's run. A gate with no name holds work published outside one (collect sboms).
type gate struct {
	name     string
	setups   []event.Setup
	resolved map[string]event.Setup
	rows     []*row
	tasks    []*task
	start    time.Time
	prepared time.Time // when the last setup was prepared
	scanned  time.Time // when the first scan started
	end      time.Time // when the last scan finished
}

func (g *gate) row(name string) *row {
	for _, r := range g.rows {
		if r.name == name {
			return r
		}
	}
	return nil
}

func (g *gate) cell(subject, setup string) *cell {
	if r := g.row(subject); r != nil {
		return r.cells[setup]
	}
	return nil
}

// cached is how many of the gate's scans reused a stored one.
func (g *gate) cached() int {
	n := 0
	for _, r := range g.rows {
		for _, c := range r.cells {
			if c.cached {
				n++
			}
		}
	}
	return n
}

// counts tallies the gate's scans by state.
func (g *gate) counts() (n [stopped + 1]int, total int) {
	for _, r := range g.rows {
		for _, c := range r.cells {
			n[c.state]++
			total++
		}
	}
	return n, total
}

type tickMsg struct{}

// settleMsg asks for the last frame: every gate summarized, then quit.
type settleMsg struct{}

const tickEvery = 100 * time.Millisecond

func tick() tea.Cmd {
	return tea.Tick(tickEvery, func(time.Time) tea.Msg { return tickMsg{} })
}

// model is the live view's state, built from bus events alone.
type model struct {
	gates         []*gate
	now           func() time.Time
	width, height int
	frame         int
	final         bool
	st            styles
}

func newModel(r *lipgloss.Renderer, now func() time.Time) *model {
	return &model{now: now, st: newStyles(r)}
}

func (m *model) Init() tea.Cmd { return tick() }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tickMsg:
		m.frame++
		return m, tick()
	case settleMsg:
		m.final = true
		return m, tea.Quit
	case partybus.Event:
		m.handle(msg)
	}
	return m, nil
}

// current is the gate events land in: the last one started, or a nameless one for work outside a gate.
func (m *model) current() *gate {
	if len(m.gates) == 0 {
		m.gates = append(m.gates, &gate{start: m.now(), resolved: map[string]event.Setup{}})
	}
	return m.gates[len(m.gates)-1]
}

// handle applies one bus event; an event whose value is not what its type carries is dropped.
func (m *model) handle(e partybus.Event) {
	now := m.now()
	switch e.Type {
	case event.GateStarted:
		if v, err := event.Parse[event.Gate](e); err == nil {
			m.gates = append(m.gates, newGate(v, now))
		}
	case event.SetupPrepared:
		if v, err := event.Parse[event.Setup](e); err == nil {
			g := m.current()
			g.resolved[v.Name], g.prepared = v, now
		}
	case event.TaskStarted, event.TaskFinished:
		if v, err := event.Parse[event.Task](e); err == nil {
			m.current().task(v, e.Type == event.TaskFinished, now)
		}
	case event.SBOMResolved:
		if v, err := event.Parse[event.SBOM](e); err == nil {
			if r := m.current().row(v.Subject); r != nil {
				r.sbom = v.From
			}
		}
	case event.ScanStarted, event.ScanFinished:
		if v, err := event.Parse[event.Scan](e); err == nil {
			m.current().scan(v, e.Type == event.ScanFinished, now)
		}
	}
}

func newGate(v event.Gate, now time.Time) *gate {
	g := &gate{name: v.Name, setups: v.Setups, resolved: map[string]event.Setup{}, start: now}
	for _, s := range v.Subjects {
		r := &row{name: s, cells: map[string]*cell{}}
		for _, su := range v.Setups {
			r.cells[su.Name] = &cell{}
		}
		g.rows = append(g.rows, r)
	}
	return g
}

func (g *gate) task(v event.Task, finished bool, now time.Time) {
	r := g.row(v.Name)
	if r != nil && v.Kind != event.BuildSBOM {
		r = nil
	}
	if !finished {
		t := &task{Task: v, start: now}
		g.tasks = append(g.tasks, t)
		if r != nil {
			r.build = t
		}
		return
	}
	for _, t := range g.tasks {
		if t.ID == v.ID {
			t.Err, t.end, t.done = v.Err, now, true
		}
	}
	if r != nil {
		r.build = nil
	}
}

func (g *gate) scan(v event.Scan, finished bool, now time.Time) {
	c := g.cell(v.Subject, v.Setup)
	switch {
	case c == nil:
		return
	case !finished:
		c.state, c.start = running, now
		if g.scanned.IsZero() {
			g.scanned = now
		}
		return
	case v.Cancelled:
		c.state = stopped
	case v.Err != nil:
		c.state = failed
	default:
		c.state = done
	}
	c.end, c.matches, c.err, c.cached = now, v.Matches, v.Err, v.Cached
	if n, total := g.counts(); n[done]+n[failed]+n[stopped] == total {
		g.end = now
	}
}
