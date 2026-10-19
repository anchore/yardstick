// Package ui draws a run's progress on stderr while it runs: each gate's setups, SBOMs and scans,
// from the events the bus carries. It draws only for an interactive run, starts on the first event
// (so a command publishing none draws nothing), and settles to a summary before anything is
// written to stdout.
package ui

import (
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wagoodman/go-partybus"
	"golang.org/x/term"

	"github.com/anchore/clio"
	"github.com/anchore/go-logger"
	"github.com/anchore/yardstick/cmd/yardstick/internal/bus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

var _ clio.UI = (*UI)(nil)

// UI is clio's UI for an interactive run. clio calls Setup, Handle and Teardown from its one event
// loop, so only selected and settled are read elsewhere.
type UI struct {
	out      *os.File
	program  *tea.Program
	exited   chan struct{}
	selected atomic.Bool
	settled  atomic.Bool
}

func New() *UI {
	return &UI{out: os.Stderr}
}

// Select is clio's UI constructor: this UI when stderr is a terminal and logs are not asked for,
// else none, and logs go to stderr as they are written.
func (u *UI) Select(cfg clio.Config) (*clio.UICollection, error) {
	if !Enabled(cfg.Log, term.IsTerminal(int(u.out.Fd()))) {
		return clio.NewUICollection(), nil
	}
	u.selected.Store(true)
	return clio.NewUICollection(u), nil
}

// Enabled is whether a run draws: stderr is a terminal, and neither -v nor -q was given.
func Enabled(cfg *clio.LoggingConfig, stderrIsTerminal bool) bool {
	switch strings.ToLower(os.Getenv("NO_TTY")) {
	case "1", "true":
		return false
	}
	return stderrIsTerminal && cfg != nil && cfg.Verbosity == 0 && !cfg.Quiet
}

func (u *UI) Setup(partybus.Unsubscribable) error {
	return nil
}

func (u *UI) Handle(e partybus.Event) error {
	switch {
	case e.Type == event.Settle:
		u.settle()
		if done, ok := e.Value.(chan struct{}); ok {
			close(done)
		}
	case event.Ours(e.Type) && !u.settled.Load():
		if u.program == nil {
			u.start()
		}
		u.program.Send(e)
	}
	return nil
}

func (u *UI) Teardown(bool) error {
	u.settle()
	return nil
}

func (u *UI) start() {
	u.program = tea.NewProgram(newModel(lipgloss.NewRenderer(u.out), time.Now),
		// no input: the terminal stays cooked, so ctrl+c is a signal clio already handles
		tea.WithOutput(u.out), tea.WithInput(nil), tea.WithoutSignalHandler())
	u.exited = make(chan struct{})
	// log lines print above the frame rather than through it
	if c, ok := log.Get().(logger.Controller); ok {
		c.SetOutput(printer{u.program})
	}
	go func() {
		defer close(u.exited)
		_, _ = u.program.Run()
	}()
}

// settle draws the last frame and stops drawing; later events are dropped.
func (u *UI) settle() {
	if u.settled.Swap(true) || u.program == nil {
		return
	}
	u.program.Send(settleMsg{})
	select {
	case <-u.exited:
	case <-time.After(time.Second):
		u.program.Quit()
		<-u.exited
	}
	if c, ok := log.Get().(logger.Controller); ok {
		c.SetOutput(u.out)
	}
}

// Stdout is w, written to only once the UI has settled, so a report never lands inside a frame.
func (u *UI) Stdout(w io.Writer) io.Writer {
	return stdout{u: u, w: w}
}

type stdout struct {
	u *UI
	w io.Writer
}

func (s stdout) Write(p []byte) (int, error) {
	if s.u.selected.Load() && !s.u.settled.Load() {
		// the settle event queues behind every event published before it, so the last frame has them
		done := make(chan struct{})
		bus.Publish(event.Settle, done)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
	return s.w.Write(p)
}

// Fd is the wrapped writer's file descriptor, so a report can tell whether it goes to a terminal.
func (s stdout) Fd() uintptr {
	if f, ok := s.w.(interface{ Fd() uintptr }); ok {
		return f.Fd()
	}
	return ^uintptr(0)
}

type printer struct {
	p *tea.Program
}

func (w printer) Write(b []byte) (int, error) {
	w.p.Send(tea.Println(strings.TrimRight(string(b), "\n"))())
	return len(b), nil
}
