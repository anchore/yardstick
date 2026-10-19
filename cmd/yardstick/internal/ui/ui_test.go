package ui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/bus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
)

// with -v (or -q), or with stderr redirected, nothing is drawn
func TestEnabled(t *testing.T) {
	t.Setenv("NO_TTY", "")
	for _, tc := range []struct {
		name     string
		cfg      *clio.LoggingConfig
		terminal bool
		want     bool
	}{
		{"interactive", &clio.LoggingConfig{}, true, true},
		{"-v", &clio.LoggingConfig{Verbosity: 1}, true, false},
		{"-vv", &clio.LoggingConfig{Verbosity: 2}, true, false},
		{"-q", &clio.LoggingConfig{Quiet: true}, true, false},
		{"stderr redirected", &clio.LoggingConfig{}, false, false},
		{"no logging config", nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Enabled(tc.cfg, tc.terminal); got != tc.want {
				t.Errorf("expected %v, got %v", tc.want, got)
			}
		})
	}
	t.Setenv("NO_TTY", "1")
	if Enabled(&clio.LoggingConfig{}, true) {
		t.Error("expected NO_TTY=1 to draw nothing")
	}
}

// loop stands in for clio's event loop: one goroutine handing every event to the UI in order
type loop chan partybus.Event

func (l loop) Publish(e partybus.Event) { l <- e }

// a write to stdout waits for the UI's last frame, so the report follows it rather than landing in it
func TestStdoutWaitsForTheLastFrame(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	u := &UI{out: f}
	u.selected.Store(true)
	events := make(loop, 16)
	go func() {
		for e := range events {
			_ = u.Handle(e)
		}
	}()
	bus.Set(events)
	t.Cleanup(func() { bus.Set(nil); close(events) })

	bus.Publish(event.GateStarted, event.Gate{Name: "g", Setups: setups[:1], Subjects: []string{"s"}})
	bus.ScanStarted("s", "candidate")
	bus.ScanFinished(t.Context(), "s", "candidate", 7, nil)

	var report bytes.Buffer
	if _, err := u.Stdout(&report).Write([]byte("the report\n")); err != nil {
		t.Fatal(err)
	}
	if !u.settled.Load() {
		t.Fatal("expected the UI settled before the report was written")
	}
	select {
	case <-u.exited:
	default:
		t.Fatal("expected the UI stopped drawing before the report was written")
	}
	drawn, _ := os.ReadFile(f.Name())
	if !strings.Contains(string(drawn), "scanned 1 in") {
		t.Errorf("expected the last frame to summarize the gate with its scan finished, got %q", drawn)
	}
	if report.String() != "the report\n" {
		t.Errorf("expected the report written whole, got %q", report.String())
	}
}

// an empty write settles the UI, which is how file outputs wait for the last frame too
func TestEmptyStdoutWriteSettles(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	u := &UI{out: f}
	u.selected.Store(true)
	events := make(loop, 16)
	go func() {
		for e := range events {
			_ = u.Handle(e)
		}
	}()
	bus.Set(events)
	t.Cleanup(func() { bus.Set(nil); close(events) })

	bus.Publish(event.GateStarted, event.Gate{Name: "g", Setups: setups[:1], Subjects: []string{"s"}})
	var out bytes.Buffer
	if _, err := u.Stdout(&out).Write(nil); err != nil {
		t.Fatal(err)
	}
	if !u.settled.Load() || out.Len() != 0 {
		t.Errorf("expected the UI settled and nothing written, settled=%v out=%q", u.settled.Load(), out.String())
	}
}

// a command that publishes nothing, or a run with no UI, writes straight through
func TestStdoutWithoutTheUI(t *testing.T) {
	var out bytes.Buffer
	u := New()
	if _, err := u.Stdout(&out).Write([]byte("x")); err != nil || out.String() != "x" {
		t.Errorf("expected a direct write, got %q, %v", out.String(), err)
	}
}
