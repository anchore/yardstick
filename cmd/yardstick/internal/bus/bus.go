// Package bus publishes what a run is doing for the UI to draw. Without a bus set (tests, or a
// command clio runs with none) every helper does nothing. Nothing in a run subscribes to it.
package bus

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
)

var publisher partybus.Publisher

func Set(p partybus.Publisher) {
	publisher = p
}

func Publish(t partybus.EventType, v any) {
	if publisher != nil {
		publisher.Publish(partybus.Event{Type: t, Value: v})
	}
}

// GateStarted announces a gate before any of it is prepared: its setups as written and its subjects.
func GateStarted(g *gatefile.Gate) {
	e := event.Gate{Name: g.Name, Setups: []event.Setup{setup("candidate", g.Candidate)}}
	if g.Reference != nil {
		e.Setups = append(e.Setups, setup("reference", g.Reference))
	}
	for _, s := range g.Subjects {
		e.Subjects = append(e.Subjects, s.Name)
	}
	Publish(event.GateStarted, e)
}

func setup(name string, s *gatefile.Setup) event.Setup {
	env := make([]string, 0, len(s.Env))
	for k, v := range s.Env {
		env = append(env, k+"="+v)
	}
	sort.Strings(env)
	return event.Setup{Name: name, Grype: s.Grype, DB: s.DB, Config: s.Config, Env: strings.Join(env, " ")}
}

// SetupPrepared says what a setup resolved to: the grype installed and the DB it scans with.
func SetupPrepared(name, grype, db string) {
	Publish(event.SetupPrepared, event.Setup{Name: name, Grype: grype, DB: db})
}

var taskID atomic.Uint64

// Task is a started piece of preparation; Done finishes it.
type Task struct {
	t event.Task
}

func StartTask(kind event.TaskKind, format string, args ...any) *Task {
	return StartDetailedTask(kind, fmt.Sprintf(format, args...), nil)
}

// StartDetailedTask starts a task with lines a UI draws under it.
func StartDetailedTask(kind event.TaskKind, name string, details []string) *Task {
	t := &Task{t: event.Task{ID: taskID.Add(1), Kind: kind, Name: name, Details: details}}
	Publish(event.TaskStarted, t.t)
	return t
}

// Done finishes the task; a nil task, one never started, does nothing.
func (t *Task) Done(err error) {
	if t == nil {
		return
	}
	done := t.t
	done.Err = err
	Publish(event.TaskFinished, done)
}

func SBOMResolved(subject, from string) {
	Publish(event.SBOMResolved, event.SBOM{Subject: subject, From: from})
}

func ScanStarted(subject, setup string) {
	Publish(event.ScanStarted, event.Scan{Subject: subject, Setup: setup})
}

// ScanFinished reports a scan's match count, or its error. A scan failing once ctx is done was
// stopped, not broken.
func ScanFinished(ctx context.Context, subject, setup string, matches int, err error) {
	Publish(event.ScanFinished, event.Scan{Subject: subject, Setup: setup, Matches: matches, Err: err, Cancelled: err != nil && ctx.Err() != nil})
}

// ScanReused reports a scan whose stored output was used instead of running grype. It is a
// finish with no start, since nothing ran.
func ScanReused(subject, setup string, matches int) {
	Publish(event.ScanFinished, event.Scan{Subject: subject, Setup: setup, Matches: matches, Cached: true})
}
