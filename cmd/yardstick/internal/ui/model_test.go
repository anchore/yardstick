package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
)

// clock is a fake time the model reads; advance moves it.
type clock struct{ t time.Time }

func (c *clock) now() time.Time                  { return c.t }
func (c *clock) advance(d time.Duration)         { c.t = c.t.Add(d) }
func newClock() *clock                           { return &clock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)} }
func send(m *model, t partybus.EventType, v any) { m.Update(partybus.Event{Type: t, Value: v}) }

// a renderer over a buffer has no colors, so a view snapshots as plain text
func testModel(c *clock, w, h int) *model {
	m := newModel(lipgloss.NewRenderer(&bytes.Buffer{}), c.now)
	m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return m
}

var setups = []event.Setup{
	{Name: "candidate", Grype: "grype@latest", DB: "latest"},
	{Name: "reference", Grype: "grype@v0.100.0", DB: "latest"},
}

func startGate(m *model, name string, subjects ...string) {
	send(m, event.GateStarted, event.Gate{Name: name, Setups: setups, Subjects: subjects})
}

func prepare(m *model, c *clock) {
	send(m, event.TaskStarted, event.Task{ID: 1, Kind: event.Install, Name: "grype@latest"})
	c.advance(300 * time.Millisecond)
	send(m, event.TaskFinished, event.Task{ID: 1, Kind: event.Install, Name: "grype@latest"})
	send(m, event.SetupPrepared, event.Setup{Name: "candidate", Grype: "grype@v0.120.1", DB: "sha256:2f1597f25b5089e9"})
	send(m, event.SetupPrepared, event.Setup{Name: "reference", Grype: "grype@v0.100.0", DB: "sha256:2f1597f25b5089e9"})
}

func scan(m *model, c *clock, subject, setup string, d time.Duration, matches int, err error) {
	send(m, event.ScanStarted, event.Scan{Subject: subject, Setup: setup})
	c.advance(d)
	send(m, event.ScanFinished, event.Scan{Subject: subject, Setup: setup, Matches: matches, Err: err})
}

// a reused scan finishes without having started
func cachedScan(m *model, subject, setup string, matches int) {
	send(m, event.ScanFinished, event.Scan{Subject: subject, Setup: setup, Matches: matches, Cached: true})
}

const (
	wolfi  = "oci:cgr.dev/chainguard/wolfi-base@sha256:be3834598c3c4b76ace6a866edcbbe1fa18086f9ee238b57769e4d230cd7d507"
	alpine = "oci:docker.io/library/alpine@sha256:ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9"
	deb    = "deb"
)

// an interactive run shows every scan's state live plus overall progress
func TestScanStatesAndProgress(t *testing.T) {
	c := newClock()
	m := testModel(c, 80, 40)
	startGate(m, "grype-upgrade", wolfi, alpine, deb)

	// preparing: the install is running, every scan queued
	send(m, event.TaskStarted, event.Task{ID: 1, Kind: event.Install, Name: "grype@latest"})
	c.advance(1500 * time.Millisecond)
	t.Run("preparing", func(t *testing.T) { snaps.MatchSnapshot(t, m.View()) })

	send(m, event.TaskFinished, event.Task{ID: 1, Kind: event.Install, Name: "grype@latest"})
	send(m, event.TaskStarted, event.Task{ID: 3, Kind: event.ImportDB, Name: "sha256-2f1597f25b5089e966272b251eb4d1f9977e59d57029af1c8810deb6e5321aa2"})
	c.advance(20 * time.Second)
	t.Run("importing a DB", func(t *testing.T) { snaps.MatchSnapshot(t, m.View()) })
	send(m, event.TaskFinished, event.Task{ID: 3, Kind: event.ImportDB})
	send(m, event.SetupPrepared, event.Setup{Name: "candidate", Grype: "grype@v0.120.1", DB: "sha256:2f1597f25b5089e9"})
	send(m, event.SetupPrepared, event.Setup{Name: "reference", Grype: "grype@v0.100.0", DB: "sha256:2f1597f25b5089e9"})
	send(m, event.SBOMResolved, event.SBOM{Subject: wolfi, From: "source"})
	send(m, event.SBOMResolved, event.SBOM{Subject: alpine, From: "source"})
	send(m, event.TaskStarted, event.Task{ID: 2, Kind: event.BuildSBOM, Name: deb})
	c.advance(4 * time.Second)
	t.Run("building an SBOM", func(t *testing.T) { snaps.MatchSnapshot(t, m.View()) })
	if m.current().row(deb).build == nil {
		t.Error("expected the deb row to show its SBOM building")
	}
	send(m, event.TaskFinished, event.Task{ID: 2, Kind: event.BuildSBOM, Name: deb})
	send(m, event.SBOMResolved, event.SBOM{Subject: deb, From: "built"})

	scan(m, c, wolfi, "candidate", 2*time.Second, 95, nil)
	scan(m, c, wolfi, "reference", 2*time.Second, 97, nil)
	scan(m, c, alpine, "candidate", time.Second, 4, nil)
	send(m, event.ScanStarted, event.Scan{Subject: alpine, Setup: "reference"})
	send(m, event.ScanStarted, event.Scan{Subject: deb, Setup: "candidate"})
	c.advance(1200 * time.Millisecond)

	g := m.current()
	n, total := g.counts()
	if n[done] != 3 || n[running] != 2 || n[queued] != 1 || total != 6 {
		t.Errorf("expected 3 done, 2 running and 1 queued of 6, got %v of %d", n, total)
	}
	if c := g.cell(wolfi, "reference"); c.matches != 97 || c.end.Sub(c.start) != 2*time.Second {
		t.Errorf("expected the wolfi reference scan to hold 97 matches over 2s, got %+v", c)
	}
	t.Run("scanning", func(t *testing.T) { snaps.MatchSnapshot(t, m.View()) })

	send(m, event.ScanFinished, event.Scan{Subject: alpine, Setup: "reference", Matches: 4})
	send(m, event.ScanFinished, event.Scan{Subject: deb, Setup: "candidate", Err: errors.New("grype sbom:x -o json: exit status 1\nfailed to load vulnerability db: no such file")})
	send(m, event.ScanStarted, event.Scan{Subject: deb, Setup: "reference"})
	send(m, event.ScanFinished, event.Scan{Subject: deb, Setup: "reference", Err: context.Canceled, Cancelled: true})
	if s := g.cell(deb, "candidate").state; s != failed {
		t.Errorf("expected the deb candidate scan failed, got %v", s)
	}
	if s := g.cell(deb, "reference").state; s != stopped {
		t.Errorf("expected the deb reference scan stopped, got %v", s)
	}
	if g.end.IsZero() {
		t.Error("expected the gate ended once every scan finished")
	}
	t.Run("a failed scan", func(t *testing.T) { snaps.MatchSnapshot(t, m.View()) })

	// settling quits and leaves a summary for the report to follow
	if _, cmd := m.Update(settleMsg{}); cmd == nil || cmd() != tea.Quit() {
		t.Error("expected settling to quit")
	}
	t.Run("settled", func(t *testing.T) { snaps.MatchSnapshot(t, m.View()) })
}

// the ETA waits for enough finished scans, then extrapolates their rate
func TestETA(t *testing.T) {
	c := newClock()
	m := testModel(c, 80, 40)
	var subjects []string
	for i := range 5 {
		subjects = append(subjects, fmt.Sprintf("s%d", i))
	}
	startGate(m, "g", subjects...)
	prepare(m, c)
	scan(m, c, "s0", "candidate", 10*time.Second, 1, nil)
	scan(m, c, "s0", "reference", 10*time.Second, 1, nil)
	g := m.current()
	if _, ok := m.eta(g, 2, 10); ok {
		t.Error("expected no ETA after two scans")
	}
	scan(m, c, "s1", "candidate", 10*time.Second, 1, nil)
	scan(m, c, "s1", "reference", 10*time.Second, 1, nil)
	// 4 scans in 40s, 6 left
	if eta, ok := m.eta(g, 4, 10); !ok || eta != "~1m00s" {
		t.Errorf("expected an ETA of ~1m00s, got %q", eta)
	}
}

// 28 scans and more stay readable in a short terminal: subjects every setup scanned collapse first,
// then the queued ones past what fits
func TestRowsCollapseToFit(t *testing.T) {
	c := newClock()
	m := testModel(c, 80, 13)
	var subjects []string
	for i := range 14 {
		subjects = append(subjects, fmt.Sprintf("oci:docker.io/anchore/test_images@sha256:%07d%057d", i, 0))
	}
	startGate(m, "grype-upgrade", subjects...)
	prepare(m, c)
	for _, s := range subjects {
		send(m, event.SBOMResolved, event.SBOM{Subject: s, From: "source"})
	}
	for _, s := range subjects[:6] {
		scan(m, c, s, "candidate", time.Second, 10, nil)
		scan(m, c, s, "reference", time.Second, 12, nil)
	}
	for _, s := range subjects[6:8] {
		send(m, event.ScanStarted, event.Scan{Subject: s, Setup: "candidate"})
		send(m, event.ScanStarted, event.Scan{Subject: s, Setup: "reference"})
	}
	view := m.View()
	if lines := bytes.Count([]byte(view), []byte("\n")) + 1; lines > 13 {
		t.Errorf("expected the view within 13 lines, got %d:\n%s", lines, view)
	}
	snaps.MatchSnapshot(t, view)
}

// several gates in one invocation: each earlier gate is a line, the current one is drawn in full
func TestGatesInOneRun(t *testing.T) {
	c := newClock()
	m := testModel(c, 80, 40)
	startGate(m, "os-packages", alpine)
	prepare(m, c)
	scan(m, c, alpine, "candidate", time.Second, 4, nil)
	scan(m, c, alpine, "reference", time.Second, 5, nil)
	startGate(m, "grype-upgrade", wolfi)
	prepare(m, c)
	send(m, event.ScanStarted, event.Scan{Subject: wolfi, Setup: "candidate"})
	c.advance(time.Second)
	t.Run("live", func(t *testing.T) { snaps.MatchSnapshot(t, m.View()) })
	m.Update(settleMsg{})
	t.Run("settled", func(t *testing.T) { snaps.MatchSnapshot(t, m.View()) })
}

// work published outside a gate (yardstick collect sboms) is drawn as a list of tasks
func TestTasksOutsideAGate(t *testing.T) {
	c := newClock()
	m := testModel(c, 80, 40)
	send(m, event.TaskStarted, event.Task{ID: 1, Kind: event.Install, Name: "syft@v1.54.1"})
	c.advance(time.Second)
	snaps.MatchSnapshot(t, m.View())

	// a download names what it fetched as a tree under its line, running and done
	details := []string{"github.com/anchore/match-claims@main", "commit 3206431b5f6c0d1e2a7b8c9d0e1f2a3b4c5d6e7f",
		"sha256:af82f6a8c1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8"}
	send(m, event.TaskStarted, event.Task{ID: 2, Kind: event.DownloadClaims, Details: details})
	c.advance(time.Second)
	t.Run("downloading", func(t *testing.T) { snaps.MatchSnapshot(t, m.View()) })
	send(m, event.TaskFinished, event.Task{ID: 2, Kind: event.DownloadClaims})
	t.Run("downloaded", func(t *testing.T) { snaps.MatchSnapshot(t, m.View()) })
}

func TestShortName(t *testing.T) {
	for in, want := range map[string]string{
		wolfi:  "chainguard/wolfi-base@be38345",
		alpine: "alpine@ddac200",
		"oci:docker.io/anchore/test_images@sha256:10008791acbc5866de04108746a02a0c4029ce3a4400a9b3dad45d7f2245f9da": "anchore/test_images@1000879",
		"oci:localhost:5000/app:1.0@sha256:10008791acbc5866de04108746a02a0c4029ce3a4400a9b3dad45d7f2245f9da":        "app:1.0@1000879",
		"sbom:/tmp/fixtures/deb.syft.json": "deb.syft.json",
		"deb":                              "deb",
	} {
		if got := shortName(in); got != want {
			t.Errorf("shortName(%q) = %q, want %q", in, got, want)
		}
	}
}

// reused-scans-are-reported, a partly cached run: reused scans show as cached with no elapsed time,
// and the scans that ran keep theirs
func TestReusedScansShowAsCached(t *testing.T) {
	c := newClock()
	m := testModel(c, 80, 40)
	startGate(m, "grype-upgrade", wolfi, alpine, deb)
	prepare(m, c)
	for _, s := range []string{wolfi, alpine} {
		cachedScan(m, s, "candidate", 12)
		cachedScan(m, s, "reference", 14)
	}
	send(m, event.ScanStarted, event.Scan{Subject: deb, Setup: "candidate"})
	c.advance(2 * time.Second)
	t.Run("one still running", func(t *testing.T) {
		view := m.View()
		if got := strings.Count(view, "cached"); got != 4 {
			t.Errorf("expected four scans shown as cached, got %d in:\n%s", got, view)
		}
		snaps.MatchSnapshot(t, view)
	})

	send(m, event.ScanFinished, event.Scan{Subject: deb, Setup: "candidate", Matches: 3})
	scan(m, c, deb, "reference", 3*time.Second, 4, nil)
	t.Run("done", func(t *testing.T) {
		view := m.View()
		if !strings.Contains(view, "4 cached") {
			t.Errorf("expected the scans line to count four cached, got:\n%s", view)
		}
		snaps.MatchSnapshot(t, view)
	})
	m.Update(settleMsg{})
	t.Run("settled", func(t *testing.T) { snaps.MatchSnapshot(t, m.View()) })
}
