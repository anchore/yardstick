//go:build unix

package research

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// childCommand starts a background loop that touches a heartbeat file, and waits for it: what an
// agent CLI started by sh looks like. Its heartbeat stopping shows the whole group was stopped (this
// works where signalling a grandchild to probe it isn't allowed).
// The loop ends on its own after about 10s, so a failing test can't leave it running.
const childCommand = `(i=0; while [ $i -lt 200 ]; do touch "$YARDSTICK_ROOT/beat-$YARDSTICK_ROW"; sleep 0.05; i=$((i+1)); done) & wait`

// canSignalGrandchildren is false where a process may signal only its direct children (some
// sandboxes, e.g. a coding agent's): there a group signal can't reach sh's children at all, so the
// tests check that the job says so, instead of that the children stopped.
func canSignalGrandchildren(t *testing.T) bool {
	t.Helper()
	cmd := exec.Command("sh", "-c", `sleep 2 & echo $!; wait`)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	var pid int
	if _, err := fmt.Fscan(out, &pid); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Logf("this environment doesn't let a process signal its grandchildren (%v); expecting the job to report survivors", err)
		return false
	}
	return true
}

func beat(store, row string) (time.Time, bool) {
	fi, err := os.Stat(filepath.Join(store, "beat-"+row))
	if err != nil {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

func waitForChild(t *testing.T, store, row string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, ok := beat(store, row); ok {
			return
		}
	}
	t.Fatal("the command never started its child")
}

func assertChildStopped(t *testing.T, store, row string) {
	t.Helper()
	time.Sleep(200 * time.Millisecond) // let a last touch in flight land
	before, _ := beat(store, row)
	time.Sleep(500 * time.Millisecond)
	if after, _ := beat(store, row); !after.Equal(before) {
		t.Errorf("the child of %s kept running after the job ended", row)
	}
}

// assertSurvivorsReported checks the job says whether its processes may still be running: not when
// the group could be stopped, and with the command to stop them when it couldn't.
func assertSurvivorsReported(t *testing.T, j Job, groupStopped bool) {
	t.Helper()
	warned := j.SurvivingGroup != 0 || strings.Contains(j.Error, "may still be running")
	switch {
	case groupStopped && warned:
		t.Errorf("expected a clean stop, got a survivors warning: %+v", j)
	case !groupStopped && (j.SurvivingGroup == 0 || !strings.Contains(j.Error, KillCommand(j.SurvivingGroup))):
		t.Errorf("expected the job to say its children may still be running, with the command to stop them, got %+v", j)
	}
}

func status(t *testing.T, r *Runner, id string) Job {
	t.Helper()
	j, err := r.load(id)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestCancelStopsTheWholeProcessGroup(t *testing.T) {
	group := canSignalGrandchildren(t)
	r, store := newRunner(t, childCommand, time.Minute)
	if _, err := r.Start(context.Background(), Request{Rows: []string{"c1"}}); err != nil {
		t.Fatal(err)
	}
	waitForChild(t, store, "c1")
	if !r.Cancellable("c1") {
		t.Fatal("expected a live job to be cancellable")
	}
	if err := r.Cancel("c1"); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if group {
		assertChildStopped(t, store, "c1")
	}
	j := status(t, r, "c1")
	if j.Status != Cancelled || j.Finished.IsZero() {
		t.Errorf("expected the job to be recorded as cancelled, got %+v", j)
	}
	assertSurvivorsReported(t, j, group)
	if r.Cancellable("c1") {
		t.Error("expected a finished job not to be cancellable")
	}
	if err := r.Cancel("c1"); err == nil || !strings.Contains(err.Error(), "not running in this process") {
		t.Errorf("expected cancelling a job that isn't live to fail, got %v", err)
	}
}

func TestTimeoutStopsTheWholeProcessGroup(t *testing.T) {
	group := canSignalGrandchildren(t)
	r, store := newRunner(t, childCommand, 500*time.Millisecond)
	if _, err := r.Start(context.Background(), Request{Rows: []string{"t1"}}); err != nil {
		t.Fatal(err)
	}
	waitForChild(t, store, "t1")
	r.Wait()
	if group {
		assertChildStopped(t, store, "t1")
	}
	j := status(t, r, "t1")
	if j.Status != TimedOut {
		t.Errorf("expected timed-out, got %s", j.Status)
	}
	assertSurvivorsReported(t, j, group)
}

func TestShutdownIsInterruptedNotCancelled(t *testing.T) {
	group := canSignalGrandchildren(t)
	r, store := newRunner(t, childCommand, time.Minute)
	ctx, stop := context.WithCancel(context.Background())
	if _, err := r.Start(ctx, Request{Rows: []string{"s1"}}); err != nil {
		t.Fatal(err)
	}
	waitForChild(t, store, "s1")
	stop()
	r.Wait()
	if group {
		assertChildStopped(t, store, "s1")
	}
	j := status(t, r, "s1")
	if j.Status != Interrupted {
		t.Errorf("expected shutdown to record interrupted, got %s", j.Status)
	}
	assertSurvivorsReported(t, j, group)
}

func TestCancellingAQueuedJobNeverRunsIt(t *testing.T) {
	r, store := newRunner(t, `touch "$YARDSTICK_ROOT/ran-$YARDSTICK_ROW"; sleep 30 & wait`, time.Minute)
	r.cfg.Concurrency, r.sem = 1, make(chan struct{}, 1)
	for _, id := range []string{"first", "second"} {
		if _, err := r.Start(context.Background(), Request{Rows: []string{id}}); err != nil {
			t.Fatal(err)
		}
	}
	for deadline := time.Now().Add(5 * time.Second); status(t, r, "first").Status != Running && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	if j := status(t, r, "second"); j.Status != Queued {
		t.Fatalf("expected the second job to wait for the only slot, got %s", j.Status)
	}
	if err := r.Cancel("second"); err != nil {
		t.Fatal(err)
	}
	if err := r.Cancel("first"); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if _, err := os.Stat(filepath.Join(store, "ran-second")); err == nil {
		t.Error("the cancelled queued job ran its command")
	}
	if j := status(t, r, "second"); j.Status != Cancelled || !j.Started.IsZero() {
		t.Errorf("expected the queued job cancelled without starting, got %+v", j)
	}
	if Cancelled.Active() {
		t.Error("cancelled must be a final state")
	}
}
