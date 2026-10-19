package research

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newRunner(t *testing.T, command string, timeout time.Duration) (*Runner, string) {
	t.Helper()
	dir := t.TempDir()
	return NewRunner(Config{Command: command, Dir: dir, Run: "pr", Concurrency: 2, Timeout: timeout, Bin: "/opt/ys/bin/yardstick"}), dir
}

func TestRunPassesContextInTheEnvironment(t *testing.T) {
	r, dir := newRunner(t, `echo "row=$YARDSTICK_ROW rows=$YARDSTICK_ROWS vuln=$YARDSTICK_RESEARCH_VULNERABILITY pkg=$YARDSTICK_RESEARCH_PACKAGE gate=$YARDSTICK_GATE name=$YARDSTICK_NAME root=$YARDSTICK_ROOT bin=$YARDSTICK_BIN path=${PATH%%:*}"`, time.Minute)
	job, err := r.Start(context.Background(), Request{Rows: []string{"aaa", "bbb"}, Vulnerability: "CVE-1", Package: "pkg:deb/ubuntu/glibc@1", Gate: "g1"})
	if err != nil {
		t.Fatal(err)
	}
	r.Wait()

	jobs, err := r.Jobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].ID != job.ID || jobs[0].Status != Done || jobs[0].Started.IsZero() || jobs[0].Finished.IsZero() {
		t.Fatalf("expected one finished job, got %+v", jobs)
	}
	out, err := os.ReadFile(r.LogPath(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	want := "row=aaa rows=aaa bbb vuln=CVE-1 pkg=pkg:deb/ubuntu/glibc@1 gate=g1 name=pr root=" + dir + " bin=/opt/ys/bin/yardstick path=/opt/ys/bin"
	if _, err := os.Stat(filepath.Join(dir, ".yardstick", "research", "jobs", "aaa", "job.json")); err != nil {
		t.Errorf("expected the job under .yardstick/research/jobs: %v", err)
	}
	if strings.TrimSpace(string(out)) != want {
		t.Errorf("expected %q, got %q", want, out)
	}
}

func TestModelAndSourceAreRecorded(t *testing.T) {
	r, _ := newRunner(t, `echo "model=$YARDSTICK_MODEL job=$YARDSTICK_RESEARCH_JOB"`, time.Minute)
	job, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}, Source: FromLabelUI})
	if err != nil {
		t.Fatal(err)
	}
	r.Wait()
	jobs, _ := r.Jobs()
	if j := jobs[0]; j.Model != DefaultModel || j.Source != FromLabelUI || !j.Researched() || j.LastDone.IsZero() {
		t.Errorf("expected a finished job on the default model, started from the UI, got %+v", j)
	}
	out, _ := os.ReadFile(r.LogPath(job.ID))
	if got, want := strings.TrimSpace(string(out)), "model=sonnet job=aaa"; got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestARerunThatFailsStillCountsAsResearched(t *testing.T) {
	r, _ := newRunner(t, `exit 0`, time.Minute)
	if _, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	r.cfg.Command = `exit 1`
	if _, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	jobs, _ := r.Jobs()
	if j := jobs[0]; j.Status != Failed || !j.Researched() {
		t.Errorf("expected the failed rerun to keep the earlier finish, got %+v", j)
	}
}

func TestValuesAreNotInterpolatedIntoTheCommand(t *testing.T) {
	// a row ID carrying shell syntax must reach the command as data
	r, _ := newRunner(t, `printf '%s' "$YARDSTICK_ROW"`, time.Minute)
	evil := "x; touch pwned"
	job, err := r.Start(context.Background(), Request{Rows: []string{evil}})
	if err != nil {
		t.Fatal(err)
	}
	r.Wait()
	out, _ := os.ReadFile(r.LogPath(job.ID))
	if string(out) != evil {
		t.Errorf("expected the row ID verbatim, got %q", out)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.Dir, "pwned")); err == nil {
		t.Error("the row ID was executed")
	}
}

func TestFailuresAndTimeoutsAreRecorded(t *testing.T) {
	r, _ := newRunner(t, `echo nope >&2; exit 3`, time.Minute)
	if _, err := r.Start(context.Background(), Request{Rows: []string{"f"}}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	jobs, _ := r.Jobs()
	if jobs[0].Status != Failed || jobs[0].Error == "" {
		t.Errorf("expected a failed job with an error, got %+v", jobs[0])
	}

	r, _ = newRunner(t, `sleep 5`, 200*time.Millisecond)
	if _, err := r.Start(context.Background(), Request{Rows: []string{"slow"}}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	jobs, _ = r.Jobs()
	if jobs[0].Status != TimedOut {
		t.Errorf("expected a timed-out job, got %+v", jobs[0])
	}
}

func TestConcurrencyIsLimited(t *testing.T) {
	r, _ := newRunner(t, `sleep 0.3`, time.Minute)
	r.cfg.Concurrency = 1
	r.sem = make(chan struct{}, 1)
	start := time.Now()
	for _, id := range []string{"a", "b", "c"} {
		if _, err := r.Start(context.Background(), Request{Rows: []string{id}}); err != nil {
			t.Fatal(err)
		}
	}
	r.Wait()
	if elapsed := time.Since(start); elapsed < 850*time.Millisecond {
		t.Errorf("expected jobs to run one at a time, took %s", elapsed)
	}
}
