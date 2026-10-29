package research

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// the result line of a run whose writes were all refused, as claude prints it last
const deniedResult = `{"type":"result","subtype":"success","is_error":false,"total_cost_usd":0.27,"num_turns":18,` +
	`"permission_denials":[{"tool_name":"Write","tool_use_id":"t1","tool_input":{"file_path":".yardstick/research/CLEANSTART-2026-GU36052/binutils/REPORT.md","content":"# x"}},` +
	`{"tool_name":"Bash","tool_use_id":"t2","tool_input":{"command":"gh api repos/bminor/binutils-gdb/commits/ea1a0737"}}],` +
	`"result":"I couldn't finish this one. Verdict I would propose: tp, fix-newer, medium."}`

// recorder is a Config.Recorded: when it is asked, the job "aaa" recorded a call at its time, when
// ok, and else none
type recorder struct {
	ok    bool
	asked int
}

func (c *recorder) recorded() (map[string]time.Time, error) {
	c.asked++
	if !c.ok {
		return map[string]time.Time{}, nil
	}
	return map[string]time.Time{"aaa": time.Now().UTC()}, nil
}

// runOne runs command as one job on row aaa, Recorded answering rec, and returns the job as recorded
func runOne(t *testing.T, command string, rec func() (map[string]time.Time, error)) (Job, *Runner) {
	t.Helper()
	dir := t.TempDir()
	r := NewRunner(Config{Command: command, Dir: dir, Run: "pr", Timeout: time.Minute, Recorded: rec})
	if _, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}, Vulnerability: "CLEANSTART-2026-GU36052"}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	jobs, err := r.Jobs()
	if err != nil || len(jobs) != 1 {
		t.Fatalf("expected one job, got %+v %v", jobs, err)
	}
	return jobs[0], r
}

func TestAJobIsDoneOnlyOnceItRecordedACall(t *testing.T) {
	// the command prints a result line from a file, which quoting it in the command can't spoil
	lines := t.TempDir()
	echo := func(line string) string {
		p := filepath.Join(lines, fmt.Sprintf("%d.json", len(line)))
		if err := os.WriteFile(p, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return "cat " + p
	}
	for name, tc := range map[string]struct {
		command  string
		recorded bool
		status   Status
		reason   string
	}{
		"recorded": {echo(deniedResult), true, Done, ""},
		// the writes and the propose call refused: nothing on disk, no call
		"refused tools": {echo(deniedResult), false, NotRecorded,
			"the agent was refused 2 tool uses: Write .yardstick/research/CLEANSTART-2026-GU36052/binutils/REPORT.md; Bash gh api repos/bminor/binutils-gdb/commits/ea1a0737"},
		// propose refused the call, and said why in the job's directory, colors and all
		"propose refused": {`printf '\033[31mproposal 1: vulnerability CLEANSTART-2026-GU36052: namespace "CLEANSTART" is not in any claims source'"'"'s vocabulary.yaml\033[0m\n' > "$YARDSTICK_RESEARCH_JOB_DIR/propose-error.txt"; ` + echo(deniedResult), false, NotRecorded,
			`propose refused it: proposal 1: vulnerability CLEANSTART-2026-GU36052: namespace "CLEANSTART" is not in any claims source's vocabulary.yaml`},
		"nothing on record": {echo(`{"type":"result","total_cost_usd":0.1,"permission_denials":[],"result":"done"}`), false, NotRecorded, "nothing was recorded; the log says what happened"},
	} {
		rec := &recorder{ok: tc.recorded}
		j, _ := runOne(t, tc.command, rec.recorded)
		if j.Status != tc.status || j.Error != tc.reason {
			t.Errorf("%s: got %s %q, want %s %q", name, j.Status, j.Error, tc.status, tc.reason)
		}
		if rec.asked == 0 {
			t.Errorf("%s: Recorded never asked", name)
		}
		// researched only once it recorded a call: batch research picks the others up again
		if recorded := tc.status == Done; j.Researched() != recorded || j.LastDone.IsZero() == recorded || j.Recorded != recorded || j.Usage == nil {
			t.Errorf("%s: expected researched=%v with its cost, got %+v", name, recorded, j)
		}
		if name != "nothing on record" && j.Summary != "I couldn't finish this one. Verdict I would propose: tp, fix-newer, medium." {
			t.Errorf("%s: expected the agent's last message kept, got %q", name, j.Summary)
		}
	}
}

func TestWithoutARecordedHookExitingZeroIsDone(t *testing.T) {
	if j, _ := runOne(t, "true", nil); j.Status != Done || j.Error != "" {
		t.Errorf("expected done, got %+v", j)
	}
}

// a rerun's refusal is its own: the last run's file is gone before the command starts
func TestARerunDropsTheLastRunsRefusal(t *testing.T) {
	// only the first run refuses: the marker it leaves outlasts it, as the job's directory does
	j, r := runOne(t, `d=$YARDSTICK_RESEARCH_JOB_DIR; [ -f "$d/ran" ] || { echo refused > "$d/propose-error.txt"; touch "$d/ran"; }`, (&recorder{}).recorded)
	if j.Error != "propose refused it: refused" {
		t.Fatalf("first run: %+v", j)
	}
	if _, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	jobs, _ := r.Jobs()
	if jobs[0].Error != "nothing was recorded; the log says what happened" {
		t.Errorf("rerun: %+v", jobs[0])
	}
	if _, err := os.Stat(filepath.Join(r.jobs, "aaa", ProposeErrorFile)); !os.IsNotExist(err) {
		t.Errorf("expected the last run's refusal removed: %v", err)
	}
}

// the refusals that kept a call from being recorded lead, whatever order they came in
func TestWritesAndProposeLeadTheReason(t *testing.T) {
	r := NewRunner(Config{Dir: t.TempDir()})
	gh := func(n string) denial {
		return denial{ToolName: "Bash", ToolInput: map[string]any{"command": "gh api " + n}}
	}
	end := ending{Denials: []denial{gh("a"), gh("b"), gh("c"), {ToolName: "Write", ToolInput: map[string]any{"file_path": "REPORT.md"}},
		{ToolName: "Bash", ToolInput: map[string]any{"command": "yardstick claims agent propose --gate g"}}}}
	if got, want := r.whyNotRecorded(&Job{ID: "aaa"}, end), "the agent was refused 5 tool uses: Write REPORT.md; Bash yardstick claims agent propose --gate g; Bash gh api a and 2 more"; got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestDenialsAreShortened(t *testing.T) {
	long := denial{ToolName: "Bash", ToolInput: map[string]any{"command": "cat > REPORT.md <<'EOF'\n# CLEANSTART-2026-GU36052 (CVE-2025-11082) on binutils 2.45.1-r0\n\n**tp, medium confidence"}}
	if got := long.String(); len([]rune(got)) > 86 || got[:31] != "Bash cat > REPORT.md <<'EOF' # " {
		t.Errorf("got %q", got)
	}
	if got := (denial{ToolName: "WebFetch"}).String(); got != "WebFetch" {
		t.Errorf("got %q", got)
	}
}

// a call recorded before the job started is a run before it's, whose id it shares
func TestACallBeforeTheRunIsNotItsOwn(t *testing.T) {
	before := time.Now().UTC().Add(-time.Hour)
	j, _ := runOne(t, "true", func() (map[string]time.Time, error) { return map[string]time.Time{"aaa": before}, nil })
	if j.Status != NotRecorded {
		t.Errorf("expected not recorded, got %+v", j)
	}
}

// a job recorded as done before yardstick told done from not recorded is settled the first time it
// is read: not recorded, with why from its log, when it recorded nothing, and no longer researched;
// marked recorded when it did. Either way it is saved, so later reads ask nothing.
func TestAnOldDoneJobIsSettledOnce(t *testing.T) {
	lines := t.TempDir()
	if err := os.WriteFile(filepath.Join(lines, "r.json"), []byte(deniedResult+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// with no Recorded, as before this yardstick, exiting 0 is done
	old, r0 := runOne(t, "cat "+filepath.Join(lines, "r.json"), nil)
	if old.Status != Done || old.Recorded || old.LastDone.IsZero() {
		t.Fatalf("expected an old-style done job, got %+v", old)
	}
	for _, recorded := range []bool{false, true} {
		dir := t.TempDir()
		if err := os.CopyFS(dir, os.DirFS(r0.cfg.Dir)); err != nil {
			t.Fatal(err)
		}
		rec := &recorder{ok: recorded}
		r := NewRunner(Config{Dir: dir, Recorded: rec.recorded})
		jobs, err := r.Jobs()
		if err != nil {
			t.Fatal(err)
		}
		j, saved := jobs[0], must(r.load("aaa"))
		switch {
		case recorded && (j.Status != Done || !j.Recorded || !j.Researched()):
			t.Errorf("recorded: expected done and marked so, got %+v", j)
		case !recorded && (j.Status != NotRecorded || j.Error[:30] != "the agent was refused 2 tool u" || j.Summary == "" || j.Researched() || !j.LastDone.IsZero()):
			t.Errorf("not recorded: expected not recorded with the denials, and not researched, got %+v", j)
		case saved.Status != j.Status || saved.Recorded != j.Recorded:
			t.Errorf("recorded=%v: expected what it came to saved, got %+v", recorded, saved)
		}
		if _, err := r.Jobs(); err != nil || rec.asked != 1 {
			t.Errorf("recorded=%v: expected one question across two reads, got %d %v", recorded, rec.asked, err)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
