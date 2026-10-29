package research

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// wroteCommand stands in for research whose propose call was denied: it writes its report and a
// proposal on its row where the plugin does, and a second proposal naming another row beside it
const wroteCommand = `d=.yardstick/research/CVE-1/foo && mkdir -p "$d" && printf '# report\n' > "$d/REPORT.md" && ` +
	`printf '{"row":"%s","verdict":"tp","justification":"no-fix"}\n' "$YARDSTICK_ROW" > "$d/proposal.json" && ` +
	`printf '{"row":"zzz","verdict":"fp","justification":"no-fix"}\n' > "$d/proposal-z.json"`

// fakePropose stands in for this yardstick's propose: it keeps what it was given in the workspace,
// refuses when the workspace holds "refuse", and when it holds "rerun" leaves the job's record as a
// rerun queued meanwhile would
const fakePropose = `#!/bin/sh
cd "$YARDSTICK_ROOT"
if [ -f refuse ]; then printf '[0000] ERROR \033[31mproposal 1: no\033[0m\n'; exit 2; fi
if [ -f rerun ]; then printf '{"rows":["aaa"],"status":"queued","queued":"2030-01-01T00:00:00Z"}' > .yardstick/jobs/aaa/job.json; fi
echo "$@" >> args.txt
`

// recordRunner has run wroteCommand as job aaa on CVE-1 in foo, which recorded nothing
func recordRunner(t *testing.T) *Runner {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(t.TempDir(), "yardstick")
	if err := os.WriteFile(bin, []byte(fakePropose), 0o700); err != nil {
		t.Fatal(err)
	}
	none := func() (map[string]time.Time, error) { return map[string]time.Time{}, nil }
	r := NewRunner(Config{Command: wroteCommand, Dir: dir, Run: "pr", Timeout: time.Minute, Bin: bin, Recorded: none})
	if _, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}, Vulnerability: "CVE-1", Package: "pkg:npm/foo@1", Gate: "g"}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	return r
}

// Record records this run's proposal.json on the job's own row, and nothing beside it
func TestRecordRecordsWhatThePageShows(t *testing.T) {
	r := recordRunner(t)
	out := r.Output(must(r.load("aaa")))
	if out.Proposal == nil || out.Proposal.Verdict != "tp" || out.Report != "# report\n" || out.OtherRow != "" {
		t.Fatalf("expected this run's proposal and report, got %+v", out)
	}
	j, err := r.Record(context.Background(), "aaa")
	if err != nil || j.Status != Done || !j.Recorded || j.LastDone.IsZero() || !j.Researched() {
		t.Fatalf("expected recorded and done, got %+v %v", j, err)
	}
	args := strings.TrimSpace(string(must(os.ReadFile(filepath.Join(r.cfg.Dir, "args.txt")))))
	if want := "claims agent propose --name pr --gate g " + filepath.Join(r.cfg.Dir, ".yardstick", "research", "CVE-1", "foo", ProposalFile); args != want {
		t.Errorf("propose got %q, want %q", args, want)
	}
	if _, err := r.Record(context.Background(), "aaa"); err == nil || !strings.Contains(err.Error(), "the job is done") {
		t.Errorf("expected a done job refused, got %v", err)
	}
}

// a proposal in the shared folder about another row, or from before this run, isn't this job's
func TestRecordRefusesAnotherRowsOrAnEarlierRunsProposal(t *testing.T) {
	r := recordRunner(t)
	p := filepath.Join(r.cfg.Dir, ".yardstick", "research", "CVE-1", "foo", ProposalFile)
	if err := os.WriteFile(p, []byte(`{"row":"zzz","verdict":"fp","justification":"no-fix"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	job := must(r.load("aaa"))
	if out := r.Output(job); out.Proposal != nil || out.OtherRow != "zzz" || out.Report != "" {
		t.Errorf("expected another finding's research, not shown as this job's, got %+v", out)
	}
	if _, err := r.Record(context.Background(), "aaa"); err == nil {
		t.Error("expected another row's proposal refused")
	}
	// the job's own row again, but written before this run started
	if err := os.WriteFile(p, []byte(`{"row":"aaa","verdict":"tp"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before := job.Started.Add(-time.Hour)
	for _, f := range []string{p, filepath.Join(filepath.Dir(p), Report)} {
		if err := os.Chtimes(f, before, before); err != nil {
			t.Fatal(err)
		}
	}
	if out := r.Output(job); out.Proposal != nil || out.Report != "" || len(out.Files) != 2 {
		t.Errorf("expected an earlier run's files listed but not shown, got %+v", out)
	}
	if _, err := r.Record(context.Background(), "aaa"); err == nil {
		t.Error("expected an earlier run's proposal refused")
	}
}

// a job from before yardstick told done from not recorded is recorded by the status the page shows
func TestRecordAnOldDoneJob(t *testing.T) {
	r := recordRunner(t)
	j := must(r.load("aaa"))
	j.Status, j.Error, j.LastDone = Done, "", j.Finished
	if err := r.save(j); err != nil {
		t.Fatal(err)
	}
	if got, err := r.Record(context.Background(), "aaa"); err != nil || got.Status != Done {
		t.Errorf("expected it recorded, got %+v %v", got, err)
	}
}

// Record keeps out of a live job's way: refused while it runs, and a rerun started while propose
// ran keeps its own record
func TestRecordLeavesALiveJobAlone(t *testing.T) {
	r := recordRunner(t)
	r.live["aaa"] = true
	if _, err := r.Record(context.Background(), "aaa"); err == nil || !strings.Contains(err.Error(), "running on it again") {
		t.Errorf("expected a live job refused, got %v", err)
	}
	delete(r.live, "aaa")
	if err := os.WriteFile(filepath.Join(r.cfg.Dir, "rerun"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Record(context.Background(), "aaa"); err == nil || !strings.Contains(err.Error(), "started on it again meanwhile") {
		t.Errorf("expected the rerun noticed, got %v", err)
	}
	if j := must(r.load("aaa")); j.Status != Queued {
		t.Errorf("expected the rerun's record kept, got %+v", j)
	}
}

// propose's refusal comes back in its words, the job left as it was
func TestRecordSaysWhyProposeRefused(t *testing.T) {
	r := recordRunner(t)
	if err := os.WriteFile(filepath.Join(r.cfg.Dir, "refuse"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Record(context.Background(), "aaa"); err == nil || err.Error() != "propose refused it: proposal 1: no" {
		t.Errorf("got %v", err)
	}
	if j := must(r.load("aaa")); j.Status != NotRecorded {
		t.Errorf("expected the job left not recorded, got %s", j.Status)
	}
}

// a finding over several binary packages: the skill writes a copy per row beside proposal.json, and
// Record records each of the job's rows once, saying what the page shows, and no other row
func TestRecordRecordsEveryRowsCopy(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(t.TempDir(), "yardstick")
	if err := os.WriteFile(bin, []byte(fakePropose), 0o700); err != nil {
		t.Fatal(err)
	}
	const wrote = `d=.yardstick/research/CVE-1/foo && mkdir -p "$d" && ` +
		`printf '{"row":"aaa","verdict":"tp","justification":"no-fix"}\n' | tee "$d/proposal.json" > "$d/proposal-aaa.json" && ` +
		`printf '{"row":"bbb","verdict":"tp","justification":"no-fix"}\n' > "$d/proposal-bbb.json" && ` +
		`printf '{"row":"bbb","verdict":"fp","justification":"no-fix"}\n' > "$d/proposal-bbb2.json" && ` +
		`printf '{"row":"zzz","verdict":"tp","justification":"no-fix"}\n' > "$d/proposal-zzz.json"`
	none := func() (map[string]time.Time, error) { return map[string]time.Time{}, nil }
	r := NewRunner(Config{Command: wrote, Dir: dir, Run: "pr", Timeout: time.Minute, Bin: bin, Recorded: none})
	if _, err := r.Start(context.Background(), Request{Rows: []string{"aaa", "bbb"}, Vulnerability: "CVE-1", Package: "pkg:npm/foo@1", Gate: "g"}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if _, err := r.Record(context.Background(), "aaa"); err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(dir, ".yardstick", "research", "CVE-1", "foo")
	args := strings.TrimSpace(string(must(os.ReadFile(filepath.Join(dir, "args.txt")))))
	if want := "claims agent propose --name pr --gate g " + filepath.Join(d, ProposalFile) + " " + filepath.Join(d, "proposal-bbb.json"); args != want {
		t.Errorf("propose got %q, want %q", args, want)
	}
}
