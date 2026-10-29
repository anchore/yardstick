package research

import (
	"context"
	"os"
	"path/filepath"
	"slices"
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
	r, dir := newRunner(t, `echo "row=$YARDSTICK_ROW rows=$YARDSTICK_ROWS vuln=$YARDSTICK_RESEARCH_VULNERABILITY pkg=$YARDSTICK_RESEARCH_PACKAGE gate=$YARDSTICK_GATE/$YARDSTICK_RESEARCH_GATE name=$YARDSTICK_NAME root=$YARDSTICK_ROOT bin=$YARDSTICK_BIN path=${PATH%%:*}"`, time.Minute)
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
	want := "row=aaa rows=aaa bbb vuln=CVE-1 pkg=pkg:deb/ubuntu/glibc@1 gate=g1/g1 name=pr root=" + dir + " bin=/opt/ys/bin/yardstick path=/opt/ys/bin"
	if _, err := os.Stat(filepath.Join(dir, ".yardstick", "jobs", "aaa", "job.json")); err != nil {
		t.Errorf("expected the job under .yardstick/jobs: %v", err)
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

// the agent gets what it needs to run and reach the model, not this process's other credentials
func TestChildEnvironmentIsAllowlisted(t *testing.T) {
	env := []string{"PATH=/bin", "HOME=/home/a", "YARDSTICK_CLAIMS_URL=https://x", "ANTHROPIC_API_KEY=k", "CLAUDE_CONFIG_DIR=/c",
		"GITHUB_TOKEN=secret", "AWS_SECRET_ACCESS_KEY=aws", "R2_SECRET=r2", "HTTPS_PROXY=http://proxy"}
	got := childEnv(env)
	want := []string{"PATH=/bin", "HOME=/home/a", "YARDSTICK_CLAIMS_URL=https://x", "ANTHROPIC_API_KEY=k", "CLAUDE_CONFIG_DIR=/c", "HTTPS_PROXY=http://proxy"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("expected %v, got %v", want, got)
	}
	// Bedrock's credentials go through only when Claude Code is set to use Bedrock
	if got := childEnv(append(env, "CLAUDE_CODE_USE_BEDROCK=1")); !slices.Contains(got, "AWS_SECRET_ACCESS_KEY=aws") || slices.Contains(got, "GITHUB_TOKEN=secret") {
		t.Errorf("expected the AWS keys with Bedrock on, and still no GITHUB_TOKEN, got %v", got)
	}
}

// the command a job runs sees the allowlisted environment, not the whole of this process's
func TestRunDropsCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret")
	t.Setenv("ANTHROPIC_API_KEY", "k")
	r, _ := newRunner(t, `echo "gh=$GITHUB_TOKEN key=$ANTHROPIC_API_KEY"`, time.Minute)
	job, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}})
	if err != nil {
		t.Fatal(err)
	}
	r.Wait()
	out, _ := os.ReadFile(r.LogPath(job.ID))
	if got := strings.TrimSpace(string(out)); got != "gh= key=k" {
		t.Errorf("expected only the model key, got %q", got)
	}
}

// the default command never hands the agent an open shell, a write anywhere or a read outside the
// workspace
func TestDefaultCommandIsNarrow(t *testing.T) {
	rules := func(flag string) []string {
		_, list, _ := strings.Cut(DefaultCommand, flag+` "`)
		list, _, _ = strings.Cut(list, `"`)
		return strings.Split(list, ",")
	}
	for _, tool := range rules("--allowedTools") {
		if slices.Contains([]string{"Bash", "Write", "Edit", "Read", "Grep", "Glob"}, tool) || strings.HasPrefix(tool, "Bash(jq") {
			t.Errorf("expected no unscoped %s, got %v", tool, rules("--allowedTools"))
		}
	}
	// a person's settings may allow Read anywhere, so only the block keeps reads in the workspace
	if !strings.Contains(DefaultCommand, `--settings '{"permissions":{"blockReadsOutsideWorkingDirectories":true}}'`) {
		t.Errorf("expected reads outside the workspace blocked, got %s", DefaultCommand)
	}
}

// a relative rule follows the agent's `cd`, after which every write was refused; the rules name the
// workspace from the root ("//" once /$YARDSTICK_ROOT expands)
func TestDefaultCommandWritesUnderTheWorkspaceByAbsolutePath(t *testing.T) {
	for _, rule := range []string{"Edit(/$YARDSTICK_ROOT/.yardstick/research/**)", "Read(/$YARDSTICK_ROOT/**)", "Grep(/$YARDSTICK_ROOT/**)", "Glob(/$YARDSTICK_ROOT/**)"} {
		if !strings.Contains(DefaultCommand, rule) {
			t.Errorf("expected the absolute rule %s on the workspace, got %s", rule, DefaultCommand)
		}
	}
}

func TestCheckRulePath(t *testing.T) {
	for dir, ok := range map[string]bool{
		"/Users/me/vunnel/tests/integration": true,
		"/Users/me/my work/vunnel":           true,
		"relative/dir":                       false,
		"/x),Bash(*":                         false,
		"/a/b*":                              false,
		`/a/"b`:                              false,
		"/a/$HOME":                           false,
		"/a/\nb":                             false,
	} {
		if err := checkRulePath(dir); (err == nil) != ok {
			t.Errorf("checkRulePath(%q): expected ok=%v, got %v", dir, ok, err)
		}
	}
}

func TestStartRefusesAWorkspaceTheRuleCantName(t *testing.T) {
	r := NewRunner(Config{Dir: "/tmp/x),Bash(*", Bin: "/opt/ys/bin/yardstick"})
	if _, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}}); err == nil || !strings.Contains(err.Error(), "permission rule") {
		t.Errorf("expected a refusal naming the permission rule, got %v", err)
	}
}

// a job's id is its directory's name: a record naming another id, or a path, can't point its log or
// its saves elsewhere
func TestAJobsIDIsItsDirectory(t *testing.T) {
	r, _ := newRunner(t, "true", time.Minute)
	dir := filepath.Join(r.jobs, "aaa")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "job.json"), []byte(`{"id":"../../../escape","rows":["aaa"],"status":"done"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.Jobs()
	if err != nil || len(jobs) != 1 || jobs[0].ID != "aaa" {
		t.Fatalf("expected the job by its directory's name, got %+v %v", jobs, err)
	}
	if got := r.LogPath(jobs[0].ID); got != filepath.Join(dir, "log.txt") {
		t.Errorf("its log is %s", got)
	}
}

// the agent may write research output, never a job record the server trusts
func TestDefaultCommandDeniesJobRecords(t *testing.T) {
	if !strings.Contains(DefaultCommand, `--disallowedTools "Edit(/$YARDSTICK_ROOT/.yardstick/jobs/**),Edit(/$YARDSTICK_ROOT/.yardstick/research/jobs/**)`) {
		t.Errorf("expected job records denied, got %s", DefaultCommand)
	}
}

// the agent's propose reads the same claims sources the server does
func TestJobEnvPassesTheServersClaims(t *testing.T) {
	env := Job{ID: "a", Rows: []string{"a"}}.env(Config{Claims: []string{"github.com/anchore/claims@main", "./additional-claims"}})
	if !slices.Contains(env, "YARDSTICK_CLAIMS=github.com/anchore/claims@main,./additional-claims") {
		t.Errorf("expected the claims sources, got %v", env)
	}
	if slices.ContainsFunc(Job{ID: "a", Rows: []string{"a"}}.env(Config{}), func(kv string) bool { return strings.HasPrefix(kv, "YARDSTICK_CLAIMS=") }) {
		t.Error("expected no YARDSTICK_CLAIMS without sources, so the workspace's config applies")
	}
	r := NewRunner(Config{Dir: "/w", Claims: []string{"/a,b"}})
	if _, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}}); err == nil {
		t.Error("expected a claims source with a comma refused")
	}
}

// job records from under .yardstick/research/jobs/, where the agent may write, move out once
func TestOldJobRecordsMoveOutOfTheResearchTree(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, ".yardstick", "research", "jobs", "aaa")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "job.json"), []byte(`{"rows":["aaa"],"status":"failed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(Config{Dir: dir})
	if jobs, err := r.Jobs(); err != nil || len(jobs) != 1 || jobs[0].ID != "aaa" {
		t.Errorf("expected the old job under .yardstick/jobs, got %+v %v", jobs, err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("expected nothing left under .yardstick/research/jobs: %v", err)
	}
	// once only: a record planted in the old place later is never imported
	planted := filepath.Join(dir, ".yardstick", "research", "jobs", "bbb")
	if err := os.MkdirAll(planted, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(planted, "job.json"), []byte(`{"rows":["bbb"],"status":"done"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if jobs, err := NewRunner(Config{Dir: dir}).Jobs(); err != nil || len(jobs) != 1 || jobs[0].ID != "aaa" {
		t.Errorf("expected only the moved job, got %+v %v", jobs, err)
	}
	// and with no old records at all, the first start still settles it
	fresh := t.TempDir()
	NewRunner(Config{Dir: fresh})
	plant := filepath.Join(fresh, ".yardstick", "research", "jobs", "ccc")
	if err := os.MkdirAll(plant, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plant, "job.json"), []byte(`{"rows":["ccc"],"status":"done"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if jobs, _ := NewRunner(Config{Dir: fresh}).Jobs(); len(jobs) != 0 {
		t.Errorf("expected nothing imported from a later plant, got %+v", jobs)
	}
}

// a user's defaultMode or MCP servers don't carry into research
func TestDefaultCommandKeepsTheUsersModeAndMCPOut(t *testing.T) {
	for _, flag := range []string{"--permission-mode default", "--strict-mcp-config"} {
		if !strings.Contains(DefaultCommand, flag) {
			t.Errorf("expected %s, got %s", flag, DefaultCommand)
		}
	}
}
