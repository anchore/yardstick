package command

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
)

// the refusal note goes only into a research job's own directory, whatever the variable says
func TestNoteRefusalOnlyInAJobDirectory(t *testing.T) {
	var job researchJob
	refuse := noteRefusal(&job, &cobra.Command{RunE: func(*cobra.Command, []string) error { return errors.New("refused") }})
	elsewhere := t.TempDir()
	job.Dir = elsewhere
	_ = refuse.RunE(refuse, nil)
	if _, err := os.Stat(filepath.Join(elsewhere, research.ProposeErrorFile)); !os.IsNotExist(err) {
		t.Errorf("expected no note outside a job's directory: %v", err)
	}
	dir := filepath.Join(t.TempDir(), ".yardstick", "research", "jobs", "j1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	job.Dir = dir
	_ = refuse.RunE(refuse, nil)
	if _, err := os.Stat(filepath.Join(dir, research.ProposeErrorFile)); err != nil {
		t.Errorf("expected the note in the job's directory: %v", err)
	}
}

// the research job on a record is the one propose runs in: a record can't name another
func TestTheResearchJobIsTheOneProposeRunsIn(t *testing.T) {
	var schema, id string
	var ts time.Time
	for _, job := range []string{"job-a", ""} {
		a := agentstore.Author{Kind: agentstore.Agent, ResearchJob: "job-b"}
		fillDefaults(&schema, &id, &ts, &a, job, time.Now())
		if a.ResearchJob != job {
			t.Errorf("in job %q: got %q", job, a.ResearchJob)
		}
	}
}

// in a research job a record's timestamp and author kind are propose's, not the record's; outside
// one they are kept
func TestAResearchJobsCallIsAnAgentsNow(t *testing.T) {
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	ahead := now.AddDate(70, 0, 0)
	for job, want := range map[string]struct {
		ts   time.Time
		kind agentstore.AuthorKind
	}{"job-a": {now, agentstore.Agent}, "": {ahead, agentstore.Human}} {
		var schema, id string
		ts := ahead
		a := agentstore.Author{Kind: agentstore.Human}
		fillDefaults(&schema, &id, &ts, &a, job, now)
		if !ts.Equal(want.ts) || a.Kind != want.kind {
			t.Errorf("in job %q: got %s %s, want %s %s", job, ts, a.Kind, want.ts, want.kind)
		}
	}
}

// the research job is read from the environment the label server sets, and no flag can name it
func TestTheResearchJobIsEnvOnly(t *testing.T) {
	cfg := clio.NewSetupConfig(clio.Identification{Name: "yardstick"})
	cfg.FangsConfig.Finders = []fangs.Finder{func(fangs.Config) []string { return nil }}
	app := clio.New(*cfg)

	t.Setenv(research.JobEnv, "job-1")
	t.Setenv(research.JobDirEnv, "/w/.yardstick/research/jobs/job-1")
	t.Setenv(research.GateEnv, "deb")
	t.Setenv(research.RowsEnv, "aaa bbb")
	var got researchJob
	opts := &agentOptions{}
	cmd := app.SetupCommand(&cobra.Command{Use: "propose", RunE: func(*cobra.Command, []string) error {
		got = opts.Research
		return nil
	}}, opts)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if want := (researchJob{ID: "job-1", Dir: "/w/.yardstick/research/jobs/job-1", Gate: "deb", Rows: "aaa bbb"}); got != want {
		t.Errorf("got %+v from the environment, want %+v", got, want)
	}

	propose := ClaimsPropose(app)
	for _, name := range []string{"research-job", "research-job-dir", "research-gate", "rows"} {
		if propose.Flags().Lookup(name) != nil {
			t.Errorf("propose has a flag --%s: a research job must come from the environment alone", name)
		}
	}
	propose.SetArgs([]string{"--research-job", "job-2"})
	propose.SetOut(io.Discard)
	propose.SetErr(io.Discard)
	if err := propose.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("expected --research-job refused as an unknown flag, got %v", err)
	}
}
