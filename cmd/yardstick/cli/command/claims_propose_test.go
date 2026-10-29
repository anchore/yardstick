package command

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
)

// the refusal note goes only into a research job's own directory, whatever the variable says
func TestNoteRefusalOnlyInAJobDirectory(t *testing.T) {
	refuse := noteRefusal(&cobra.Command{RunE: func(*cobra.Command, []string) error { return errors.New("refused") }})
	elsewhere := t.TempDir()
	t.Setenv(research.JobDirEnv, elsewhere)
	_ = refuse.RunE(refuse, nil)
	if _, err := os.Stat(filepath.Join(elsewhere, research.ProposeErrorFile)); !os.IsNotExist(err) {
		t.Errorf("expected no note outside a job's directory: %v", err)
	}
	job := filepath.Join(t.TempDir(), ".yardstick", "research", "jobs", "j1")
	if err := os.MkdirAll(job, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(research.JobDirEnv, job)
	_ = refuse.RunE(refuse, nil)
	if _, err := os.Stat(filepath.Join(job, research.ProposeErrorFile)); err != nil {
		t.Errorf("expected the note in the job's directory: %v", err)
	}
}

// the research job on a record is the one propose runs in: a record can't name another
func TestTheResearchJobIsTheOneProposeRunsIn(t *testing.T) {
	var schema, id string
	var ts time.Time
	for env, want := range map[string]string{"job-a": "job-a", "": ""} {
		t.Setenv(researchJobEnv, env)
		a := agentstore.Author{Kind: agentstore.Agent, ResearchJob: "job-b"}
		fillDefaults(&schema, &id, &ts, &a, time.Now())
		if a.ResearchJob != want {
			t.Errorf("with %s=%q: got %q, want %q", researchJobEnv, env, a.ResearchJob, want)
		}
	}
}
