package command

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

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
