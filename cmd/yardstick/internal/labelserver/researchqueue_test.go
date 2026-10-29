package labelserver

import (
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
)

// a job that ran but recorded nothing is counted as such, not as a failure
func TestProgressCountsNotRecorded(t *testing.T) {
	jobs := []research.Job{{Status: research.Done}, {Status: research.NotRecorded}, {Status: research.Failed}, {Status: research.Cancelled}}
	got := progress(jobs, jobs, 1)
	if got.Done != 1 || got.NotRecorded != 1 || got.Failed != 1 || got.Cancelled != 1 {
		t.Errorf("expected one of each, got %+v", got)
	}
}
