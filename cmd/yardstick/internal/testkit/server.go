package testkit

import (
	"context"
	"path/filepath"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

// researchCommand stands in for the research-vuln skill: it proposes tp for the row it was given,
// through the CLI the way the skill does, between the init and result events claude streams, costing
// $0.25.
const researchCommand = `echo '{"type":"system","subtype":"init","model":"e2e"}' && printf '{"row":"%s","verdict":"tp","justification":"no-fix","confidence":"medium","note":"e2e research stand-in","author":{"skill":"research-vuln","model":"e2e"}}\n' "$YARDSTICK_ROW" | yardstick claims agent propose && ` +
	`echo '{"type":"result","subtype":"success","result":"proposed tp","total_cost_usd":0.25,"num_turns":4,"duration_ms":2000,"usage":{"input_tokens":30,"cache_read_input_tokens":9000,"cache_creation_input_tokens":1000,"output_tokens":400}}'`

// NewServer is the label server over the scanned workspace in the working directory, as the label
// UI's end to end tests run it. Research runs the stand-in, never claude, and bin is the yardstick
// it calls back into. The runner is returned so a caller can wait for its jobs once ctx ends.
func NewServer(ctx context.Context, dir, bin string) (*labelserver.Server, *research.Runner, error) {
	r := research.NewRunner(research.Config{
		Command: researchCommand, Dir: dir, Run: runrecord.DefaultName, Concurrency: 2, Timeout: time.Minute, Bin: bin,
		Recorded: agentstore.Open(filepath.Join(dir, agentstore.Dir)).RecordedJobs,
	})
	srv, err := newServer(ctx, r)
	return srv, r, err
}

// newServer is the label server with its research run by r.
func newServer(ctx context.Context, r *research.Runner) (*labelserver.Server, error) {
	return labelserver.New(ctx, labelserver.Options{
		Run: runrecord.DefaultName, Author: author, Store: agentstore.Open(agentstore.Dir),
		Research:             r,
		ResearchAvailability: research.Availability{Available: true},
		Load: func(p string) (*gatefile.Gate, error) {
			return gatefile.Load(p, gatefile.Options{Checks: analysis.Definitions()})
		},
	})
}
