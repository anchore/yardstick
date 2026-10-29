package research

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// What a job's agent writes: the research-vuln skill keeps its report and the proposal it means to
// record in the job's own output directory, .yardstick/research/job-<id>/ (OutputEnv), whether or not
// propose took the proposal. A run outside a job writes under .yardstick/research/<vuln>/<package>/.

// Report and ProposalFile are the skill's files in a job's output directory; OutputEnv names that
// directory for the plugin's yardstick-vuln-sources.py and the skill.
const (
	Report       = "REPORT.md"
	ProposalFile = "proposal.json"
	OutputEnv    = "YARDSTICK_RESEARCH_OUT"
)

// maxReport caps how much of a report is read.
const maxReport = 256 * 1024

// OutputDir is where the job's agent writes its report and proposal, relative to the workspace;
// empty for an id that isn't one path component.
func OutputDir(job Job) string {
	if job.ID == "" || filepath.Base(job.ID) != job.ID {
		return ""
	}
	return filepath.Join(".yardstick", "research", "job-"+job.ID)
}

// Written is a proposal the agent wrote down, as far as a person reads it before it is recorded.
type Written struct {
	Verdict       string   `json:"verdict"`
	Justification string   `json:"justification,omitempty"`
	Confidence    string   `json:"confidence,omitempty"`
	Note          string   `json:"note,omitempty"`
	OpenQuestions []string `json:"openQuestions,omitempty"`
}

// Output is what a job's agent left in its output directory: the files there of the skill's, the
// report's text, and the proposal when it holds a verdict (the plugin writes it first as a skeleton
// with none) and is about one of this job's rows. A run clears the directory as it starts, so what
// is there is the last run's.
type Output struct {
	Dir      string   `json:"dir"`
	Files    []string `json:"files"`
	Report   string   `json:"report,omitempty"`
	Proposal *Written `json:"proposal,omitempty"`
}

// Output reads what the job's agent wrote; nil when it has no output directory, or never started (a
// rerun cancelled while queued would otherwise show the run before it).
func (r *Runner) Output(job Job) *Output {
	out, _ := r.output(job)
	return out
}

// output is Output, and the bytes of proposal.json it read its Proposal from.
func (r *Runner) output(job Job) (*Output, []byte) {
	rel := OutputDir(job)
	if rel == "" || job.Started.IsZero() {
		return nil, nil
	}
	var raw []byte
	out := &Output{Dir: rel, Files: []string{}}
	dir := filepath.Join(r.cfg.Dir, rel)
	has := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		if err == nil {
			out.Files = append(out.Files, name)
		}
		return err == nil
	}
	report, proposal := has(Report), has(ProposalFile)
	if proposal {
		var w struct {
			Written
			Row string `json:"row"`
		}
		data, err := os.ReadFile(filepath.Join(dir, ProposalFile))
		if err == nil && json.Unmarshal(data, &w) == nil && slices.Contains(job.Rows, w.Row) && w.Verdict != "" {
			out.Proposal, raw = &w.Written, data
		}
	}
	if report {
		if data, err := readCapped(filepath.Join(dir, Report)); err == nil {
			out.Report = string(data)
		}
	}
	return out, raw
}

// readCapped is the first maxReport bytes of a file.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxReport))
}

// Record records the proposal the job's agent wrote but didn't record, as it would have: this
// yardstick's `claims agent propose` on proposal.json, in the job's environment, so the call carries
// the job's id and is checked as the agent's are. It records exactly what Output shows: the bytes it
// read go to propose on stdin, never a path propose would read again after the agent (this job's, or
// another's) could have rewritten it. The job is judged as Jobs reads it, so one from before
// yardstick told done from not recorded can be recorded too. Once recorded the job is Done; a
// refusal is returned as propose said it, and the job left as it was. Nothing is researched again.
func (r *Runner) Record(ctx context.Context, id string) (Job, error) {
	r.mu.Lock()
	job, err := r.load(id)
	live := r.live[id]
	if err == nil && !live {
		jobs := []Job{job}
		r.reconcile(jobs)
		job = jobs[0]
	}
	r.mu.Unlock()
	switch {
	case err != nil:
		return job, err
	case live:
		return job, errors.New("research is running on it again")
	case job.Status != NotRecorded:
		return job, fmt.Errorf("the job is %s, not %s", job.Status, NotRecorded)
	case r.cfg.Bin == "":
		return job, errors.New("this server can't run propose: it doesn't know its own binary")
	}
	o, raw := r.output(job)
	if o == nil || o.Proposal == nil {
		return job, errors.New("this run wrote no proposal with a verdict about its rows to record")
	}
	in := bytes.Join(append([][]byte{raw}, r.rowCopies(job, filepath.Join(r.cfg.Dir, o.Dir), raw, *o.Proposal)...), []byte("\n"))
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.cfg.Bin, "claims", "agent", "propose", "--name", cmp.Or(job.Run, r.cfg.Run), "--gate", job.Gate) //nolint:gosec // G204: this binary
	cmd.Dir, cmd.Stdin = r.cfg.Dir, bytes.NewReader(in)
	cmd.Env = append(childEnv(os.Environ()), job.env(r.cfg)...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(ansi.ReplaceAllString(out.String(), ""))
		// the CLI's error line, without its log prefix
		if i := strings.LastIndex(msg, "ERROR "); i >= 0 {
			msg = strings.TrimSpace(msg[i+len("ERROR "):])
		}
		if msg == "" {
			msg = err.Error()
		}
		return job, fmt.Errorf("propose refused it: %s", msg)
	}
	// a rerun started while propose ran is the job's record now: it says what it comes to
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, err := r.load(id)
	if err != nil {
		return job, err
	}
	if r.live[id] || !cur.Queued.Equal(job.Queued) {
		return cur, errors.New("recorded, but research started on it again meanwhile, so the job says what that run comes to")
	}
	cur.Status, cur.Error, cur.Recorded = Done, "", true
	cur.LastDone = time.Now().UTC()
	return cur, r.save(cur)
}

// rowCopies are proposal.json (raw) once more for each other row of the job the skill wrote a copy for
// beside it, when the finding covers several binary packages (proposal-<row id>.json) and the copy
// says what the page shows (proposal.json's verdict and justification). Each is raw with only its row
// changed, so Record records every row the agent would have and nothing the page didn't show.
func (r *Runner) rowCopies(job Job, dir string, raw []byte, shown Written) [][]byte {
	paths, _ := filepath.Glob(filepath.Join(dir, "proposal-*.json"))
	var out [][]byte
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil
	}
	var first string
	_ = json.Unmarshal(fields["row"], &first)
	seen := map[string]bool{first: true} // proposal.json's row is recorded already
	for _, p := range paths {
		var w struct {
			Written
			Row string `json:"row"`
		}
		data, err := os.ReadFile(p)
		if err != nil || json.Unmarshal(data, &w) != nil {
			continue
		}
		if !slices.Contains(job.Rows, w.Row) || seen[w.Row] || w.Verdict != shown.Verdict || w.Justification != shown.Justification {
			continue
		}
		seen[w.Row] = true
		fields["row"], _ = json.Marshal(w.Row)
		if b, err := json.Marshal(fields); err == nil {
			out = append(out, b)
		}
	}
	return out
}
