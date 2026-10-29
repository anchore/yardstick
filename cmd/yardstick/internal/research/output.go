package research

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/anchore/packageurl-go"
)

// What a job's agent writes: the research-vuln skill keeps its report and the proposal it means to
// record under .yardstick/research/<vulnerability>/<package name>/ (the plugin's
// yardstick-vuln-sources.py), whether or not propose took the proposal.

// Report and ProposalFile are the skill's files in a job's output directory.
const (
	Report       = "REPORT.md"
	ProposalFile = "proposal.json"
)

// maxReport caps how much of a report is read.
const maxReport = 256 * 1024

// unsafePart is what the plugin replaces in a path component.
var unsafePart = regexp.MustCompile(`[^A-Za-z0-9._+-]`)

// safePart is one path component as the plugin's safe_part makes it; empty when it refuses one.
func safePart(s string) string {
	s = unsafePart.ReplaceAllString(s, "_")
	if s == "." || s == ".." {
		return ""
	}
	return s
}

// OutputDir is where the job's agent writes its report and proposal, relative to the workspace;
// empty when the job's vulnerability can't name one.
func OutputDir(job Job) string {
	pkg := "all"
	if p, err := packageurl.FromString(job.Package); err == nil && p.Name != "" {
		pkg = p.Name
	}
	vuln, name := safePart(job.Vulnerability), safePart(pkg)
	if vuln == "" || name == "" {
		return ""
	}
	return filepath.Join(".yardstick", "research", vuln, name)
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
// report's text, and the proposal when it holds a verdict (the plugin writes it first as a
// skeleton with none).
type Output struct {
	Dir      string   `json:"dir"`
	Files    []string `json:"files"`
	Report   string   `json:"report,omitempty"`
	Proposal *Written `json:"proposal,omitempty"`
}

// Output reads what the job's agent wrote; nil when it has no output directory.
func (r *Runner) Output(job Job) *Output {
	rel := OutputDir(job)
	if rel == "" {
		return nil
	}
	out := &Output{Dir: rel, Files: []string{}}
	dir := filepath.Join(r.cfg.Dir, rel)
	if data, err := readCapped(filepath.Join(dir, Report)); err == nil {
		out.Files, out.Report = append(out.Files, Report), string(data)
	}
	if data, err := os.ReadFile(filepath.Join(dir, ProposalFile)); err == nil {
		out.Files = append(out.Files, ProposalFile)
		var w Written
		if json.Unmarshal(data, &w) == nil && w.Verdict != "" {
			out.Proposal = &w
		}
	}
	return out
}

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, maxReport)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

// proposals are the files the agent meant to record: a copy per row when it researched several
// binary packages (proposal-<row>.json), else proposal.json.
func proposals(dir string) []string {
	rows, _ := filepath.Glob(filepath.Join(dir, "proposal-*.json"))
	if len(rows) > 0 {
		slices.Sort(rows)
		return rows
	}
	return []string{filepath.Join(dir, ProposalFile)}
}

// Record records what the job's agent wrote but didn't record, as it would have: this yardstick's
// `claims agent propose` on its proposal files, in the job's environment, so the calls carry the
// job's id and are checked as the agent's are. Once recorded the job is Done; a refusal is
// returned as propose said it, and the job left as it was. Nothing is researched again.
func (r *Runner) Record(ctx context.Context, id string) (Job, error) {
	job, err := r.load(id)
	if err != nil {
		return job, err
	}
	switch {
	case job.Status != NotRecorded:
		return job, fmt.Errorf("the job is %s, not %s", job.Status, NotRecorded)
	case r.cfg.Bin == "":
		return job, errors.New("this server can't run propose: it doesn't know its own binary")
	}
	o := r.Output(job)
	if o == nil || o.Proposal == nil {
		return job, errors.New("the agent wrote no proposal with a verdict to record")
	}
	args := append([]string{"claims", "agent", "propose", "--name", cmp.Or(job.Run, r.cfg.Run), "--gate", job.Gate}, proposals(filepath.Join(r.cfg.Dir, o.Dir))...)
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.cfg.Bin, args...) //nolint:gosec // G204: this binary, the job's own files
	cmd.Dir = r.cfg.Dir
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
	job.Status, job.Error = Done, ""
	if err := r.save(job); err != nil {
		return job, err
	}
	return job, nil
}
