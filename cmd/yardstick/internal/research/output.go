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
	"strconv"
	"strings"
	"time"
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
	if s == "" || s == "." || s == ".." {
		return ""
	}
	return s
}

// purlName is the plugin's PURL_RE (yardstick_common.py) up to the name: one optional namespace
// segment, then the name up to the version, qualifiers or subpath. A Go module keeps the path past
// its first segment in the name (golang.org/x/net names "x/net"), as the plugin's parse_purl does.
var purlName = regexp.MustCompile(`^pkg:[^/]+/(?:[^/]+/)?([^@?#]+)`)

// packageDir is the plugin's directory for a package: safe_part of parse_purl's name, the purl
// itself when it doesn't parse, "all" with none.
func packageDir(purl string) string {
	name := purl
	if m := purlName.FindStringSubmatch(purl); m != nil {
		name = unquote(m[1])
	}
	if name == "" {
		name = "all"
	}
	return safePart(name)
}

// unquote decodes %XX escapes as Python's urllib.parse.unquote does: a malformed escape is left as
// it is, and the bytes are read as UTF-8. Invalid UTF-8 becomes U+FFFD, one per run here where
// Python may give several; either way safePart makes each "_", so only such a name's length differs.
func unquote(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b = append(b, byte(v))
				i += 2
				continue
			}
		}
		b = append(b, s[i])
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

// OutputDir is where the job's agent writes its report and proposal, relative to the workspace, as
// the plugin's yardstick-vuln-sources.py names it; empty when the plugin would refuse the name.
func OutputDir(job Job) string {
	vuln, name := safePart(job.Vulnerability), packageDir(job.Package)
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
// report's text, and the proposal when it holds a verdict (the plugin writes it first as a skeleton
// with none). The directory is the vulnerability's and package's, with no subject, so another
// job's agent can write there too: a report or proposal counts only when written since this run
// started, and a proposal only when it is about one of this job's rows. OtherRow is the row a
// proposal there names instead, another finding's research.
type Output struct {
	Dir      string   `json:"dir"`
	Files    []string `json:"files"`
	Report   string   `json:"report,omitempty"`
	Proposal *Written `json:"proposal,omitempty"`
	OtherRow string   `json:"otherRow,omitempty"`
}

// Output reads what the job's agent wrote; nil when it has no output directory.
func (r *Runner) Output(job Job) *Output {
	rel := OutputDir(job)
	if rel == "" {
		return nil
	}
	out := &Output{Dir: rel, Files: []string{}}
	dir := filepath.Join(r.cfg.Dir, rel)
	// this run's: written since it started
	ours := func(name string) bool {
		info, err := os.Stat(filepath.Join(dir, name))
		if err == nil {
			out.Files = append(out.Files, name)
		}
		return err == nil && !info.ModTime().Before(job.Started)
	}
	report, proposal := ours(Report), ours(ProposalFile)
	if proposal {
		var w struct {
			Written
			Row string `json:"row"`
		}
		data, err := os.ReadFile(filepath.Join(dir, ProposalFile))
		switch {
		case err != nil || json.Unmarshal(data, &w) != nil:
		case w.Row != "" && !slices.Contains(job.Rows, w.Row):
			out.OtherRow = w.Row
		case w.Row != "" && w.Verdict != "":
			out.Proposal = &w.Written
		}
	}
	if report && out.OtherRow == "" {
		if data, err := readCapped(filepath.Join(dir, Report)); err == nil {
			out.Report = string(data)
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

// Record records the proposal the job's agent wrote but didn't record, as it would have: this
// yardstick's `claims agent propose` on proposal.json, in the job's environment, so the call carries
// the job's id and is checked as the agent's are. It records exactly what Output shows: this run's
// proposal, about one of the job's rows. The job is judged as Jobs reads it, so one from before
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
	o := r.Output(job)
	if o == nil || o.Proposal == nil {
		return job, errors.New("this run wrote no proposal with a verdict about its rows to record")
	}
	args := []string{"claims", "agent", "propose", "--name", cmp.Or(job.Run, r.cfg.Run), "--gate", job.Gate, filepath.Join(r.cfg.Dir, o.Dir, ProposalFile)}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.cfg.Bin, args...) //nolint:gosec // G204: this binary, the job's own file
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
