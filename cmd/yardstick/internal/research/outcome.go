package research

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// A job whose command exited 0 has done its research, but a person sees it only once the agent
// recorded a call: a job that recorded nothing says so (NotRecorded), and why.

// JobDirEnv names the job's directory for the commands the agent runs; ProposeErrorFile is where
// `yardstick claims agent propose` leaves its refusal in it.
const (
	JobDirEnv        = "YARDSTICK_RESEARCH_JOB_DIR"
	ProposeErrorFile = "propose-error.txt"
)

// summaryWidth caps the agent's last message a job keeps.
const summaryWidth = 4000

// denial is one tool use the agent was refused, as claude's result line lists it.
type denial struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
}

// ending is how the agent ended, from the last result line of its log: the tool uses it was
// refused, and its last message.
type ending struct {
	Denials []denial
	Text    string
}

func readEnding(path string) ending {
	data, err := os.ReadFile(path)
	if err != nil {
		return ending{}
	}
	var out ending
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		var r struct {
			Type    string   `json:"type"`
			Result  string   `json:"result"`
			Denials []denial `json:"permission_denials"`
		}
		if !bytes.HasPrefix(line, []byte("{")) || json.Unmarshal(line, &r) != nil || r.Type != resultType {
			continue
		}
		out = ending{Denials: r.Denials, Text: r.Result}
	}
	return out
}

// recorded says whether the job recorded a call since it started, a rerun having the id of the run
// before it. With no Recorded, or an error asking, exiting 0 is taken as recorded, as before.
func (r *Runner) recorded(job *Job) bool {
	if r.cfg.Recorded == nil {
		return true
	}
	at, err := r.cfg.Recorded()
	return err != nil || recordedSince(at, job)
}

func recordedSince(at map[string]time.Time, job *Job) bool {
	t, ok := at[job.ID]
	return ok && !t.Before(job.Started)
}

// reconcile reads a done job that recorded nothing as NotRecorded, saying why from its log, as a
// job that finished before yardstick told the two apart: its record still says done. It asks
// Recorded once for all of them.
func (r *Runner) reconcile(jobs []Job) {
	if r.cfg.Recorded == nil || !slices.ContainsFunc(jobs, func(j Job) bool { return j.Status == Done }) {
		return
	}
	at, err := r.cfg.Recorded()
	if err != nil {
		return
	}
	for i := range jobs {
		j := &jobs[i]
		if j.Status != Done || recordedSince(at, j) {
			continue
		}
		end := readEnding(r.LogPath(j.ID))
		j.Status, j.Error = NotRecorded, r.whyNotRecorded(j, end)
		if j.Summary == "" {
			j.Summary = summary(end.Text)
		}
	}
}

// whyNotRecorded says why a job that exited 0 recorded nothing: propose's refusal when it left one,
// else the tool uses the agent was refused, else that it never proposed.
func (r *Runner) whyNotRecorded(job *Job, end ending) string {
	if data, err := os.ReadFile(filepath.Join(r.jobs, job.ID, ProposeErrorFile)); err == nil {
		if msg := strings.TrimSpace(ansi.ReplaceAllString(string(data), "")); msg != "" {
			return "propose refused it: " + msg
		}
	}
	if n := len(end.Denials); n > 0 {
		// the refusals that kept a call from being recorded first: a write, or propose itself
		denials := slices.Clone(end.Denials)
		slices.SortStableFunc(denials, func(a, b denial) int { return b.blocksRecording() - a.blocksRecording() })
		shown := make([]string, 0, 3)
		for _, d := range denials[:min(n, 3)] {
			shown = append(shown, d.String())
		}
		more := ""
		if n > len(shown) {
			more = fmt.Sprintf(" and %d more", n-len(shown))
		}
		return fmt.Sprintf("the agent was refused %d tool %s: %s%s", n, plural(n, "use", "uses"), strings.Join(shown, "; "), more)
	}
	return "the agent ended without proposing"
}

// ansi is a terminal color sequence, as the CLI's log lines carry
var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// blocksRecording is 1 for a refusal that keeps a call from being recorded: a write, or running
// propose; else 0.
func (d denial) blocksRecording() int {
	cmd, _ := d.ToolInput["command"].(string)
	if d.ToolName == "Write" || d.ToolName == "Edit" || strings.Contains(cmd, "claims agent propose") || strings.Contains(cmd, "cat >") {
		return 1
	}
	return 0
}

// String is the tool and what it was asked to do, shortened: "Write .yardstick/research/…/REPORT.md".
func (d denial) String() string {
	for _, k := range toolKeys {
		if v, ok := d.ToolInput[k].(string); ok && v != "" {
			v = strings.Join(strings.Fields(v), " ")
			if len(v) > 80 {
				v = v[:79] + "…"
			}
			return d.ToolName + " " + v
		}
	}
	return d.ToolName
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// summary is the agent's last message, trimmed to what a job keeps.
func summary(text string) string {
	text = strings.TrimSpace(text)
	if len(text) > summaryWidth {
		text = text[:summaryWidth] + "…"
	}
	return text
}

// conclude is the status of a job whose command exited 0: Done once it recorded a call, else
// NotRecorded, with why in its Error. It keeps the agent's last message either way.
func (r *Runner) conclude(job *Job) (Status, error) {
	end := readEnding(r.LogPath(job.ID))
	job.Summary = summary(end.Text)
	if r.recorded(job) {
		return Done, nil
	}
	return NotRecorded, errors.New(r.whyNotRecorded(job, end))
}
