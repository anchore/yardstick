// Package research runs an agent in the background to investigate a gate's rows (by default,
// the yardstick plugin's /yardstick:research-vuln skill), ported from delta's. An agent reports
// back by recording a proposal with `yardstick claims agent propose`; yardstick only starts the command
// and tracks the job.
//
// Jobs live on disk under .yardstick/research/jobs/<id>/ (job.json and log.txt).
package research

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// DefaultCommand runs the plugin's research-vuln skill headless, on the configured model
// ($YARDSTICK_MODEL). Values are passed in the environment (see Job.env), never interpolated into
// the command, so a crafted path or ID can't inject shell. stream-json prints one event per line as
// the agent works, so the log is live, and ends in the result line the job's Usage is read from.
//
// The agent reads pages anyone can write, so it gets the tools the skill uses and no more: the two
// yardstick commands it runs, and file writes only under .yardstick/research/ (an Edit path rule
// covers Write too). The skill's own allowed-tools adds its helper script, by the plugin's path,
// which writes only there as well. Its environment is childEnv's.
const DefaultCommand = `claude -p "/yardstick:research-vuln row:$YARDSTICK_ROW $YARDSTICK_ROOT" --model "${YARDSTICK_MODEL:-sonnet}" ` +
	`--allowedTools "Bash(yardstick claims agent propose *),Bash(yardstick claims policy),Bash(yardstick claims policy *),Read,Grep,Glob,Edit(.yardstick/research/**),WebFetch,WebSearch" ` +
	`--output-format stream-json --verbose`

// DefaultModel is the model research runs on unless configured otherwise: a name or alias the
// command understands (for claude, "sonnet", "opus", "haiku" or a full model ID).
const DefaultModel = "sonnet"

// Where a person started a job, recorded as Job.Source (the same convention as a claim's source).
const FromLabelUI = "yardstick claims serve"

type Status string

const (
	Queued      Status = "queued"
	Running     Status = "running"
	Done        Status = "done"         // the command exited 0 and the agent recorded a call
	NotRecorded Status = "not-recorded" // the command exited 0, but the agent recorded no call; Error says why
	Failed      Status = "failed"       // the command exited non-zero, or couldn't start
	TimedOut    Status = "timed-out"
	Interrupted Status = "interrupted" // yardstick stopped while the job was running
	Cancelled   Status = "cancelled"   // a person cancelled it (see Runner.Cancel)
)

// errCancelled is the cause a person's cancel gives a job's context, to tell it apart from
// yardstick shutting down (Interrupted) and the timeout (TimedOut).
var errCancelled = errors.New("cancelled")

func (s Status) Active() bool {
	return s == Queued || s == Running
}

// Job is one research request: the rows of one finding group (they share a vulnerability and a
// source package, so the agent researches them together).
type Job struct {
	ID            string   `json:"id"`
	Rows          []string `json:"rows"`
	Vulnerability string   `json:"vulnerability"`
	Package       string   `json:"package"`
	Gate          string   `json:"gate,omitempty"` // the gate whose scans the rows belong to
	Run           string   `json:"run,omitempty"`  // the run name the gate was scanned under
	Source        string   `json:"source,omitempty"`
	// Model is the model the job runs on (Request.Model, else Config.Model when it was queued).
	Model string `json:"model,omitempty"`
	// Batch is the id shared by the jobs one start of many created, empty for a job started alone.
	Batch string `json:"batch,omitempty"`
	// From is the screen of Source a person started it from (the label UI's research page, a
	// findings table or a finding), empty when not known.
	From     string    `json:"from,omitempty"`
	Status   Status    `json:"status"`
	Error    string    `json:"error,omitempty"`
	Command  string    `json:"command"`
	Dir      string    `json:"dir"` // working directory the command ran in
	Queued   time.Time `json:"queued"`
	Started  time.Time `json:"started,omitzero"`
	Finished time.Time `json:"finished,omitzero"`
	// LastDone is when research of this group last finished (Done or NotRecorded), in this run or an earlier one.
	// A rerun replaces the job's record, and a rerun that fails or is still running doesn't undo
	// that the rows were researched.
	LastDone time.Time `json:"lastDone,omitzero"`
	// SurvivingGroup is the process group of a cancelled, timed-out or interrupted job when something
	// in it was still alive after the command exited (e.g. a sandbox refused to signal the agent),
	// so a person can stop it; Error says how.
	SurvivingGroup int `json:"survivingGroup,omitempty"`
	// Usage is what the run cost, from the result line the command printed last; nil when it printed none.
	Usage *Usage `json:"usage,omitempty"`
	// Summary is the agent's last message, from that line: what it concluded, even when it recorded nothing.
	Summary string `json:"summary,omitempty"`
}

// Config is how research runs.
type Config struct {
	Command     string        // run with `sh -c`
	Model       string        // given to the command as YARDSTICK_MODEL (default DefaultModel)
	Dir         string        // the workspace: holds .yardstick, and the command runs in it
	Run         string        // the run name, given as YARDSTICK_NAME
	Concurrency int           // how many jobs run at once
	Timeout     time.Duration // per job
	Bin         string        // this yardstick binary, for the agent to call back with
	// Recorded is when each job last recorded a call (a proposal or cause stamped with its id); a
	// job that exited 0 with none since it started is NotRecorded. Nil takes exiting 0 as recorded.
	Recorded func() (map[string]time.Time, error)
}

// Runner queues jobs and runs up to Concurrency at a time.
type Runner struct {
	cfg  Config
	jobs string // .yardstick/research/jobs
	sem  chan struct{}
	mu   sync.Mutex
	live map[string]bool // jobs this process is running or has queued
	// cancels stops each live job; only the job's own goroutine records the result
	cancels map[string]*jobControl
	wg      sync.WaitGroup
}

type jobControl struct {
	cancel context.CancelCauseFunc
}

func NewRunner(cfg Config) *Runner {
	if cfg.Command == "" {
		cfg.Command = DefaultCommand
	}
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Minute
	}
	return &Runner{
		cfg:     cfg,
		jobs:    filepath.Join(cfg.Dir, ".yardstick", "research", "jobs"),
		sem:     make(chan struct{}, cfg.Concurrency),
		live:    map[string]bool{},
		cancels: map[string]*jobControl{},
	}
}

// Request is what to research: a group's rows (the first is the one the agent starts from).
type Request struct {
	Rows          []string
	Vulnerability string
	Package       string
	Gate          string // the gate whose scans the rows belong to
	Source        string // where a person started it
	Model         string // overrides Config.Model when set; see CheckModel
	Batch         string
	From          string // the screen of Source it was started from
}

// Start queues a job and returns at once; the job runs when a slot is free and stops when ctx ends.
// A group that already has an active job isn't queued twice.
func (r *Runner) Start(ctx context.Context, req Request) (Job, error) {
	if len(req.Rows) == 0 {
		return Job{}, errors.New("nothing to research")
	}
	if req.Model != "" {
		if err := CheckModel(req.Model); err != nil {
			return Job{}, err
		}
	}
	id := req.Rows[0]
	r.mu.Lock()
	existing, loadErr := r.load(id)
	if loadErr == nil && existing.Status.Active() && r.live[id] {
		r.mu.Unlock()
		return existing, nil
	}
	job := Job{
		ID:            id,
		Rows:          req.Rows,
		Vulnerability: req.Vulnerability,
		Package:       req.Package,
		Gate:          req.Gate,
		Run:           r.cfg.Run,
		Source:        req.Source,
		Model:         cmp.Or(req.Model, r.cfg.Model),
		Batch:         req.Batch,
		From:          req.From,
		Status:        Queued,
		Command:       r.cfg.Command,
		Dir:           r.cfg.Dir,
		Queued:        time.Now().UTC(),
	}
	if loadErr == nil {
		job.LastDone = existing.LastDone
	}
	if err := r.save(job); err != nil {
		r.mu.Unlock()
		return Job{}, err
	}
	ctx, cancel := context.WithCancelCause(ctx)
	ctl := &jobControl{cancel: cancel}
	r.live[id], r.cancels[id] = true, ctl
	r.mu.Unlock()

	// the goroutine owns job from here on; the caller gets it as queued
	queued := job
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() {
			r.mu.Lock()
			if r.cancels[id] == ctl { // a restart of the same group may have replaced it
				delete(r.live, id)
				delete(r.cancels, id)
			}
			r.mu.Unlock()
			cancel(nil)
		}()
		select {
		case r.sem <- struct{}{}:
		case <-ctx.Done():
			// cancelled or shut down while waiting for a slot: the command never runs
			job.Status, job.Finished = Interrupted, time.Now().UTC()
			if context.Cause(ctx) == errCancelled {
				job.Status = Cancelled
			}
			_ = r.save(job)
			return
		}
		defer func() { <-r.sem }()
		r.run(ctx, &job)
	}()
	return queued, nil
}

// Cancel stops a job this process started, queued or running; its goroutine records Cancelled. Jobs
// started by another yardstick process can't be cancelled from here.
func (r *Runner) Cancel(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctl := r.cancels[id]
	if ctl == nil {
		return errors.New("not running in this process")
	}
	ctl.cancel(errCancelled)
	return nil
}

// Cancellable is true for jobs this process is running or has queued.
func (r *Runner) Cancellable(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cancels[id] != nil
}

// Concurrency is how many jobs run at once.
func (r *Runner) Concurrency() int {
	return r.cfg.Concurrency
}

// Model is the model jobs run on unless a request names another.
func (r *Runner) Model() string {
	return r.cfg.Model
}

// Wait blocks until every job this runner started has finished.
func (r *Runner) Wait() {
	r.wg.Wait()
}

func (r *Runner) run(ctx context.Context, job *Job) {
	job.Status, job.Started = Running, time.Now().UTC()
	_ = r.save(*job)
	log.Infof("research %s: started (%s %s)", job.ID, job.Vulnerability, job.Package)

	// a rerun's refusal is its own: the last run's is no reason this one recorded nothing
	_ = os.Remove(filepath.Join(r.jobs, job.ID, ProposeErrorFile))
	logFile, err := os.Create(filepath.Join(r.jobs, job.ID, "log.txt"))
	if err != nil {
		r.finish(job, Failed, err)
		return
	}
	defer logFile.Close()

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()
	// running the user's configured command is the point; job values reach it only through the
	// environment (see Job.env), never through the command text
	cmd := exec.CommandContext(ctx, "sh", "-c", r.cfg.Command) //nolint:gosec // G204: configured by the user, by design
	cmd.Dir = r.cfg.Dir
	cmd.Env = append(childEnv(os.Environ()), job.env(r.cfg)...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	// stop the whole process group, not just sh: the agent and its children would otherwise outlive a
	// cancel or timeout and keep spending tokens; WaitDelay still forces the kill afterwards
	stopProcessGroup(cmd)
	cmd.WaitDelay = 10 * time.Second
	err = cmd.Run()
	if ctx.Err() != nil {
		job.SurvivingGroup = survivingGroup(cmd)
	}

	switch {
	case context.Cause(ctx) == errCancelled:
		r.finish(job, Cancelled, errCancelled)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		r.finish(job, TimedOut, fmt.Errorf("no result after %s", r.cfg.Timeout))
	case ctx.Err() != nil:
		r.finish(job, Interrupted, ctx.Err())
	case err != nil:
		r.finish(job, Failed, err)
	default:
		// finish reads the log too, which the command is done writing
		s, err := r.conclude(job)
		r.finish(job, s, err)
	}
}

func (r *Runner) finish(job *Job, s Status, err error) {
	job.Status, job.Finished = s, time.Now().UTC()
	job.Usage = readUsage(r.LogPath(job.ID))
	if s == Done || s == NotRecorded {
		job.LastDone = job.Finished
	}
	if err != nil {
		job.Error = err.Error()
	}
	if g := job.SurvivingGroup; g != 0 {
		job.Error = strings.TrimPrefix(job.Error+"; ", "; ") + SurvivorsWarning(g)
		log.Warnf("research %s: %s", job.ID, SurvivorsWarning(g))
	}
	if saveErr := r.save(*job); saveErr != nil {
		log.Warnf("research %s: unable to record the result: %v", job.ID, saveErr)
	}
	log.Infof("research %s: %s", job.ID, s)
}

// SurvivorsWarning says that a job's processes may still be running, and how to stop them.
func SurvivorsWarning(group int) string {
	return fmt.Sprintf("child processes may still be running (process group %d): stop them with %s", group, KillCommand(group))
}

// KillCommand stops a process group.
func KillCommand(groups ...int) string {
	cmd := "kill -TERM --"
	for _, g := range groups {
		cmd += fmt.Sprintf(" -%d", g)
	}
	return cmd
}

// env is what the command gets to work with. YARDSTICK_GATE and YARDSTICK_NAME are what the CLI's
// --gate and --name read, so `yardstick claims agent propose` resolves the job's rows with no flags; the
// vulnerability and package go under RESEARCH_ names because clio would read YARDSTICK_PACKAGE and
// YARDSTICK_VULNERABILITY as `claims add` flags. The binary's directory leads PATH, so `yardstick`
// is this binary.
func (j Job) env(cfg Config) []string {
	env := []string{
		"YARDSTICK_ROW=" + j.Rows[0],
		"YARDSTICK_ROWS=" + strings.Join(j.Rows, " "),
		"YARDSTICK_RESEARCH_VULNERABILITY=" + j.Vulnerability,
		"YARDSTICK_RESEARCH_PACKAGE=" + j.Package,
		"YARDSTICK_GATE=" + j.Gate,
		"YARDSTICK_NAME=" + cmp.Or(j.Run, cfg.Run),
		"YARDSTICK_ROOT=" + cfg.Dir,
		"YARDSTICK_BIN=" + cfg.Bin,
		"YARDSTICK_RESEARCH_JOB=" + j.ID,                                                 // `yardstick claims agent propose` stamps it on the proposals the job records
		JobDirEnv + "=" + filepath.Join(cfg.Dir, ".yardstick", "research", "jobs", j.ID), // and leaves its refusal there
		"YARDSTICK_MODEL=" + cmp.Or(j.Model, cfg.Model),
	}
	if cfg.Bin != "" {
		env = append(env, "PATH="+filepath.Dir(cfg.Bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	return env
}

// childEnv is the part of this process's environment a research command gets: what it needs to run
// and to reach the model, since the agent reads pages anyone can write and a prompt there could ask
// it to print its environment. GITHUB_TOKEN, cloud keys and the like stay behind, except a cloud
// provider's own when Claude Code is set to use that provider.
func childEnv(environ []string) []string {
	keep := []string{"YARDSTICK_", "ANTHROPIC_", "CLAUDE_", "LC_", "XDG_"}
	providers := map[string][]string{
		"CLAUDE_CODE_USE_BEDROCK": {"AWS_"},
		"CLAUDE_CODE_USE_VERTEX":  {"GOOGLE_", "GCLOUD_", "CLOUDSDK_", "CLOUD_ML_REGION", "VERTEX_REGION_"},
		"CLAUDE_CODE_USE_FOUNDRY": {"AZURE_"},
	}
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		if prefixes, ok := providers[k]; ok && v != "" && v != "0" && v != "false" {
			keep = append(keep, prefixes...)
		}
	}
	exact := []string{"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TERM", "LANG", "TZ", "NO_COLOR",
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS"}
	var out []string
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if slices.Contains(exact, k) || slices.ContainsFunc(keep, func(p string) bool { return strings.HasPrefix(k, p) }) {
			out = append(out, kv)
		}
	}
	return out
}

// Researched is true once research of the job's rows has finished, in this run or an earlier one,
// whether or not it left an agent hint.
func (j Job) Researched() bool {
	return j.Status == Done || j.Status == NotRecorded || !j.LastDone.IsZero()
}

// Jobs lists every recorded job, newest first. Jobs left active by a yardstick that is no longer
// running them are reported as interrupted.
func (r *Runner) Jobs() ([]Job, error) {
	entries, err := os.ReadDir(r.jobs)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Job
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		j, err := r.load(e.Name())
		if err != nil {
			continue
		}
		if j.Status.Active() && !r.live[j.ID] && time.Since(j.Queued) > r.cfg.Timeout+time.Minute {
			j.Status = Interrupted
		}
		out = append(out, j)
	}
	r.reconcile(out)
	sort.Slice(out, func(i, k int) bool { return out[i].Queued.After(out[k].Queued) })
	return out, nil
}

// LogPath is where a job's output goes.
func (r *Runner) LogPath(id string) string {
	return filepath.Join(r.jobs, id, "log.txt")
}

func (r *Runner) load(id string) (Job, error) {
	data, err := os.ReadFile(filepath.Join(r.jobs, id, "job.json"))
	if err != nil {
		return Job{}, err
	}
	var j Job
	return j, json.Unmarshal(data, &j)
}

func (r *Runner) save(j Job) error {
	dir := filepath.Join(r.jobs, j.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "job.json.tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "job.json"))
}
