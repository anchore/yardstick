package labelserver

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
)

// Where a hint came from (hintSummary.Origin).
const (
	OriginLabelUI     = "label-ui"     // a research job a person started here
	OriginResearchJob = "research-job" // a research job this server has no record of starting here
	OriginSkillRun    = "skill-run"    // no research job: a skill run on its own, e.g. triage-deltas
)

// Research levels (stateRow.ResearchLevel), Will 2026-10-13: three levels of "researched".
const (
	LevelNone       = ""           // no agent hint from either skill, no research-vuln run
	LevelTriaged    = "triaged"    // a triage-deltas (or other agent) hint, no research-vuln output
	LevelResearched = "researched" // research-vuln output exists, however it was started
)

// ResearchSummary is the newest research job covering a row.
type ResearchSummary struct {
	Job      string          `json:"job"`
	Status   research.Status `json:"status"`
	Error    string          `json:"error,omitempty"`
	Started  time.Time       `json:"started,omitzero"`
	Finished time.Time       `json:"finished,omitzero"`
	Queued   time.Time       `json:"queued,omitzero"`
	LastDone time.Time       `json:"lastDone,omitzero"`
	Model    string          `json:"model,omitempty"`
	Source   string          `json:"source,omitempty"`
	Batch    string          `json:"batch,omitempty"`
	// Cancellable is true for jobs this server started and is still running or holding.
	Cancellable    bool `json:"cancellable,omitempty"`
	SurvivingGroup int  `json:"survivingGroup,omitempty"`
	// Position is the job's place in the runner's queue while it waits (1 starts next), of
	// QueueLength jobs waiting; both zero otherwise.
	Position    int `json:"position,omitempty"`
	QueueLength int `json:"queueLength,omitempty"`
}

// researchIndex is every research job, by what the state API says about rows.
type researchIndex struct {
	all      []research.Job // newest first
	newest   map[string]*ResearchSummary
	finished map[string]bool // a job finished on the row, now or before, with or without a hint
	byRow    map[string][]research.Job
	byID     map[string]research.Job
	position map[string]int // queuePositions
}

// researchIndex reads the jobs; it is empty when there is no runner.
func (s *Server) researchIndex() (*researchIndex, error) {
	idx := &researchIndex{newest: map[string]*ResearchSummary{}, finished: map[string]bool{},
		byRow: map[string][]research.Job{}, byID: map[string]research.Job{}, position: map[string]int{}}
	if s.opts.Research == nil {
		return idx, nil
	}
	all, err := s.opts.Research.Jobs() // newest first
	if err != nil {
		return nil, err
	}
	idx.all, idx.position = all, queuePositions(s.opts.Research, all)
	for _, j := range all {
		idx.byID[j.ID] = j
		for _, id := range j.Rows {
			idx.byRow[id] = append(idx.byRow[id], j)
			if j.Researched() {
				idx.finished[id] = true
			}
			if _, seen := idx.newest[id]; !seen {
				idx.newest[id] = &ResearchSummary{Job: j.ID, Status: j.Status, Error: j.Error, Started: j.Started, Finished: j.Finished,
					Queued: j.Queued, LastDone: j.LastDone, Model: j.Model, Source: j.Source, Batch: j.Batch,
					Cancellable: j.Status.Active() && s.opts.Research.Cancellable(j.ID), SurvivingGroup: j.SurvivingGroup,
					Position: idx.position[j.ID], QueueLength: map[bool]int{true: len(idx.position)}[idx.position[j.ID] > 0]}
			}
		}
	}
	return idx, nil
}

// queuePositions numbers the queued jobs this process holds, 1-based, in the order it starts them:
// the order they were queued.
// ponytail: queue order is the order the jobs' goroutines block on the runner's slots, which Go
// serves first come first served in practice but doesn't promise
func queuePositions(r *research.Runner, all []research.Job) map[string]int {
	var waiting []research.Job
	for _, j := range all {
		if j.Status == research.Queued && r.Cancellable(j.ID) {
			waiting = append(waiting, j)
		}
	}
	slices.SortStableFunc(waiting, func(a, b research.Job) int { return a.Queued.Compare(b.Queued) })
	out := map[string]int{}
	for i, j := range waiting {
		out[j.ID] = i + 1
	}
	return out
}

// active is true while a research job covering the row is queued or running.
func (idx *researchIndex) active(rowID string) bool {
	for _, j := range idx.byRow[rowID] {
		if j.Status.Active() {
			return true
		}
	}
	return false
}

// isResearchSkill is true for research-vuln, plugin-namespaced or not.
func isResearchSkill(skill string) bool {
	return strings.TrimPrefix(skill, "yardstick:") == "research-vuln"
}

// rowResearchLevel is the highest level the row has reached: researched once a research job on it
// finished or research-vuln left a hint, triaged with any other agent hint or a cause listing it.
func (v *view) rowResearchLevel(idx *researchIndex, rowID string) string {
	if idx.finished[rowID] {
		return LevelResearched
	}
	skills := v.researchedBy(rowID)
	if slices.ContainsFunc(skills, isResearchSkill) {
		return LevelResearched
	}
	if len(skills) > 0 || v.hints[rowID] != nil || len(v.rowCauses[rowID]) > 0 {
		return LevelTriaged
	}
	return LevelNone
}

// researchedBy is the skills of the row's hint and of the causes listing it, sorted. Unlike
// delta, superseded proposals are not consulted: the agent store keeps only the newest.
func (v *view) researchedBy(rowID string) []string {
	var out []string
	add := func(skill string) {
		if skill != "" && !slices.Contains(out, skill) {
			out = append(out, skill)
		}
	}
	if h := v.hints[rowID]; h != nil {
		add(h.Proposal.Author.Skill)
	}
	for _, cv := range v.rowCauses[rowID] {
		add(cv.Author.Skill)
	}
	slices.Sort(out)
	return out
}

// hintOrigin says where a hint came from, and the research job that recorded it, if any: the job
// it names, else a job on the row that was running when it was written.
func hintOrigin(idx *researchIndex, rowID string, p agentstore.Proposal) (origin, job string) {
	j, ok := idx.byID[p.Author.ResearchJob]
	if !ok && p.Author.ResearchJob == "" {
		for _, c := range idx.byRow[rowID] {
			if !c.Started.IsZero() && !p.Timestamp.Before(c.Started) && (c.Finished.IsZero() || !p.Timestamp.After(c.Finished)) {
				j, ok = c, true
				break
			}
		}
	}
	switch {
	case !ok && p.Author.ResearchJob != "":
		return OriginResearchJob, p.Author.ResearchJob
	case !ok:
		return OriginSkillRun, ""
	case j.Source == research.FromLabelUI:
		return OriginLabelUI, j.ID
	}
	return OriginResearchJob, j.ID
}

// ResearchRequest is the body of POST .../research (and, rows only, of .../research/cancel): rows,
// or a selection the server resolves, as in delta:
//
//	{"rows": ["<row id>", ...], "from": "table"}
//	{"select": "no-hint"}            open rows with no agent hint at all
//	{"select": "could-move-check", "subject": "<slug>", "limit": 10, "dryRun": true}
//
// A selection takes only open rows not yet researched with nothing queued or running; there is
// deliberately no "all". Rows given that a job is already queued or running on are skipped. Sibling
// packages (same alias group and source package) share a job. From is the screen asking (table or
// finding), recorded on the jobs.
type ResearchRequest struct {
	Rows    []string `json:"rows"`
	Select  string   `json:"select,omitempty"`
	Subject string   `json:"subject,omitempty"`
	Limit   int      `json:"limit,omitempty"`
	DryRun  bool     `json:"dryRun,omitempty"`
	From    string   `json:"from,omitempty"`
}

// ResearchResponse is what a start queued: the jobs, the rows they cover (Matches), and the rows
// given that were skipped because a job on them is already queued or running. A start of more
// than one row shares one batch id.
type ResearchResponse struct {
	Jobs    []string `json:"jobs"`
	Matches int      `json:"matches"`
	Queued  int      `json:"queued"`
	Skipped int      `json:"skipped"`
	Batch   string   `json:"batch,omitempty"`
}

// Where in the label UI research was started (research.Job.From).
const (
	FromResearchPage = "research"
	FromTable        = "table"
	FromFinding      = "finding"
)

const (
	selectNoHint         = "no-hint"
	selectCouldMoveCheck = "could-move-check"
)

// researchReady writes the error response when research cannot start here.
func (s *Server) researchReady(w http.ResponseWriter) bool {
	switch a := s.opts.ResearchAvailability; {
	case s.opts.Research == nil:
		http.Error(w, "research isn't configured", http.StatusNotImplemented)
	case !a.Available:
		msg := "research is unavailable: " + a.Reason
		if a.Command != "" {
			msg += "; run: " + a.Command
		}
		http.Error(w, msg, http.StatusServiceUnavailable)
	default:
		return true
	}
	return false
}

func (s *Server) handleResearch(w http.ResponseWriter, req *http.Request) {
	if !s.researchReady(w) {
		return
	}
	var body ResearchRequest
	if !decode(w, req, &body) {
		return
	}
	e, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	rows := body.Rows
	switch {
	case body.Select != "" && len(body.Rows) > 0:
		http.Error(w, "give either rows or select, not both", http.StatusBadRequest)
		return
	case body.Select != "":
		var status int
		var err error
		if rows, status, err = s.selectForResearch(e, v, body); err != nil {
			http.Error(w, err.Error(), status)
			return
		}
	case len(body.Rows) == 0:
		http.Error(w, "nothing to research: give rows or select", http.StatusBadRequest)
		return
	}
	if body.From != "" && body.From != FromTable && body.From != FromFinding {
		http.Error(w, fmt.Sprintf("from must be %q or %q, got %q", FromTable, FromFinding, body.From), http.StatusBadRequest)
		return
	}
	idx, err := s.researchIndex()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	asked := len(rows)
	rows = slices.DeleteFunc(slices.Clone(rows), idx.active)
	requests, err := research.Requests(v.verdict, rows)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := ResearchResponse{Jobs: []string{}, Matches: len(rows), Queued: len(requests), Skipped: asked - len(rows)}
	if body.DryRun || len(requests) == 0 {
		writeJSON(w, out)
		return
	}
	for i := range requests {
		requests[i].Gate, requests[i].Source, requests[i].From = e.name, research.FromLabelUI, body.From
	}
	if out.Batch, out.Jobs, err = s.start(requests, asked > 1); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

// selectForResearch resolves a selection to row ids, with the status to answer with when it can't.
func (s *Server) selectForResearch(e *entry, v *view, body ResearchRequest) ([]string, int, error) {
	if body.Select != selectNoHint && body.Select != selectCouldMoveCheck {
		return nil, http.StatusBadRequest, fmt.Errorf("select must be %q or %q, got %q", selectNoHint, selectCouldMoveCheck, body.Select)
	}
	if body.Select == selectCouldMoveCheck && (v.stale != "" || len(e.gate.Checks) == 0) {
		why := v.stale
		if why == "" {
			why = "it has no checks"
		}
		return nil, http.StatusConflict, fmt.Errorf("no match in gate %s could move a check: %s", e.name, why)
	}
	idx, err := s.researchIndex()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	si := -1 // every subject
	if body.Subject != "" {
		if si = slices.IndexFunc(summarize(e, v).Subjects, func(sub SubjectInfo) bool { return sub.Slug == body.Subject }); si < 0 {
			return nil, http.StatusNotFound, fmt.Errorf("no subject %q in gate %s", body.Subject, e.name)
		}
	}
	var flips, narrows []string
	for _, r := range v.orderedRows() {
		id := r.match.Row
		if (si >= 0 && r.si != si) || !r.open() || idx.active(id) {
			continue
		}
		if lvl := v.rowResearchLevel(idx, id); lvl == LevelResearched || (body.Select == selectNoHint && lvl != LevelNone) {
			continue
		}
		if body.Select == selectNoHint {
			narrows = append(narrows, id)
			continue
		}
		switch eff := v.effectOf(id); {
		case eff == nil:
		case len(eff.CouldFlip) > 0:
			flips = append(flips, id)
		default:
			narrows = append(narrows, id)
		}
	}
	ids := slices.Concat(flips, narrows)
	if body.Limit > 0 && len(ids) > body.Limit {
		ids = ids[:body.Limit]
	}
	return ids, http.StatusOK, nil
}

type NotCancelled struct {
	Job string `json:"job"`
	Why string `json:"why"`
}

// handleCancelResearch cancels the newest research job of each given row, when this server is
// running or holding it. The job records Cancelled itself as it stops.
func (s *Server) handleCancelResearch(w http.ResponseWriter, req *http.Request) {
	if s.opts.Research == nil {
		http.Error(w, "research isn't configured", http.StatusNotImplemented)
		return
	}
	var body ResearchRequest
	if !decode(w, req, &body) {
		return
	}
	if s.gateFor(w, req) == nil {
		return
	}
	all, err := s.opts.Research.Jobs() // newest first
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cancelled, refused := []string{}, []NotCancelled{}
	seen := map[string]bool{}
	for _, row := range body.Rows {
		i := slices.IndexFunc(all, func(j research.Job) bool { return slices.Contains(j.Rows, row) })
		switch {
		case i < 0:
			refused = append(refused, NotCancelled{row, "no research for this row"})
		case seen[all[i].ID]:
		case !all[i].Status.Active():
			seen[all[i].ID] = true
			refused = append(refused, NotCancelled{all[i].ID, fmt.Sprintf("not running (%s)", all[i].Status)})
		default:
			seen[all[i].ID] = true
			if err := s.opts.Research.Cancel(all[i].ID); err != nil {
				refused = append(refused, NotCancelled{all[i].ID, err.Error()})
			} else {
				cancelled = append(cancelled, all[i].ID)
			}
		}
	}
	writeJSON(w, CancelResponse{cancelled, refused})
}

// handleResearchLog serves the end of a job's log.
func (s *Server) handleResearchLog(w http.ResponseWriter, req *http.Request) {
	if s.opts.Research == nil {
		http.Error(w, "research isn't configured", http.StatusNotImplemented)
		return
	}
	jobs, err := s.opts.Research.Jobs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// only jobs on disk, by their own id: the request's id never becomes a path
	i := slices.IndexFunc(jobs, func(j research.Job) bool { return j.ID == req.PathValue("id") })
	if i < 0 {
		http.Error(w, "no such job", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(s.opts.Research.LogPath(jobs[i].ID))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	const tail = 64 << 10
	if len(data) > tail {
		data = data[len(data)-tail:]
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// CancelResponse is the answer to cancelling research: the jobs cancelled, and why others were not.
type CancelResponse struct {
	Cancelled    []string       `json:"cancelled"`
	NotCancelled []NotCancelled `json:"notCancelled"`
}
