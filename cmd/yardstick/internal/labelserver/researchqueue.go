package labelserver

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/http"
	"slices"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
)

// The research queue: every open row across the gates that no agent has looked at, grouped by
// what labeling it can do to a gate, priced from the workspace's finished jobs, and started as one
// batch. Rows are the queue's (queue.go), each counted once however many gates it is in.

// what researching a group of rows can do
const (
	researchChange = "change" // decides or could move a check in some gate in scope
	researchNone   = "none"   // only counted, or bears on no check
)

// ResearchQueueRequest is POST /api/research. Groups picks what the estimate covers and Start
// starts (change when empty); Limit caps the jobs, in the queue's order; Model defaults to the
// one research is configured with. Check (with a gate: scope) takes only the rows bearing on that
// check, grouped by what they do to it; Rows takes only those rows, both groups, in place of Groups.
type ResearchQueueRequest struct {
	Scope  string   `json:"scope,omitempty"` // all, gate:<name> or image:<slug>, as the queue's
	Check  string   `json:"check,omitempty"`
	Rows   []string `json:"rows,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Limit  int      `json:"limit,omitempty"`
	Model  string   `json:"model,omitempty"`
	DryRun bool     `json:"dryRun,omitempty"`
}

// ResearchQueueResponse is the plan, and once started the batch and its job ids. Groups always
// holds both groups, selected or not.
type ResearchQueueResponse struct {
	Groups      []ResearchGroup  `json:"groups"`
	Skipped     ResearchSkipped  `json:"skipped"`
	Estimate    ResearchEstimate `json:"estimate"`
	Concurrency int              `json:"concurrency"`
	Batch       string           `json:"batch,omitempty"`
	Jobs        []string         `json:"jobs,omitempty"`
}

// ResearchGroup is one group's jobs in the queue's order. Rows counts the open rows they cover. An
// unselected group's jobs are what selecting it would add.
type ResearchGroup struct {
	Group    string            `json:"group"` // change or none
	Selected bool              `json:"selected"`
	Rows     int               `json:"rows"`
	Jobs     []ResearchJobPlan `json:"jobs"`
}

// ResearchJobPlan is one job a start would queue: the row it starts from and its siblings (Rows,
// that row first), researched under Gate. Matches are the open rows of Rows that research could
// start on, each in one job of the plan, which the research page lists one per row.
type ResearchJobPlan struct {
	Vulnerability string          `json:"vulnerability"`
	Package       PackageInfo     `json:"package"`
	Image         string          `json:"image"`
	ImageSlug     string          `json:"imageSlug"`
	Gate          string          `json:"gate"`
	Rows          []string        `json:"rows"`
	Matches       []ResearchMatch `json:"matches"`
}

// ResearchMatch is one open row of a job, and what labeling it does in scope (the queue's effect,
// or with a check its effect on that check).
type ResearchMatch struct {
	Row           string      `json:"row"`
	Vulnerability string      `json:"vulnerability"`
	Package       PackageInfo `json:"package"`
	Effect        string      `json:"effect"`
}

// ResearchSkipped counts the open rows in scope left out: research finished on them, an agent
// hint or cause already covers them, or a job on them is queued or running.
type ResearchSkipped struct {
	Researched int `json:"researched"`
	Hinted     int `json:"hinted"`
	Active     int `json:"active"`
}

// ResearchEstimate is what starting the selected jobs (up to the limit) would cost: Low, Mean and
// High in USD, tokens in and out, and Seconds at the runner's concurrency, all zero when Basis is
// not measured.
type ResearchEstimate struct {
	Jobs      int            `json:"jobs"`
	Rows      int            `json:"rows"`
	Low       float64        `json:"low"`
	Mean      float64        `json:"mean"`
	High      float64        `json:"high"`
	TokensIn  int            `json:"tokensIn"`
	TokensOut int            `json:"tokensOut"`
	Seconds   float64        `json:"seconds"`
	Basis     research.Basis `json:"basis"`
}

// planned is a job of the plan and the request that starts it.
type planned struct {
	ResearchJobPlan
	req research.Request
}

// handleResearchQueue plans research of the open rows with no research level (no agent hint or
// cause, no finished research) and nothing queued or running, across the gates in scope. Each row
// is researched under the gate where labeling it does the most (then the closest to done), and a
// row another job already covers gets none of its own. Without dryRun it starts the selected jobs
// as one batch.
func (s *Server) handleResearchQueue(w http.ResponseWriter, req *http.Request) {
	if !s.researchReady(w) {
		return
	}
	var body ResearchQueueRequest
	if !decode(w, req, &body) {
		return
	}
	scope, selected, err := body.parse()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	model := cmp.Or(body.Model, s.opts.Research.Model())
	b, err := s.joinGates()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idx := b.j.idx
	var only map[string]string
	switch {
	case len(body.Rows) > 0:
		only = map[string]string{}
		for _, id := range body.Rows {
			only[id] = ""
		}
	case body.Check != "":
		var status int
		if only, status, err = b.checkEffects(scope.gate, body.Check); err != nil {
			http.Error(w, err.Error(), status)
			return
		}
	}
	out := ResearchQueueResponse{Concurrency: s.opts.Research.Concurrency()}
	cands, open := b.researchCandidates(idx, scope, only, &out.Skipped)
	groups, start, err := b.planResearch(cands, open, selected, body.Limit, body.Model)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out.Groups = groups
	basis := research.Estimate(slices.Collect(maps.Values(idx.byID)), model)
	n := float64(len(start))
	out.Estimate = ResearchEstimate{Jobs: len(start), Basis: basis, Low: basis.Min * n, Mean: basis.Mean * n, High: basis.Max * n,
		TokensIn: basis.TokensIn * len(start), TokensOut: basis.TokensOut * len(start),
		Seconds: basis.Seconds * math.Ceil(n/float64(out.Concurrency))}
	for _, p := range start {
		out.Estimate.Rows += openRows(open, p.Rows)
	}
	if body.DryRun || len(start) == 0 {
		writeJSON(w, out)
		return
	}
	reqs := make([]research.Request, 0, len(start))
	for _, p := range start {
		reqs = append(reqs, p.req)
	}
	if out.Batch, out.Jobs, err = s.start(reqs, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

// parse checks the request and says its scope and the groups it selects.
func (body *ResearchQueueRequest) parse() (queueScope, map[string]bool, error) {
	scope, ok := parseScope(body.Scope)
	if !ok {
		return scope, nil, errors.New("scope must be all, gate:<name> or image:<slug>")
	}
	groups := body.Groups
	switch {
	case len(body.Rows) > 0 && (len(groups) > 0 || body.Check != ""):
		return scope, nil, errors.New("give rows, or groups and check, not both")
	case body.Check != "" && scope.gate == "":
		return scope, nil, errors.New("check needs a gate:<name> scope")
	case len(body.Rows) > 0:
		groups = []string{researchChange, researchNone}
	case len(groups) == 0:
		groups = []string{researchChange}
	}
	selected := map[string]bool{}
	for _, g := range groups {
		if g != researchChange && g != researchNone {
			return scope, nil, fmt.Errorf("groups are %q and %q, got %q", researchChange, researchNone, g)
		}
		selected[g] = true
	}
	// a model given here is checked; the configured one (--research-model) is the user's own
	if body.Model != "" {
		if err := research.CheckModel(body.Model); err != nil {
			return scope, nil, err
		}
	}
	return scope, selected, nil
}

// start starts the jobs, under one new batch id when batch is set.
func (s *Server) start(reqs []research.Request, batch bool) (string, []string, error) {
	id := ""
	if batch {
		b := make([]byte, 4)
		if _, err := rand.Read(b); err != nil {
			return "", nil, err
		}
		id = hex.EncodeToString(b)
	}
	jobs := []string{}
	for _, r := range reqs {
		r.Batch = id
		job, err := s.opts.Research.Start(s.ctx, r)
		if err != nil {
			return "", nil, err
		}
		jobs = append(jobs, job.ID)
	}
	return id, jobs, nil
}

// researchCandidate is an open row research may start on: its group (change or none) and the gate
// it is researched under.
type researchCandidate struct {
	queued
	group, gate string
}

// researchCandidates are the open rows in scope with no research level and no active job, in the
// queue's order, and the set of them by id; skipped counts the rest. only, when set, limits them to
// its rows, and an effect it gives a row decides the row's group in place of the row's own.
func (b *queueBuild) researchCandidates(idx *researchIndex, scope queueScope, only map[string]string, skipped *ResearchSkipped) ([]researchCandidate, map[string]bool) {
	var cands []researchCandidate
	open := map[string]bool{}
	for _, id := range b.j.order {
		// low keeps every hint on the entry, so a low-confidence one still counts as a hint
		q, ok := b.entry(id, scope, true)
		if !ok {
			continue
		}
		effect := q.Effect
		if only != nil {
			eff, in := only[id]
			if !in {
				continue
			}
			effect = cmp.Or(eff, effect)
		}
		switch lvl := b.researchLevel(idx, &q.CrossFinding); {
		case idx.active(id):
			skipped.Active++
			continue
		case lvl == LevelResearched:
			skipped.Researched++
			continue
		case lvl != LevelNone:
			skipped.Hinted++
			continue
		}
		q.Effect = cmp.Or(effect, effectNone)
		c := researchCandidate{queued: q, group: researchNone, gate: b.researchGate(&q.CrossFinding, scope)}
		if effect == effectDecides || effect == effectCouldMove {
			c.group = researchChange
		}
		cands = append(cands, c)
		open[id] = true
	}
	slices.SortStableFunc(cands, func(a, b researchCandidate) int {
		return cmp.Or(cmp.Compare(a.tier, b.tier), cmp.Compare(a.rows, b.rows), cmp.Compare(a.queued.gate, b.queued.gate), cmp.Compare(a.si, b.si), cmp.Compare(a.at, b.at))
	})
	return cands, open
}

// checkEffects are the rows bearing on a check of a gate, each with its effect on the check, as
// the check's findings have them; with the status to answer with when there is no such check.
func (b *queueBuild) checkEffects(gate, check string) (map[string]string, int, error) {
	v := b.views[gate]
	if v == nil {
		return nil, http.StatusNotFound, fmt.Errorf("no gate %q", gate)
	}
	i := slices.IndexFunc(v.verdict.Checks, func(c analysis.Check) bool { return c.Name == check })
	if i < 0 {
		return nil, http.StatusNotFound, fmt.Errorf("the gate has no check %s", check)
	}
	out := map[string]string{}
	for _, re := range v.checkRows(v.verdict.Checks[i]) {
		out[re.id] = re.effect
	}
	for _, id := range v.decidingRows(v.verdict.Checks[i]) {
		out[id] = effectDecides
	}
	return out, http.StatusOK, nil
}

// researchGate is the gate in scope where labeling the row does the most, then the closest to done.
func (b *queueBuild) researchGate(f *CrossFinding, scope queueScope) string {
	var best *CrossAppearance
	for i, a := range f.In {
		if scope.has(f, a) && (best == nil || cmp.Or(cmp.Compare(queueRank[appearanceEffect(a)], queueRank[appearanceEffect(*best)]),
			cmp.Compare(b.Gates[b.gateAt[a.Gate]].Rows, b.Gates[b.gateAt[best.Gate]].Rows)) < 0) {
			best = &f.In[i]
		}
	}
	return best.Gate
}

// planResearch makes each candidate not already covered one job, its siblings with it, group by
// group: the selected ones first, so an unselected group shows only what selecting it would add.
// start is the selected jobs, up to limit, on model (empty for the configured one).
func (b *queueBuild) planResearch(cands []researchCandidate, open, selected map[string]bool, limit int, model string) ([]ResearchGroup, []planned, error) {
	groups := []string{researchChange, researchNone}
	if !selected[researchChange] {
		groups = []string{researchNone, researchChange}
	}
	var out []ResearchGroup
	var start []planned
	covered := map[string]bool{}
	byRow := map[string]*researchCandidate{}
	for i := range cands {
		byRow[cands[i].Row] = &cands[i]
	}
	for _, g := range groups {
		grp := ResearchGroup{Group: g, Selected: selected[g], Jobs: []ResearchJobPlan{}}
		for _, c := range cands {
			if c.group != g || covered[c.Row] {
				continue
			}
			v := b.views[c.gate]
			reqs, err := research.Requests(v.verdict, []string{c.Row})
			if err != nil {
				return nil, nil, err
			}
			r := reqs[0]
			r.Gate, r.Source, r.Model, r.From = c.gate, research.FromLabelUI, model, FromResearchPage
			pkg := v.rows[c.Row].pm.Package
			p := planned{ResearchJobPlan{Vulnerability: r.Vulnerability, Package: PackageInfo{Name: pkg.Name, Version: pkg.Version, PURL: r.Package},
				Image: c.Image, ImageSlug: c.slug, Gate: c.gate, Rows: r.Rows, Matches: []ResearchMatch{}}, r}
			for _, id := range r.Rows {
				if m, rr := byRow[id], v.rows[id]; m != nil && rr != nil && !covered[id] {
					p.Matches = append(p.Matches, ResearchMatch{Row: id, Vulnerability: m.Vulnerability, Package: PackageInfo{Name: rr.pm.Package.Name, Version: rr.pm.Package.Version}, Effect: m.Effect})
				}
				covered[id] = true
			}
			grp.Rows += openRows(open, r.Rows)
			grp.Jobs = append(grp.Jobs, p.ResearchJobPlan)
			if grp.Selected && (limit <= 0 || len(start) < limit) {
				start = append(start, p)
			}
		}
		out = append(out, grp)
	}
	slices.SortStableFunc(out, func(a, b ResearchGroup) int { return cmp.Compare(a.Group, b.Group) }) // change, then none
	return out, start, nil
}

// openRows counts the rows that are open in the plan
func openRows(open map[string]bool, rows []string) int {
	n := 0
	for _, id := range rows {
		if open[id] {
			n++
		}
	}
	return n
}

// researchLevel is the row's highest research level over every gate it is in: a cause in one gate
// is enough to call it triaged.
func (b *queueBuild) researchLevel(idx *researchIndex, f *CrossFinding) string {
	rank := map[string]int{LevelNone: 0, LevelTriaged: 1, LevelResearched: 2}
	lvl := LevelNone
	for _, a := range f.In {
		if l := b.views[a.Gate].rowResearchLevel(idx, a.Row); rank[l] > rank[lvl] {
			lvl = l
		}
	}
	return lvl
}

// ResearchProgress is where a set of jobs stands. Spent sums the finished jobs' cost; Estimate adds
// the per-job mean of its model for each job still queued or running, and it and SecondsLeft are
// zero when a job's model's cost isn't measured.
type ResearchProgress struct {
	Total       int     `json:"total"`
	Done        int     `json:"done"`
	Running     int     `json:"running"`
	Queued      int     `json:"queued"`
	Failed      int     `json:"failed"` // failed, timed out or interrupted
	Cancelled   int     `json:"cancelled"`
	Spent       float64 `json:"spent"`
	Estimate    float64 `json:"estimate"`
	SecondsLeft float64 `json:"secondsLeft"`
}

// progress is jobs' progress, estimated from all (every job, for each model's cost) at concurrency.
func progress(all, jobs []research.Job, concurrency int) ResearchProgress {
	out := ResearchProgress{Total: len(jobs)}
	bases := map[string]research.Basis{}
	measured := true
	var left, mean float64
	for _, j := range jobs {
		basis, ok := bases[j.Model]
		if !ok {
			basis = research.Estimate(all, j.Model)
			bases[j.Model] = basis
		}
		measured = measured && basis.Measured
		if j.Usage != nil {
			out.Spent += j.Usage.CostUSD
		}
		switch j.Status {
		case research.Done:
			out.Done++
		case research.Running:
			out.Running++
			left += max(basis.Seconds-time.Since(j.Started).Seconds(), 0)
			mean += basis.Mean
		case research.Queued:
			out.Queued++
			left += basis.Seconds
			mean += basis.Mean
		case research.Cancelled:
			out.Cancelled++
		default:
			out.Failed++
		}
	}
	if !measured {
		return out
	}
	out.Estimate = out.Spent + mean
	if active := out.Running + out.Queued; active > 0 {
		out.SecondsLeft = left / float64(min(active, concurrency))
	}
	return out
}

// ResearchBatch is GET /api/research/batch: one batch's progress.
type ResearchBatch struct {
	ID               string    `json:"id"`
	Started          time.Time `json:"started"`
	Model            string    `json:"model"`
	ResearchProgress `tstype:",extends"`
	Hints            ResearchHints `json:"hints"`
}

// ResearchHints counts the proposals a batch's jobs recorded, by verdict.
type ResearchHints struct {
	TP      int `json:"tp"`
	FP      int `json:"fp"`
	Unclear int `json:"unclear"`
}

func (h *ResearchHints) add(v claimsv1.Verdict) {
	switch v {
	case claimsv1.TP:
		h.TP++
	case claimsv1.FP:
		h.FP++
	case claimsv1.Unclear:
		h.Unclear++
	}
}

// batchJobs is the jobs of batch id, or of the newest batch when id is empty, from all (newest first).
func batchJobs(all []research.Job, id string) []research.Job {
	if id == "" {
		if i := slices.IndexFunc(all, func(j research.Job) bool { return j.Batch != "" }); i >= 0 {
			id = all[i].Batch
		}
	}
	var out []research.Job
	for _, j := range all {
		if id != "" && j.Batch == id {
			out = append(out, j)
		}
	}
	return out
}

// handleResearchBatch answers with a batch's progress (?id=, else the newest batch), or null when
// no batch was ever started.
func (s *Server) handleResearchBatch(w http.ResponseWriter, req *http.Request) {
	if s.opts.Research == nil {
		http.Error(w, "research isn't configured", http.StatusNotImplemented)
		return
	}
	all, err := s.opts.Research.Jobs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := req.URL.Query().Get("id")
	jobs := batchJobs(all, id)
	if len(jobs) == 0 {
		if id != "" {
			http.Error(w, "no such batch", http.StatusNotFound)
			return
		}
		writeJSON(w, nil)
		return
	}
	out := ResearchBatch{ID: jobs[0].Batch, Model: jobs[0].Model, Started: jobs[len(jobs)-1].Queued,
		ResearchProgress: progress(all, jobs, s.opts.Research.Concurrency())}
	hints, err := s.jobHints(all)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, j := range jobs {
		for _, h := range hints[j.ID] {
			out.Hints.add(h.Verdict)
		}
	}
	writeJSON(w, out)
}

// ResearchJobHint is a hint a research job left.
type ResearchJobHint struct {
	ID         string           `json:"id"`
	Verdict    claimsv1.Verdict `json:"verdict"`
	Confidence string           `json:"confidence,omitempty"`
}

// jobHints are the proposals each job recorded, by job id.
func (s *Server) jobHints(all []research.Job) (map[string][]ResearchJobHint, error) {
	proposals, err := s.opts.Store.Proposals.Current()
	if err != nil {
		return nil, err
	}
	byID := map[string]research.Job{}
	for _, j := range all {
		byID[j.ID] = j
	}
	out := map[string][]ResearchJobHint{}
	for _, p := range proposals {
		// a job's id is its first row, so a proposal from an earlier run of it is not this job's
		if j, ok := byID[p.Author.ResearchJob]; ok && !p.Timestamp.Before(j.Queued) {
			out[j.ID] = append(out[j.ID], ResearchJobHint{ID: p.ID, Verdict: p.Verdict, Confidence: p.Confidence})
		}
	}
	return out, nil
}

// ResearchJob is one job on the jobs page: Position is its place in the runner's queue while it
// waits (1 starts next), Hints what it left.
type ResearchJob struct {
	research.Job `tstype:",extends"`
	Position     int               `json:"position,omitempty"`
	Cancellable  bool              `json:"cancellable,omitempty"`
	Hints        []ResearchJobHint `json:"hints"`
}

// ResearchJobs is GET /api/research/jobs: every job, newest first, and where the work in flight
// stands. Summary covers the jobs queued or running and every job of a batch that has one, so a
// running batch's finished jobs count; it is all zero when nothing is active.
type ResearchJobs struct {
	Jobs    []ResearchJob       `json:"jobs"`
	Summary ResearchJobsSummary `json:"summary"`
}

type ResearchJobsSummary struct {
	ResearchProgress `tstype:",extends"`
	Concurrency      int           `json:"concurrency"`
	Hints            ResearchHints `json:"hints"`
}

func (s *Server) handleResearchJobs(w http.ResponseWriter, _ *http.Request) {
	if s.opts.Research == nil {
		http.Error(w, "research isn't configured", http.StatusNotImplemented)
		return
	}
	idx, err := s.researchIndex()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hints, err := s.jobHints(idx.all)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	busy := map[string]bool{} // batches with a job active
	for _, j := range idx.all {
		if j.Status.Active() && j.Batch != "" {
			busy[j.Batch] = true
		}
	}
	out := ResearchJobs{Jobs: []ResearchJob{}, Summary: ResearchJobsSummary{Concurrency: s.opts.Research.Concurrency()}}
	var current []research.Job
	for _, j := range idx.all {
		out.Jobs = append(out.Jobs, ResearchJob{Job: j, Position: idx.position[j.ID], Cancellable: j.Status.Active() && s.opts.Research.Cancellable(j.ID),
			Hints: append([]ResearchJobHint{}, hints[j.ID]...)})
		if j.Status.Active() || busy[j.Batch] {
			current = append(current, j)
			for _, h := range hints[j.ID] {
				out.Summary.Hints.add(h.Verdict)
			}
		}
	}
	out.Summary.ResearchProgress = progress(idx.all, current, out.Summary.Concurrency)
	writeJSON(w, out)
}

// ResearchBatchCancel is the body of POST /api/research/batch/cancel.
type ResearchBatchCancel struct {
	ID string `json:"id"`
}

// handleCancelBatch cancels every job of a batch still queued or running here.
func (s *Server) handleCancelBatch(w http.ResponseWriter, req *http.Request) {
	if s.opts.Research == nil {
		http.Error(w, "research isn't configured", http.StatusNotImplemented)
		return
	}
	var body ResearchBatchCancel
	if !decode(w, req, &body) {
		return
	}
	if body.ID == "" {
		http.Error(w, "no batch given", http.StatusBadRequest)
		return
	}
	all, err := s.opts.Research.Jobs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jobs := batchJobs(all, body.ID)
	if len(jobs) == 0 {
		http.Error(w, "no such batch", http.StatusNotFound)
		return
	}
	out := CancelResponse{Cancelled: []string{}, NotCancelled: []NotCancelled{}}
	for _, j := range jobs {
		if !j.Status.Active() {
			continue
		}
		if err := s.opts.Research.Cancel(j.ID); err != nil {
			out.NotCancelled = append(out.NotCancelled, NotCancelled{j.ID, err.Error()})
		} else {
			out.Cancelled = append(out.Cancelled, j.ID)
		}
	}
	writeJSON(w, out)
}
