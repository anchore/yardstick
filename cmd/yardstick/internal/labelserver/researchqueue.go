package labelserver

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"math"
	"net/http"
	"slices"
	"time"

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
// one research is configured with.
type ResearchQueueRequest struct {
	Scope  string   `json:"scope,omitempty"` // all, gate:<name> or image:<slug>, as the queue's
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
// that row first), researched under Gate.
type ResearchJobPlan struct {
	Vulnerability string      `json:"vulnerability"`
	Package       PackageInfo `json:"package"`
	Image         string      `json:"image"`
	Gate          string      `json:"gate"`
	Rows          []string    `json:"rows"`
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
	scope, ok := parseScope(body.Scope)
	if !ok {
		http.Error(w, "scope must be all, gate:<name> or image:<slug>", http.StatusBadRequest)
		return
	}
	if len(body.Groups) == 0 {
		body.Groups = []string{researchChange}
	}
	selected := map[string]bool{}
	for _, g := range body.Groups {
		if g != researchChange && g != researchNone {
			http.Error(w, fmt.Sprintf("groups are %q and %q, got %q", researchChange, researchNone, g), http.StatusBadRequest)
			return
		}
		selected[g] = true
	}
	model := cmp.Or(body.Model, s.opts.Research.Model())
	if err := research.CheckModel(model); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b, err := s.joinGates()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idx, err := s.researchIndex()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := ResearchQueueResponse{Concurrency: s.opts.Research.Concurrency()}
	cands, open := b.researchCandidates(idx, scope, &out.Skipped)
	groups, start, err := b.planResearch(cands, open, selected, body.Limit, model)
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
	if out.Batch, out.Jobs, err = s.startBatch(start); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

// startBatch starts the jobs under one new batch id.
func (s *Server) startBatch(start []planned) (string, []string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	id, jobs := hex.EncodeToString(b), []string{}
	for _, p := range start {
		p.req.Batch = id
		job, err := s.opts.Research.Start(s.ctx, p.req)
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
// queue's order, and the set of them by id; skipped counts the rest.
func (b *queueBuild) researchCandidates(idx *researchIndex, scope queueScope, skipped *ResearchSkipped) ([]researchCandidate, map[string]bool) {
	var cands []researchCandidate
	open := map[string]bool{}
	for _, id := range b.j.order {
		// low keeps every hint on the entry, so a low-confidence one still counts as a hint
		q, ok := b.entry(id, scope, true)
		if !ok {
			continue
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
		c := researchCandidate{queued: q, group: researchNone, gate: b.researchGate(&q.CrossFinding, scope)}
		if q.Effect == effectDecides || q.Effect == effectCouldMove {
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
// start is the selected jobs, up to limit.
func (b *queueBuild) planResearch(cands []researchCandidate, open, selected map[string]bool, limit int, model string) ([]ResearchGroup, []planned, error) {
	groups := []string{researchChange, researchNone}
	if !selected[researchChange] {
		groups = []string{researchNone, researchChange}
	}
	var out []ResearchGroup
	var start []planned
	covered := map[string]bool{}
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
			r.Gate, r.Source, r.Model = c.gate, research.FromLabelUI, model
			pkg := v.rows[c.Row].pm.Package
			p := planned{ResearchJobPlan{Vulnerability: r.Vulnerability, Package: PackageInfo{Name: pkg.Name, Version: pkg.Version, PURL: r.Package},
				Image: c.Image, Gate: c.gate, Rows: r.Rows}, r}
			for _, id := range r.Rows {
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

// ResearchBatch is GET /api/research/batch: one batch's progress. Spent sums the finished jobs'
// cost; Estimate adds the per-job mean for each job still queued or running, and it and
// SecondsLeft are zero when the model's cost isn't measured.
type ResearchBatch struct {
	ID          string        `json:"id"`
	Started     time.Time     `json:"started"`
	Model       string        `json:"model"`
	Total       int           `json:"total"`
	Done        int           `json:"done"`
	Running     int           `json:"running"`
	Queued      int           `json:"queued"`
	Failed      int           `json:"failed"` // failed, timed out or interrupted
	Cancelled   int           `json:"cancelled"`
	Spent       float64       `json:"spent"`
	Estimate    float64       `json:"estimate"`
	SecondsLeft float64       `json:"secondsLeft"`
	Hints       ResearchHints `json:"hints"`
}

// ResearchHints counts the proposals a batch's jobs recorded, by verdict.
type ResearchHints struct {
	TP      int `json:"tp"`
	FP      int `json:"fp"`
	Unclear int `json:"unclear"`
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
	out := ResearchBatch{ID: jobs[0].Batch, Model: jobs[0].Model, Total: len(jobs), Started: jobs[len(jobs)-1].Queued}
	basis := research.Estimate(all, out.Model)
	byID := map[string]research.Job{}
	var left float64
	for _, j := range jobs {
		byID[j.ID] = j
		if j.Usage != nil {
			out.Spent += j.Usage.CostUSD
		}
		switch j.Status {
		case research.Done:
			out.Done++
		case research.Running:
			out.Running++
			left += max(basis.Seconds-time.Since(j.Started).Seconds(), 0)
		case research.Queued:
			out.Queued++
			left += basis.Seconds
		case research.Cancelled:
			out.Cancelled++
		default:
			out.Failed++
		}
	}
	if active := out.Running + out.Queued; active > 0 && basis.Measured {
		out.Estimate = out.Spent + basis.Mean*float64(active)
		out.SecondsLeft = left / float64(min(active, s.opts.Research.Concurrency()))
	} else if basis.Measured {
		out.Estimate = out.Spent
	}
	if out.Hints, err = s.batchHints(byID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

// batchHints counts the proposals the batch's jobs (by id) recorded.
func (s *Server) batchHints(byID map[string]research.Job) (ResearchHints, error) {
	var out ResearchHints
	proposals, err := s.opts.Store.Proposals.Current()
	if err != nil {
		return out, err
	}
	for _, p := range proposals {
		// a job's id is its first row, so a proposal from an earlier run of it is not this batch's
		if j, ok := byID[p.Author.ResearchJob]; !ok || p.Timestamp.Before(j.Queued) {
			continue
		}
		switch p.Verdict {
		case claimsv1.TP:
			out.TP++
		case claimsv1.FP:
			out.FP++
		case claimsv1.Unclear:
			out.Unclear++
		}
	}
	return out, nil
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
