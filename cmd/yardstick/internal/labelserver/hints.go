package labelserver

import (
	"cmp"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
)

// Hint review: every pending hint across the gates, a proposal or a cause, grouped by what
// accepting it alone does to the gates, and accepted many at a time.

// what accepting a hint alone does
const (
	groupDecides = "decides" // some gate's outcome changes
	groupNeeded  = "needed"  // no outcome changes, but it closes rows a gate that is not passing counts
	groupNone    = "none"    // neither
)

var groupRank = map[string]int{groupDecides: 0, groupNeeded: 1, groupNone: 2}

// HintsResponse is GET /api/hints. Low counts the unclear hints left out (low=0): accepting one
// closes nothing, so they stay out of a batch decision unless asked for.
type HintsResponse struct {
	Hints []HintEntry `json:"hints"`
	Low   int         `json:"low"`
}

// HintEntry is one pending hint and the open rows it covers. Group is what labeling only its rows
// with its verdict does (decides, needed or none); Replaces says a covered row already holds a
// label from a claims source, unclear included.
type HintEntry struct {
	HintSummary `tstype:",extends"`
	Kind        string            `json:"kind" tstype:"HintKind"`
	Cause       string            `json:"cause,omitempty"` // a cause's one-line title
	Author      agentstore.Author `json:"author"`
	Note        string            `json:"note,omitempty"`
	Group       string            `json:"group" tstype:"HintGroup"`
	Replaces    bool              `json:"replaces"`
	Rows        []HintRow         `json:"rows"`
	Gates       []HintGate        `json:"gates"`
}

// HintRow is a row a hint covers, with the gates it is in.
type HintRow struct {
	Row           string        `json:"row"`
	Image         ImageRef      `json:"image"`
	Vulnerability string        `json:"vulnerability"`
	Package       PackageInfo   `json:"package"`
	Direction     string        `json:"direction" tstype:"Direction"`
	Label         *FindingLabel `json:"label" tstype:"FindingLabel | null"`
	Gates         []string      `json:"gates"`
}

// HintGate is a gate a hint has rows in: its outcome now, and with only the hint's rows labeled.
type HintGate struct {
	Gate    string         `json:"gate"`
	Rows    []string       `json:"rows"`
	Outcome analysis.State `json:"outcome"`
	After   analysis.State `json:"after"`
}

// summary is a cause as lists show a hint.
func (cv *CauseView) summary() HintSummary {
	out := HintSummary{ID: cv.ID, Verdict: cv.Verdict, Justification: cv.Justification, Confidence: cv.Confidence, Skill: cv.Author.Skill,
		Model: cv.Author.Model, ResearchJob: cv.Author.ResearchJob, Problems: len(cv.Policy.Problems), Status: hintPending, Written: cv.Timestamp}
	if r := cv.Policy.Rule; r != nil {
		out.Rule, out.Decision, out.Title = r.Name, r.Decision, r.Title
	}
	return out
}

// judged is a gate that can be judged, and each row's effect in it (rowEffects).
type judged struct {
	e       *entry
	v       *view
	effects map[string]string
}

// hintSet collects the pending hints across gates, by id in the order first seen.
type hintSet struct {
	order []*HintEntry
	byID  map[string]*HintEntry
}

// add puts a row of gate e under hint id, made by mk when the hint is new.
func (hs *hintSet) add(e *entry, v *view, imgs []ImageRef, id string, mk func() *HintEntry, r *rowRef) {
	h := hs.byID[id]
	if h == nil {
		h = mk()
		hs.byID[id] = h
		hs.order = append(hs.order, h)
	}
	if len(h.Gates) == 0 || h.Gates[len(h.Gates)-1].Gate != e.name {
		h.Gates = append(h.Gates, HintGate{Gate: e.name, Outcome: v.verdict.Outcome})
	}
	hg := &h.Gates[len(h.Gates)-1]
	hg.Rows = append(hg.Rows, r.match.Row)
	if i := slices.IndexFunc(h.Rows, func(x HintRow) bool { return x.Row == r.match.Row }); i >= 0 {
		h.Rows[i].Gates = append(h.Rows[i].Gates, e.name)
		return
	}
	f := v.finding(r, imgs, "")
	h.Rows = append(h.Rows, HintRow{Row: f.Row, Image: f.Image, Vulnerability: f.Vulnerability, Package: f.Package, Direction: f.Direction, Label: f.Label,
		Gates: []string{e.name}})
	h.Replaces = h.Replaces || r.pm.Label != nil
}

// pendingHints are the pending hints over every gate that can be judged, in the order first seen,
// each with its rows per gate.
func (s *Server) pendingHints() ([]*HintEntry, map[string]judged, error) {
	all, err := s.entries()
	if err != nil {
		return nil, nil, err
	}
	hs := &hintSet{byID: map[string]*HintEntry{}}
	gates := map[string]judged{}
	for _, e := range all {
		v, err := s.view(e)
		if err != nil || v.stale != "" {
			continue // nothing to judge a hint against
		}
		gates[e.name] = judged{e, v, v.rowEffects()}
		imgs := images(e, v)
		for _, r := range v.orderedRows() {
			// a proposal pairs any open row; review is about the changes, as the queue is
			if hv := v.hints[r.match.Row]; hv != nil && hv.Status == hintPending && r.changed() {
				hs.add(e, v, imgs, hv.Proposal.ID, func() *HintEntry {
					return &HintEntry{HintSummary: *hv.summary(), Kind: "proposal", Author: hv.Proposal.Author, Note: hv.Proposal.Note}
				}, r)
			}
		}
		for _, cv := range v.causeOrder {
			for _, id := range cv.Rows {
				if v.memberState(cv, id) == memberPending {
					hs.add(e, v, imgs, cv.ID, func() *HintEntry {
						return &HintEntry{HintSummary: cv.summary(), Kind: "cause", Cause: cv.Title, Author: cv.Author, Note: cv.Note}
					}, v.rows[id])
				}
			}
		}
	}
	return hs.order, gates, nil
}

// group is what labeling only the hint's rows with its verdict does, per gate by analysis.EvaluateAs
// as the preview does: decides when a gate's outcome changes, needed when none does but the hint
// closes a row that a gate not passing counts. An unclear verdict closes nothing.
func (h *HintEntry) group(gates map[string]judged) {
	h.Group = groupNone
	closes := h.Verdict == claimsv1.TP || h.Verdict == claimsv1.FP
	for i := range h.Gates {
		hg := &h.Gates[i]
		hg.After = hg.Outcome
		if !closes {
			continue
		}
		g := gates[hg.Gate]
		hyp := map[*pairing.Match]claimsv1.Verdict{}
		for _, id := range hg.Rows {
			hyp[g.v.rows[id].pm] = h.Verdict
		}
		hg.After = analysis.EvaluateAs(g.e.gate.Checks, g.v.paired.Subjects, hyp).Outcome
		switch {
		case hg.After != hg.Outcome:
			h.Group = groupDecides
		case h.Group == groupNone && hg.Outcome != analysis.Pass && slices.ContainsFunc(hg.Rows, func(id string) bool { return g.effects[id] != "" }):
			h.Group = groupNeeded
		}
	}
}

// handleHints answers with every pending hint, filtered by gate= and image= (a slug), unclear ones
// only with low=1. Grouped: decides, needed, none, each in the order first seen.
func (s *Server) handleHints(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	gate, image, low := q.Get("gate"), q.Get("image"), q.Get("low") == "1"
	hints, gates, err := s.pendingHints()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := HintsResponse{Hints: []HintEntry{}}
	for _, h := range hints {
		if (gate != "" && !slices.ContainsFunc(h.Gates, func(g HintGate) bool { return g.Gate == gate })) ||
			(image != "" && !slices.ContainsFunc(h.Rows, func(r HintRow) bool { return r.Image.Slug == image })) {
			continue
		}
		if h.Verdict == claimsv1.Unclear && !low {
			out.Low++
			continue
		}
		h.group(gates)
		out.Hints = append(out.Hints, *h)
	}
	slices.SortStableFunc(out.Hints, func(a, b HintEntry) int { return cmp.Compare(groupRank[a.Group], groupRank[b.Group]) })
	writeJSON(w, out)
}

type HintsAcceptRequest struct {
	Hints []string `json:"hints"`
	// Rows, when given, limits the accept to these rows; a cause's member whose own hint disagrees
	// with it is accepted only when named here.
	Rows []string `json:"rows,omitempty"`
}

// AcceptedLabel is one label a hints accept wrote, the rows it was written for and the gates they
// are in.
type AcceptedLabel struct {
	Hint  string         `json:"hint"`
	File  string         `json:"file"` // corpus-relative, in the gate's writable claims source
	Label claimsv1.Label `json:"label"`
	Rows  []string       `json:"rows"`
	Gates []string       `json:"gates"`
}

type HintsAcceptResponse struct {
	Written []AcceptedLabel `json:"written"`
	Skipped []SkippedRow    `json:"skipped"`
	Labels  []LabelKey      `json:"labels"` // what POST /api/history/revert takes to undo the accept
}

// hintAccept is a hints accept as it is collected: each label once, and every hint seen.
type hintAccept struct {
	HintsAcceptRequest
	author  string
	now     time.Time
	out     HintsAcceptResponse
	found   map[string]bool
	written map[string]int // writable source|file|key to its index in out.Written
}

// put adds the label a hint says for a row to the gate's batch p, unless it was written already.
func (a *hintAccept) put(e *entry, wr claimsv1.Writer, p *pending, hint string, r *rowRef, l claimsv1.Label) error {
	if len(a.Rows) > 0 && !slices.Contains(a.Rows, r.match.Row) {
		return nil
	}
	var one pending
	if err := one.add(e, r, l, false); err != nil {
		return err
	}
	placed := one.placed[0]
	k := wr.Dir + "|" + placed.File + "|" + placed.Label.Key().String()
	i, ok := a.written[k]
	switch {
	case !ok:
		a.written[k] = len(a.out.Written)
		a.out.Written = append(a.out.Written, AcceptedLabel{Hint: hint, File: placed.File, Label: placed.Label, Rows: []string{r.match.Row}})
		p.placed = append(p.placed, placed)
	case a.out.Written[i].Label.Verdict != l.Verdict:
		w := a.out.Written[i]
		a.out.Skipped = append(a.out.Skipped, SkippedRow{r.match.Row, fmt.Sprintf("hint %s says %s, and %s already wrote %s", hint, l.Verdict, w.Hint, w.Label.Verdict)})
	case !slices.Contains(a.out.Written[i].Rows, r.match.Row):
		a.out.Written[i].Rows = append(a.out.Written[i].Rows, r.match.Row)
	}
	return nil
}

// gate is the batch of labels accepting the hints writes in one gate: a proposal's on each changed
// row it is pending on, a cause's on each open member (one whose own hint disagrees only when named).
func (a *hintAccept) gate(e *entry, v *view) (*pending, error) {
	p := &pending{}
	wr, werr := v.set.Writer()
	put := func(hint string, r *rowRef, l claimsv1.Label) error {
		if werr != nil {
			return werr
		}
		return a.put(e, wr, p, hint, r, l)
	}
	for _, r := range v.orderedRows() {
		if h := v.hints[r.match.Row]; h != nil && slices.Contains(a.Hints, h.Proposal.ID) {
			a.found[h.Proposal.ID] = true
			// review lists a proposal on the changes, so seenIn is the setup reporting one
			if h.Status != hintPending || !r.changed() {
				continue
			}
			if err := put(h.Proposal.ID, r, h.Proposal.Label(a.author, a.now)); err != nil {
				return nil, err
			}
		}
	}
	for _, cv := range v.causeOrder {
		if !slices.Contains(a.Hints, cv.ID) {
			continue
		}
		a.found[cv.ID] = true
		for _, id := range cv.Rows {
			r, state := v.rows[id], v.memberState(cv, id)
			if state == memberConflict && len(a.Rows) == 0 {
				a.out.Skipped = append(a.out.Skipped, SkippedRow{id, "its own hint disagrees with cause " + cv.ID})
			}
			if state != memberPending && (state != memberConflict || !slices.Contains(a.Rows, id)) {
				continue
			}
			// the package and vulnerability come from the row, never from the stored member
			if err := put(cv.ID, r, cv.Label(agentstore.Member{Package: r.match.Package, Vulnerability: r.match.Vulnerability}, a.author, a.now)); err != nil {
				return nil, err
			}
		}
	}
	return p, nil
}

// touched fills each written label's gates: every gate its rows are in, by row id.
func (a *hintAccept) touched(rowGates map[string][]string) {
	for i := range a.out.Written {
		l := &a.out.Written[i]
		for _, id := range l.Rows {
			for _, g := range rowGates[id] {
				if !slices.Contains(l.Gates, g) {
					l.Gates = append(l.Gates, g)
				}
			}
		}
	}
}

// handleAcceptHints accepts many hints across gates in one go. Each label is the one the single
// accepts write: a proposal's through Proposal.Label, a cause's per member row through Cause.Label,
// both subject scoped, placed by pending.add. A label is written once however many gates or rows it
// covers (by writable source, file and key), and nothing is written when any label is refused.
func (s *Server) handleAcceptHints(w http.ResponseWriter, req *http.Request) {
	a := &hintAccept{author: s.opts.Author, now: time.Now().UTC(), found: map[string]bool{}, written: map[string]int{},
		out: HintsAcceptResponse{Written: []AcceptedLabel{}, Skipped: []SkippedRow{}, Labels: []LabelKey{}}}
	if !decode(w, req, &a.HintsAcceptRequest) {
		return
	}
	if len(a.Hints) == 0 {
		http.Error(w, "no hints given", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.entries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type gateBatch struct {
		v *view
		p *pending
	}
	var batches []gateBatch
	rowGates := map[string][]string{}
	for _, e := range all {
		v, err := s.view(e)
		if err != nil {
			continue
		}
		for id := range v.rows {
			rowGates[id] = append(rowGates[id], e.name)
		}
		p, err := a.gate(e, v)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		batches = append(batches, gateBatch{v, p})
	}
	for _, id := range a.Hints {
		if !a.found[id] {
			http.Error(w, "no hint "+id+" in any gate", http.StatusBadRequest)
			return
		}
	}
	// check every label before writing any, since each gate's batch is its own write
	for _, gb := range batches {
		wr, _ := gb.v.set.Writer() // put refused any label for a gate without one
		for _, p := range gb.p.placed {
			if err := wr.Check(p); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
	}
	for _, gb := range batches {
		err := s.write(gb.v, gb.p)
		a.out.Labels = append(a.out.Labels, gb.p.keys...)
		if err != nil {
			// the gates before this one wrote theirs, so the error lists them for undoing
			writeFailed(w, err, a.out.Labels)
			return
		}
	}
	a.touched(rowGates)
	log.Infof("accepted %d hint(s) as %d label(s)", len(a.Hints), len(a.out.Written))
	writeJSON(w, a.out)
}
