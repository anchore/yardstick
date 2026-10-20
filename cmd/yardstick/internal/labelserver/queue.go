package labelserver

import (
	"cmp"
	"net/http"
	"slices"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
)

// The queue: every open change across the gates, one entry per image match, in the order worth
// labeling them. It is the cross-gate join (shared.go) keyed by row id, with the rows that bear on
// no check kept.

// Queue is GET /api/queue.
type Queue struct {
	Gates   []QueueGate  `json:"gates"`
	Entries []QueueEntry `json:"entries"`
	// Settled is the stopping point: no labeling of the open rows changes any gate's outcome.
	Settled bool `json:"settled"`
}

type QueueGate struct {
	GateSummary `tstype:",extends"`
	// Rows counts every open change, where Open counts the ones bearing on a check.
	Rows int `json:"rows"`
	// Settled says no labeling of the gate's open changes changes its outcome.
	Settled bool `json:"settled"`
}

// QueueEntry is one open row. Row is the id it has in every gate it is in; Effect is its strongest
// over the gates in scope (In has every gate, each with its own): decides (a tp or fp label alone changes a gate's outcome), could-move (changes a
// check's state), counted (narrows a check's range) or none.
type QueueEntry struct {
	CrossFinding `tstype:",extends"`
	Row          string        `json:"row"`
	Label        *FindingLabel `json:"label" tstype:"FindingLabel | null"` // the unclear label, when there is one
	Effect       string        `json:"effect"`
}

const effectNone = "none"

// queueRank is effectRank with none, the weakest
var queueRank = map[string]int{effectDecides: 0, effectCouldMove: 1, effectCounted: 2, effectNone: 3}

// appearanceEffect is what labeling the row does in one gate.
func appearanceEffect(a CrossAppearance) string {
	switch {
	case a.Decides:
		return effectDecides
	case a.Effect != nil && len(a.Effect.CouldFlip) > 0:
		return effectCouldMove
	case a.Effect != nil:
		return effectCounted
	}
	return effectNone
}

// queueScope is a parsed ?scope=: all, gate:<name> or image:<slug>.
type queueScope struct{ gate, image string }

func parseScope(s string) (queueScope, bool) {
	kind, name, _ := strings.Cut(s, ":")
	switch kind {
	case "", "all":
		return queueScope{}, true
	case "gate":
		return queueScope{gate: name}, name != ""
	case "image":
		return queueScope{image: name}, name != ""
	}
	return queueScope{}, false
}

func (q queueScope) has(f *CrossFinding, a CrossAppearance) bool {
	return (q.gate == "" || a.Gate == q.gate) && (q.image == "" || f.slug == q.image)
}

// queued is an entry and what the queue orders it by: tier (deciding a gate, moving a check, none),
// its gate's open rows and place in the gate list, and its image and report position there.
type queued struct {
	QueueEntry
	tier, rows, gate, si, at int
}

// queueBuild is the queue as it is put together: the gates joined, and each one's view and place.
type queueBuild struct {
	Queue
	j      *join
	views  map[string]*view
	gateAt map[string]int
}

// joinGates joins every gate's open changes by row id and summarizes the gates.
func (s *Server) joinGates() (*queueBuild, error) {
	all, err := s.entries()
	if err != nil {
		return nil, err
	}
	b := &queueBuild{Queue: Queue{Gates: []QueueGate{}, Entries: []QueueEntry{}, Settled: true}, j: &join{byKey: map[string]*CrossFinding{}, byRow: true},
		views: map[string]*view{}, gateAt: map[string]int{}}
	for _, e := range all {
		b.gateAt[e.name] = len(b.Gates)
		v, err := s.view(e)
		if err != nil {
			b.Gates = append(b.Gates, QueueGate{GateSummary: GateSummary{Name: e.name, Description: e.gate.Description, Outcome: analysis.Undecided, Note: err.Error()}})
			continue
		}
		b.views[e.name] = v
		g := QueueGate{GateSummary: b.j.add(e, v)}
		// a gate that cannot be judged has nothing the queue can settle, so it holds nothing up
		if v.stale == "" {
			g.Settled = v.settled(e)
			b.Settled = b.Settled && g.Settled
		}
		b.Gates = append(b.Gates, g)
	}
	for _, f := range b.j.byKey {
		for _, a := range f.In {
			b.Gates[b.gateAt[a.Gate]].Rows++
		}
	}
	return b, nil
}

// entry is one joined row as the queue has it, sorted by the closest to done of its gates in
// scope; false when it is in none.
func (b *queueBuild) entry(id string, scope queueScope, low bool) (queued, bool) {
	f := b.j.byKey[id]
	rows := func(a *CrossAppearance) int { return b.Gates[b.gateAt[a.Gate]].Rows }
	var primary *CrossAppearance
	for i, a := range f.In {
		if scope.has(f, a) && (primary == nil || rows(&a) < rows(primary)) {
			primary = &f.In[i]
		}
	}
	if primary == nil {
		return queued{}, false
	}
	if !low && f.Hint != nil && f.Hint.Confidence == lowConfidence {
		f.Hint = nil
	}
	if !low && f.Cause != nil && f.Cause.Confidence == lowConfidence {
		f.Cause = nil
	}
	r := b.views[primary.Gate].rows[id]
	qe := QueueEntry{CrossFinding: *f, Row: id, Label: labelOf(r.pm.Label, verdictOf(r)), Effect: effectNone}
	for _, a := range f.In {
		if eff := appearanceEffect(a); scope.has(f, a) && queueRank[eff] < queueRank[qe.Effect] {
			qe.Effect = eff
		}
	}
	// deciding a gate first, then whatever moves a check, then none
	tier := min(queueRank[qe.Effect], 1)
	if qe.Effect == effectNone {
		tier = 2
	}
	return queued{qe, tier, rows(primary), b.gateAt[primary.Gate], primary.si, primary.at}, true
}

// handleQueue answers with the open rows in scope, ordered: rows that decide a gate first, then by
// gate (fewest open rows first), by image, and in report order; rows that change nothing last. A
// row in several gates sorts by the closest to done of its gates in scope. low=1 keeps
// low-confidence hints, which are dropped from entries otherwise.
func (s *Server) handleQueue(w http.ResponseWriter, req *http.Request) {
	scope, ok := parseScope(req.URL.Query().Get("scope"))
	if !ok {
		http.Error(w, "scope must be all, gate:<name> or image:<slug>", http.StatusBadRequest)
		return
	}
	b, err := s.joinGates()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var queue []queued
	for _, id := range b.j.order {
		if q, ok := b.entry(id, scope, req.URL.Query().Get("low") == "1"); ok {
			queue = append(queue, q)
		}
	}
	slices.SortStableFunc(queue, func(a, b queued) int {
		return cmp.Or(cmp.Compare(a.tier, b.tier), cmp.Compare(a.rows, b.rows), cmp.Compare(a.gate, b.gate), cmp.Compare(a.si, b.si), cmp.Compare(a.at, b.at))
	})
	for _, q := range queue {
		b.Entries = append(b.Entries, q.QueueEntry)
	}
	writeJSON(w, b.Queue)
}

// settled says no labeling of the gate's open changes changes its outcome: neither labeling every
// one the way that favors the candidate (a dropped match fp, an added one tp) nor every one the
// way that counts against it does.
// ponytail: the two extremes, not every mix of verdicts; a gate that only a mix moves reads as settled
func (v *view) settled(e *entry) bool {
	favors, against := map[*pairing.Match]claimsv1.Verdict{}, map[*pairing.Match]claimsv1.Verdict{}
	for _, r := range v.orderedRows() {
		switch {
		case !r.open() || !r.changed():
		case r.match.InCandidate:
			favors[r.pm], against[r.pm] = claimsv1.TP, claimsv1.FP
		default:
			favors[r.pm], against[r.pm] = claimsv1.FP, claimsv1.TP
		}
	}
	for _, hyp := range []map[*pairing.Match]claimsv1.Verdict{favors, against} {
		if analysis.EvaluateAs(e.gate.Checks, v.paired.Subjects, hyp).Outcome != v.verdict.Outcome {
			return false
		}
	}
	return true
}
