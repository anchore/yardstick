package labelserver

import (
	"net/http"
	"slices"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
)

// causeView is a cause as it applies to one gate: its member rows present, and the policy check.
type causeView struct {
	agentstore.Cause
	Policy  policyCheck
	Rows    []string // member rows in this gate, in report order
	Missing int      // members this gate does not have
}

// attachCauses matches each of this gate's causes' members to the gate's rows, by row id. A cause
// covers exactly the rows it lists, and only those whose package and vulnerability (or an alias)
// are the member's: a member naming one row and another package never reaches a label.
func (s *Server) attachCauses(e *entry, v *view) error {
	causes, err := s.opts.Store.Causes.Current()
	if err != nil {
		return err
	}
	v.causes, v.rowCauses = map[string]*causeView{}, map[string][]*causeView{}
	members := map[string][]*causeView{}
	for _, c := range causes {
		if c.Gate != e.name {
			continue
		}
		cv := &causeView{Cause: c, Policy: policyCheck{Rule: ruleOf(v.vocab, c.Evidence), Problems: c.Problems(v.vocab)}}
		v.causes[c.ID] = cv
		v.causeOrder = append(v.causeOrder, cv)
		for _, m := range c.Members {
			if r := v.rows[m.Row]; r != nil && memberIs(r, m) {
				members[m.Row] = append(members[m.Row], cv)
			}
		}
	}
	for _, r := range v.orderedRows() {
		for _, cv := range members[r.match.Row] {
			cv.Rows = append(cv.Rows, r.match.Row)
			v.rowCauses[r.match.Row] = append(v.rowCauses[r.match.Row], cv)
		}
	}
	for _, cv := range v.causeOrder {
		cv.Missing = len(cv.Members) - len(cv.Rows)
	}
	return nil
}

// memberIs is true when a member names the row's package and its vulnerability or an alias.
func memberIs(r *rowRef, m agentstore.Member) bool {
	return m.Package == r.match.Package &&
		(m.Vulnerability == r.match.Vulnerability || m.Vulnerability == r.match.Group || slices.Contains(r.match.Aliases, m.Vulnerability))
}

// Member states: what accepting the cause would do with a member row.
const (
	memberPending  = "pending"  // open; accepting labels it
	memberConflict = "conflict" // open, but its own hint disagrees with the cause: left out unless chosen
	memberLabeled  = "labeled"  // labeled some other way: accepting skips it
	memberAccepted = "accepted" // labeled with the cause's verdict (a label carries no basedOn, so this is agreement)
)

func (v *view) memberState(cv *causeView, id string) string {
	r := v.rows[id]
	switch {
	case !r.open() && verdictOf(r) == string(cv.Verdict):
		return memberAccepted
	case !r.open():
		return memberLabeled
	case v.hints[id] != nil && v.hints[id].Proposal.Verdict != cv.Verdict:
		return memberConflict
	}
	return memberPending
}

// stateCause is what the map shows of a cause on its package.
type stateCause struct {
	ID            string            `json:"id"`
	Title         string            `json:"title"`
	Verdict       claimsv1.Verdict  `json:"verdict"`
	Justification string            `json:"justification,omitempty"`
	Confidence    string            `json:"confidence,omitempty"`
	Author        agentstore.Author `json:"author"`
	Rule          string            `json:"rule,omitempty"`
	RuleText      string            `json:"ruleText,omitempty"` // what the rule rests on, in plain words
	Problems      int               `json:"problems,omitempty"`
	SourcePackage string            `json:"sourcePackage"`
	Direction     string            `json:"direction,omitempty"`
	Rows          []string          `json:"rows"`
	Pending       []string          `json:"pending"`
	Conflicts     []string          `json:"conflicts"`
	Labeled       int               `json:"labeled"`
	Accepted      int               `json:"accepted"`
	Missing       int               `json:"missing,omitempty"`
}

func (v *view) stateCauses() []stateCause {
	out := []stateCause{}
	for _, cv := range v.causeOrder {
		if len(cv.Rows) == 0 {
			continue // not about this gate
		}
		sc := stateCause{ID: cv.ID, Title: cv.Title, Verdict: cv.Verdict, Justification: cv.Justification, Confidence: cv.Confidence, Author: cv.Author,
			Problems: len(cv.Policy.Problems), SourcePackage: cv.SourcePackage, Direction: cv.Direction, Rows: cv.Rows, Missing: cv.Missing,
			Pending: []string{}, Conflicts: []string{}}
		if r := cv.Policy.Rule; r != nil {
			sc.Rule, sc.RuleText = r.Name, r.Basis
		}
		for _, id := range cv.Rows {
			switch v.memberState(cv, id) {
			case memberPending:
				sc.Pending = append(sc.Pending, id)
			case memberConflict:
				sc.Conflicts = append(sc.Conflicts, id)
			case memberLabeled:
				sc.Labeled++
			case memberAccepted:
				sc.Accepted++
			}
		}
		out = append(out, sc)
	}
	return out
}

type causeMember struct {
	agentstore.Member
	State   string       `json:"state"` // pending, conflict, labeled, accepted, or missing
	Verdict string       `json:"verdict,omitempty"`
	Hint    *hintSummary `json:"hint,omitempty"`
}

func (s *Server) handleCause(w http.ResponseWriter, req *http.Request) {
	_, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	cv := v.causes[req.PathValue("id")]
	if cv == nil {
		http.Error(w, "no such cause", http.StatusNotFound)
		return
	}
	resp := struct {
		Cause   agentstore.Cause `json:"cause"`
		Policy  policyCheck      `json:"policy"`
		Members []causeMember    `json:"members"`
	}{cv.Cause, cv.Policy, []causeMember{}}
	for _, m := range cv.Members {
		cm := causeMember{Member: m, State: "missing"}
		if r := v.rows[m.Row]; r != nil && slices.Contains(cv.Rows, m.Row) {
			cm.State, cm.Verdict = v.memberState(cv, m.Row), verdictOf(r)
			if h := v.hints[m.Row]; h != nil {
				cm.Hint = h.summary()
			}
		}
		resp.Members = append(resp.Members, cm)
	}
	writeJSON(w, resp)
}

// explanationView is an explanation of this gate's run, with the member rows the gate has.
type explanationView struct {
	agentstore.Explanation
	Rows    []string
	Missing int
}

// attachExplanations matches the run's explanations of this gate to its rows. Explanations never
// change a verdict; they only say why rows differ.
func (s *Server) attachExplanations(e *entry, v *view) error {
	all, err := s.opts.Store.Explanations.Current()
	if err != nil {
		return err
	}
	v.rowExplanation = map[string]*explanationView{}
	byRow := map[string]*explanationView{}
	for _, x := range all {
		if x.Gate != e.name || x.Run != s.opts.Run {
			continue
		}
		ev := &explanationView{Explanation: x}
		v.explanations = append(v.explanations, ev)
		for _, m := range x.Members {
			byRow[m.Row] = ev // the newest explanation listing a row wins
		}
	}
	for _, r := range v.orderedRows() {
		if ev := byRow[r.match.Row]; ev != nil {
			ev.Rows = append(ev.Rows, r.match.Row)
			v.rowExplanation[r.match.Row] = ev
		}
	}
	for _, ev := range v.explanations {
		ev.Missing = len(ev.Members) - len(ev.Rows)
	}
	return nil
}

// stateExplanation is what the map shows of an explanation; the row endpoint serves it whole.
type stateExplanation struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Reason      string            `json:"reason,omitempty"` // the computed why key it refines
	Rows        []string          `json:"rows"`
	Missing     int               `json:"missing,omitempty"`
	Author      agentstore.Author `json:"author"`
	Timestamp   time.Time         `json:"timestamp"`
	Facts       int               `json:"facts"`
	LogExcerpts int               `json:"logExcerpts"`
}

func (v *view) stateExplanations() []stateExplanation {
	out := []stateExplanation{}
	for _, ev := range v.explanations {
		if len(ev.Rows) == 0 {
			continue
		}
		out = append(out, stateExplanation{ID: ev.ID, Title: ev.Title, Reason: ev.Reason, Rows: slices.Clip(ev.Rows), Missing: ev.Missing,
			Author: ev.Author, Timestamp: ev.Timestamp, Facts: len(ev.Facts), LogExcerpts: len(ev.LogExcerpts)})
	}
	return out
}
