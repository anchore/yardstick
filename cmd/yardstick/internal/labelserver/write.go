package labelserver

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelwrite"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
)

// A label's scope: the package within the scanned subject, or the package anywhere (global/).
const (
	scopeSubject  = "subject"
	scopeAnywhere = "anywhere"
)

func global(scope string) (bool, error) {
	switch scope {
	case "", scopeSubject:
		return false, nil
	case scopeAnywhere:
		return true, nil
	}
	return false, errors.New(`scope must be "subject" or "anywhere"`)
}

// pending is a batch of labels to write in one go, and the override records they make.
type pending struct {
	placed    []claimsv1.Placed
	overrides []agentstore.Override
	keys      []LabelKey // what write wrote, once each
}

// add places a label about a row, with seenIn from the setup that reported it.
func (p *pending) add(e *entry, r *rowRef, l claimsv1.Label, glob bool) error {
	sub := &e.rec.Subjects[r.si]
	setup := pairing.Candidate
	if !r.match.InCandidate && r.match.InReference {
		setup = pairing.Reference
	}
	l.SeenIn = labelwrite.SeenInFor(e.rec, sub, setup)
	placed, err := labelwrite.Place(sub, l, glob)
	if err != nil {
		return fmt.Errorf("row %s: %w", r.match.Row, err)
	}
	p.placed = append(p.placed, placed)
	return nil
}

// write writes the batch into the gate's writable claims source, then the override records. The
// writer checks every label before writing any. p.keys is what landed, error or not.
func (s *Server) write(v *view, p *pending) error {
	p.keys = []LabelKey{}
	if len(p.placed) == 0 {
		return nil
	}
	wr, err := v.set.Writer()
	if err != nil {
		return err
	}
	written, err := wr.Write(p.placed)
	for _, wt := range written {
		p.keys = append(p.keys, LabelKey{Source: wr.Dir, File: wt.File, Package: wt.Key.Package, Vulnerability: wt.Key.Vulnerability, Prior: wt.Prior})
	}
	if err != nil {
		return err
	}
	if len(p.overrides) > 0 {
		if err := s.opts.Store.Overrides.Add(p.overrides...); err != nil {
			return fmt.Errorf("the labels were written, but not the override records: %w", err)
		}
	}
	return nil
}

// WriteError is the body of a write that failed once some labels had landed: the error, and the
// labels written, which POST /api/history/revert takes to undo them. A write that failed before
// any landed answers 400 with the error as plain text instead.
type WriteError struct {
	Error  string     `json:"error"`
	Labels []LabelKey `json:"labels"`
}

// writeFailed answers a failed write, listing what landed when anything did.
func writeFailed(w http.ResponseWriter, err error, landed []LabelKey) {
	if len(landed) == 0 {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Warnf("a write failed after %d label(s) landed: %v", len(landed), err)
	writeJSONStatus(w, http.StatusInternalServerError, WriteError{err.Error(), landed})
}

type LabelsRequest struct {
	Rows          []string `json:"rows"`
	Verdict       string   `json:"verdict"`
	Justification string   `json:"justification"`
	Note          string   `json:"note"`
	// Scope is "subject" (the package within the scanned subject) or "anywhere".
	Scope string `json:"scope"`
	// OverrideReason, optional, says why the verdict differs from the rows' hints; it goes on the
	// override records, never on the label.
	OverrideReason *agentstore.Reason `json:"overrideReason,omitempty"`
}

// handleLabels writes a person's verdict on each row. A verdict differing from a row's pending
// hint, or a cause listing it, is recorded as an override.
func (s *Server) handleLabels(w http.ResponseWriter, req *http.Request) {
	var body LabelsRequest
	if !decode(w, req, &body) {
		return
	}
	verdict := claimsv1.Verdict(body.Verdict)
	glob, err := global(body.Scope)
	switch {
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case !slices.Contains(claimsv1.Verdicts(), verdict):
		http.Error(w, fmt.Sprintf("verdict must be tp, fp or unclear, got %q", body.Verdict), http.StatusBadRequest)
		return
	case len(body.Rows) == 0:
		http.Error(w, "no rows given", http.StatusBadRequest)
		return
	case body.OverrideReason != nil && !slices.Contains(agentstore.ReasonKinds, body.OverrideReason.Kind):
		http.Error(w, fmt.Sprintf("override reason kind must be one of %v", agentstore.ReasonKinds), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	e, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	now := time.Now().UTC()
	ts := now.Format(time.RFC3339)
	var batch pending
	overridden := []string{}
	for _, id := range body.Rows {
		r := v.rows[id]
		if r == nil {
			http.Error(w, "no such row: "+id, http.StatusBadRequest)
			return
		}
		l := claimsv1.Label{Package: r.match.Package, Vulnerability: r.match.Vulnerability, Verdict: verdict, Justification: body.Justification,
			Author: s.opts.Author, Notes: claimsv1.NotesOf(body.Note, s.opts.Author, ts), FirstIssued: ts, LastUpdated: ts}
		if err := batch.add(e, r, l, glob); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if o := s.overrides(e, v, r, l, body.OverrideReason, now); len(o) > 0 {
			batch.overrides = append(batch.overrides, o...)
			overridden = append(overridden, id)
		}
	}
	if body.OverrideReason != nil && len(overridden) == 0 {
		http.Error(w, "an override reason was given, but no row has a differing hint", http.StatusBadRequest)
		return
	}
	if err := s.write(v, &batch); err != nil {
		writeFailed(w, err, batch.keys)
		return
	}
	log.Infof("wrote %d %s label(s), %d overriding an agent", len(batch.placed), verdict, len(overridden))
	writeJSON(w, LabelsResponse{len(batch.placed), overridden, batch.keys})
}

// overrides are the records a person's label on a row makes against the row's pending hint and
// the causes listing it, when its verdict differs from theirs.
func (s *Server) overrides(e *entry, v *view, r *rowRef, l claimsv1.Label, reason *agentstore.Reason, now time.Time) []agentstore.Override {
	var against []string
	if h := v.hints[r.match.Row]; h != nil && h.Status == hintPending && h.Proposal.Verdict != l.Verdict {
		against = append(against, h.Proposal.ID)
	}
	for _, cv := range v.rowCauses[r.match.Row] {
		if cv.Verdict != l.Verdict {
			against = append(against, cv.ID)
		}
	}
	subj, err := labelwrite.Place(&e.rec.Subjects[r.si], claimsv1.Label{}, false)
	if err != nil || subj.Subject == nil {
		return nil // the label's own placement refuses the row before this matters
	}
	var out []agentstore.Override
	for _, p := range against {
		out = append(out, agentstore.Override{Schema: agentstore.Schema, Proposal: p, Gate: e.name, Subject: *subj.Subject, Package: l.Package,
			Vulnerability: l.Vulnerability, Verdict: l.Verdict, Justification: l.Justification, Reason: reason, Note: strings.Join(l.NoteTexts(), "\n"), Author: s.opts.Author, Timestamp: now})
	}
	return out
}

// handleAccept endorses the hints on the given rows: per distinct proposal, the label it says, by
// the person accepting it.
func (s *Server) handleAccept(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Rows []string `json:"rows"`
	}
	if !decode(w, req, &body) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	now := time.Now().UTC()
	seen := map[string]bool{}
	var batch pending
	for _, id := range body.Rows {
		h := v.hints[id]
		if h == nil {
			http.Error(w, "no hint for row "+id, http.StatusBadRequest)
			return
		}
		if h.Status == "agrees" || seen[h.Proposal.ID] {
			continue
		}
		seen[h.Proposal.ID] = true
		if err := batch.add(e, v.rows[id], h.Proposal.Label(s.opts.Author, now), false); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := s.write(v, &batch); err != nil {
		writeFailed(w, err, batch.keys)
		return
	}
	log.Infof("accepted %d proposal(s)", len(batch.placed))
	writeJSON(w, AcceptResponse{len(batch.placed), batch.keys})
}

type SkippedRow struct {
	Row string `json:"row"`
	Why string `json:"why"`
}

// handleAcceptCause endorses a cause for the chosen member rows: per row, the label the cause says
// for that member. Rows already labeled are skipped.
func (s *Server) handleAcceptCause(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Rows  []string `json:"rows"`
		Scope string   `json:"scope"`
	}
	if !decode(w, req, &body) {
		return
	}
	glob, err := global(body.Scope)
	if err != nil || len(body.Rows) == 0 {
		http.Error(w, "give the member rows to accept, and a scope of subject or anywhere", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	cv := v.causes[req.PathValue("id")]
	if cv == nil {
		http.Error(w, "no such cause", http.StatusNotFound)
		return
	}
	now := time.Now().UTC()
	var batch pending
	skipped := []SkippedRow{}
	for _, id := range body.Rows {
		r := v.rows[id]
		switch {
		case r == nil || !slices.Contains(cv.Rows, id):
			http.Error(w, fmt.Sprintf("row %s is not a member of cause %s in this gate", id, cv.ID), http.StatusBadRequest)
			return
		case !r.open():
			skipped = append(skipped, SkippedRow{id, "already labeled " + verdictOf(r)})
			continue
		}
		// the package and vulnerability come from the row, never from the stored member
		l := cv.Label(agentstore.Member{Package: r.match.Package, Vulnerability: r.match.Vulnerability}, s.opts.Author, now)
		if err := batch.add(e, r, l, glob); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := s.write(v, &batch); err != nil {
		writeFailed(w, err, batch.keys)
		return
	}
	log.Infof("accepted cause %s for %d row(s)", cv.ID, len(batch.placed))
	writeJSON(w, AcceptCauseResponse{len(batch.placed), skipped, batch.keys})
}

// handlePreview answers with the gate's result as if the given rows were labeled so, e.g.
// {"labels": {"<row id>": "tp"}}: what accepting a set of hints would do to each check's range.
// Nothing is written and nothing is re-read; the checks are evaluated again over the cached
// pairing.
func (s *Server) handlePreview(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Labels map[string]claimsv1.Verdict `json:"labels"`
	}
	if !decode(w, req, &body) {
		return
	}
	e, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	if v.stale != "" {
		http.Error(w, fmt.Sprintf("gate %s has no result to preview: %s", e.name, v.stale), http.StatusConflict)
		return
	}
	hyp := map[*pairing.Match]claimsv1.Verdict{}
	for id, verdict := range body.Labels {
		r := v.rows[id]
		switch {
		case verdict != claimsv1.TP && verdict != claimsv1.FP:
			http.Error(w, fmt.Sprintf("row %s: a preview label must be tp or fp, got %q", id, verdict), http.StatusBadRequest)
			return
		case r == nil:
			http.Error(w, "no such row: "+id, http.StatusBadRequest)
			return
		}
		hyp[r.pm] = verdict
	}
	g := analysis.EvaluateAs(e.gate.Checks, v.paired.Subjects, hyp)
	writeJSON(w, v.result(e.gate, g.Outcome, g.Checks))
}

// LabelsResponse is the answer to POST labels: the rows written, and those that overrode a hint.
type LabelsResponse struct {
	Written    int        `json:"written"`
	Overridden []string   `json:"overridden"`
	Labels     []LabelKey `json:"labels"` // what POST /api/history/revert takes to undo the write
}

// AcceptResponse is the answer to accepting a hint.
type AcceptResponse struct {
	Written int        `json:"written"`
	Labels  []LabelKey `json:"labels"`
}

// AcceptCauseResponse is the answer to accepting a cause.
type AcceptCauseResponse struct {
	Written int          `json:"written"`
	Skipped []SkippedRow `json:"skipped"`
	Labels  []LabelKey   `json:"labels"`
}
