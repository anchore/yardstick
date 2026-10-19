package labelserver

import (
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
)

const unlabeled = "unlabeled"

// verdictOf is a row's verdict as the UI reads it: tp or fp when a label decides it, unclear when
// the label deciding it says so, else unlabeled.
func verdictOf(r *rowRef) string {
	switch {
	case r.match.Verdict != "":
		return string(r.match.Verdict)
	case r.pm.Label != nil && r.pm.Label.Verdict == claimsv1.Unclear && !r.pm.Label.Disagrees():
		return string(claimsv1.Unclear)
	}
	return unlabeled
}

// direction is which setup reported a row; each asks the labeler a different question.
func direction(m *report.Match) string {
	switch {
	case m.InCandidate && m.InReference:
		return "both"
	case m.InCandidate:
		return "added"
	case m.InReference:
		return "dropped"
	}
	return "neither"
}

type state struct {
	Scans        runSummary         `json:"scans"`
	Author       string             `json:"author"`
	Subjects     []stateSubject     `json:"subjects"`
	Causes       []stateCause       `json:"causes"`
	Gate         *gateStatus        `json:"gate"`
	Explanations []stateExplanation `json:"explanations"`
	// Candidate and Reference are each setup as resolved, for the header.
	Candidate  *setup.Prepared `json:"candidate,omitempty"`
	Reference  *setup.Prepared `json:"reference,omitempty"`
	Vocabulary *vocabulary     `json:"vocabulary,omitempty"`
	Warnings   []string        `json:"warnings,omitempty"`
	// ResearchConcurrency is how many research jobs run at once, absent when research cannot
	// start, which hides the UI's research controls; Research says why.
	ResearchConcurrency int                    `json:"researchConcurrency,omitempty"`
	Research            *research.Availability `json:"research,omitempty"`
}

// vocabulary is what the UI needs of vocabulary.yaml: the justifications by verdict.
type vocabulary struct {
	Justifications map[claimsv1.Verdict]map[string]string `json:"justifications"`
}

func vocabOf(v *claimsv1.Vocabulary) *vocabulary {
	if v == nil {
		return nil
	}
	return &vocabulary{Justifications: v.Justifications}
}

type stateSubject struct {
	Name string     `json:"name"`
	Slug string     `json:"slug"`
	Rows []stateRow `json:"rows"`
}

// stateRow is a report row in delta's row shape: the fields named the same pass through, and
// these shadow the ones that differ.
type stateRow struct {
	report.Match
	ID          string       `json:"id"`
	MatchID     string       `json:"match"`
	Package     pkgRef       `json:"package"`
	Verdict     string       `json:"verdict"`
	Hint        *hintSummary `json:"hint,omitempty"`
	Causes      []string     `json:"causes,omitempty"`
	Explanation string       `json:"explanation,omitempty"`
	Gate        *rowEffect   `json:"gate,omitempty"`
	// ResearchLevel is "", "triaged" or "researched"; Researched is it being "researched".
	ResearchLevel string           `json:"researchLevel,omitempty"`
	Researched    bool             `json:"researched,omitempty"`
	ResearchedBy  []string         `json:"researchedBy,omitempty"`
	Research      *researchSummary `json:"research,omitempty"` // the newest job covering the row
}

type pkgRef struct {
	Ref string `json:"ref"`
}

// rowEffect is what labeling an open row does to the gate.
type rowEffect struct {
	Bears     []string      `json:"bears,omitempty"`
	CouldFlip []string      `json:"couldFlip,omitempty"`
	IfTP      outcomeEffect `json:"ifTP"`
	IfFP      outcomeEffect `json:"ifFP"`
}

type outcomeEffect struct {
	Outcome analysis.State `json:"outcome"`
}

// effectOf is a row's effect when its label bears on some check, else nil.
func (v *view) effectOf(id string) *rowEffect {
	eff, ok := v.effects[id]
	if !ok {
		return nil
	}
	out := &rowEffect{Bears: eff.Narrows, IfTP: outcomeEffect{eff.Outcome[claimsv1.TP]}, IfFP: outcomeEffect{eff.Outcome[claimsv1.FP]}}
	for _, c := range v.verdict.Checks {
		if eff.States[claimsv1.TP][c.Name] != c.State || eff.States[claimsv1.FP][c.Name] != c.State {
			out.CouldFlip = append(out.CouldFlip, c.Name)
		}
	}
	if len(out.Bears) == 0 && len(out.CouldFlip) == 0 {
		return nil
	}
	return out
}

// hintSummary is what lists show of a hint.
type hintSummary struct {
	ID            string           `json:"id"`
	Verdict       claimsv1.Verdict `json:"verdict"`
	Justification string           `json:"justification,omitempty"`
	Confidence    string           `json:"confidence,omitempty"`
	Skill         string           `json:"skill,omitempty"`
	Model         string           `json:"model,omitempty"`
	ResearchJob   string           `json:"researchJob,omitempty"`
	Rule          string           `json:"rule,omitempty"`
	Decision      string           `json:"decision,omitempty"`
	Title         string           `json:"title,omitempty"` // the rule's, a headline for people
	Problems      int              `json:"problems,omitempty"`
	Status        string           `json:"status"`
	Written       time.Time        `json:"written,omitzero"`
	Origin        string           `json:"origin,omitempty"` // label-ui, research-job or skill-run
}

func (h *hint) summary() *hintSummary {
	p := h.Proposal
	out := &hintSummary{ID: p.ID, Verdict: p.Verdict, Justification: p.Justification, Confidence: p.Confidence, Skill: p.Author.Skill,
		Model: p.Author.Model, ResearchJob: p.Author.ResearchJob, Problems: len(h.Policy.Problems), Status: h.Status, Written: p.Timestamp}
	if r := h.Policy.Rule; r != nil {
		out.Rule, out.Decision, out.Title = r.Name, r.Decision, r.Title
	}
	return out
}

// listRow is a row as lists show it, with its research from idx.
func (v *view) listRow(r *rowRef, idx *researchIndex) stateRow {
	m := r.match
	lvl := v.rowResearchLevel(idx, m.Row)
	sr := stateRow{Match: *m, ID: m.Row, MatchID: m.ID, Package: pkgRef{m.Package}, Verdict: verdictOf(r),
		ResearchLevel: lvl, Researched: lvl == LevelResearched, ResearchedBy: v.researchedBy(m.Row), Research: idx.newest[m.Row]}
	if r.open() {
		sr.Gate = v.effectOf(m.Row)
	}
	if h := v.hints[m.Row]; h != nil {
		sr.Hint = h.summary()
		sr.Hint.Origin, sr.Hint.ResearchJob = hintOrigin(idx, m.Row, h.Proposal)
	}
	for _, cv := range v.rowCauses[m.Row] {
		sr.Causes = append(sr.Causes, cv.ID)
	}
	if ev := v.rowExplanation[m.Row]; ev != nil {
		sr.Explanation = ev.ID
	}
	return sr
}

// gateStatus is a gate and its result, as delta's gate.Status.
type gateStatus struct {
	Name        string      `json:"name"`
	Locator     string      `json:"locator"`
	Description string      `json:"description,omitempty"`
	Note        string      `json:"note,omitempty"`
	Rerun       bool        `json:"rerun,omitempty"`
	Result      *gateResult `json:"result,omitempty"`
}

type gateResult struct {
	Outcome analysis.State `json:"outcome"`
	// CI is what CI reads the outcome as under the gate's undecided policy.
	CI     analysis.State `json:"ci"`
	Checks []checkResult  `json:"checks"`
}

type checkResult struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	ValueMeans  string             `json:"valueMeans"`
	Counts      string             `json:"counts,omitempty"`
	Direction   string             `json:"direction"`
	Params      map[string]float64 `json:"params,omitempty"`
	Threshold   float64            `json:"threshold"`
	Value       analysis.Value     `json:"value"`
	State       analysis.State     `json:"state"`
	FailsOn     []string           `json:"failsOn,omitempty"` // row ids
}

// which side of a check's threshold passes
const (
	atMost  = "atMost"
	atLeast = "atLeast"
)

// checkWords say what each check's value is, what it counts, and which side of the threshold
// passes: the UI's words for checks it draws.
var checkWords = map[string]struct{ means, counts, direction string }{
	analysis.F1NotWorse:             {"the reference's F1 less the candidate's", "f1", atMost},
	analysis.NoNewFalseNegatives:    {"new false negatives", "fn", atMost},
	analysis.NoNewFalsePositives:    {"new false positives", "fp", atMost},
	analysis.UnjudgedChangesAtMost:  {"unlabeled deltas", "unjudged", atMost},
	analysis.UnlabeledPercentAtMost: {"percent of the candidate's matches unlabeled", "unjudged", atMost},
	analysis.ExpectationsMetAtLeast: {"expectations the candidate meets", "", atLeast},
	analysis.NoNewMisses:            {"expectations the candidate newly misses", "", atMost},
}

func (v *view) gateStatus(e *entry) *gateStatus {
	g := v.verdict
	st := &gateStatus{Name: e.name, Locator: e.gate.Path, Description: e.gate.Description}
	if v.stale != "" {
		st.Note, st.Rerun = v.stale, true
		return st
	}
	st.Result = v.result(e.gate, g.Outcome, g.Checks)
	return st
}

// result is a gate's evaluation in delta's result shape.
func (v *view) result(g *gatefile.Gate, outcome analysis.State, checks []analysis.Check) *gateResult {
	res := &gateResult{Outcome: outcome, CI: analysis.Fail}
	if outcome == analysis.Pass || (outcome == analysis.Undecided && g.Undecided == gatefile.UndecidedPass) {
		res.CI = analysis.Pass
	}
	for _, c := range checks {
		w := checkWords[c.Name]
		cr := checkResult{Name: c.Name, Description: analysis.Registry[c.Name].Description, ValueMeans: w.means, Counts: w.counts,
			Direction: w.direction, Params: c.Params, Threshold: c.Threshold, Value: c.Value, State: c.State}
		if c.Message != "" {
			cr.Description += "; " + c.Message
		}
		for _, sc := range c.Subjects {
			for _, id := range sc.FailsOn {
				cr.FailsOn = append(cr.FailsOn, pairing.RowID(sc.Subject, id))
			}
		}
		res.Checks = append(res.Checks, cr)
	}
	return res
}

func (s *Server) handleState(w http.ResponseWriter, req *http.Request) {
	e, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	idx, err := s.researchIndex()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	st := state{Scans: summarize(e, v), Author: s.opts.Author, Gate: v.gateStatus(e), Vocabulary: vocabOf(v.vocab), Warnings: v.verdict.Warnings,
		Causes: v.stateCauses(), Explanations: v.stateExplanations()}
	if s.opts.Research != nil {
		a := s.opts.ResearchAvailability
		st.Research = &a
		if a.Available {
			st.ResearchConcurrency = s.opts.Research.Concurrency()
		}
	}
	if c, ok := e.rec.Setups[pairing.Candidate]; ok {
		st.Candidate = &c
	}
	if r, ok := e.rec.Setups[pairing.Reference]; ok {
		st.Reference = &r
	}
	for si, sub := range v.verdict.Subjects {
		ss := stateSubject{Name: st.Scans.Subjects[si].Name, Slug: st.Scans.Subjects[si].Slug, Rows: []stateRow{}}
		for j := range sub.Matches {
			ss.Rows = append(ss.Rows, v.listRow(v.rows[sub.Matches[j].Row], idx))
		}
		st.Subjects = append(st.Subjects, ss)
	}
	writeJSON(w, st)
}

// runSummary is a gate's scans as the gate list and every page's header show them.
type runSummary struct {
	ID       string        `json:"id"` // the gate's name
	Created  string        `json:"created"`
	Gate     string        `json:"gate"` // the gate file
	Label    string        `json:"label"`
	Compared string        `json:"compared"`
	Subjects []subjectInfo `json:"subjects"`
}

type subjectInfo struct {
	Name string `json:"name"` // what a person calls it, e.g. wolfi-base
	Slug string `json:"slug"` // unique within the gate, for URLs
}

func summarize(e *entry, v *view) runSummary {
	sum := runSummary{ID: e.name, Created: e.rec.Created, Gate: e.gate.Path, Compared: compared(v.verdict.Header)}
	seen := map[string]int{}
	var names []string
	for _, s := range e.rec.Subjects {
		name := subjectName(s.Name)
		slug := slugify(name)
		if seen[slug]++; seen[slug] > 1 {
			slug = fmt.Sprintf("%s-%d", slug, seen[slug])
		}
		sum.Subjects = append(sum.Subjects, subjectInfo{Name: name, Slug: slug})
		names = append(names, name)
	}
	switch len(names) {
	case 0:
		sum.Label = "no subjects"
	case 1:
		sum.Label = names[0]
	default:
		sum.Label = fmt.Sprintf("%s + %d more", names[0], len(names)-1)
	}
	return sum
}

var digestSuffix = regexp.MustCompile(`@sha256:[0-9a-f]+$`)

// subjectName is a gate subject's name, or for one named by its reference, the image's repo and
// tag: oci:cgr.dev/chainguard/wolfi-base@sha256:... is wolfi-base.
func subjectName(name string) string {
	if _, ref, ok := strings.Cut(name, ":"); ok && strings.Contains(ref, "/") {
		return path.Base(digestSuffix.ReplaceAllString(ref, ""))
	}
	return name
}

var slugUnsafe = regexp.MustCompile(`[^a-z0-9._]+`)

func slugify(s string) string {
	if out := strings.Trim(slugUnsafe.ReplaceAllString(strings.ToLower(s), "-"), "-."); out != "" {
		return out
	}
	return "subject"
}

// compared says what differs between the setups, e.g. "grype v0.120.1 vs v0.100.0".
func compared(h report.Header) string {
	if h.OneSetup {
		return "one setup"
	}
	var parts []string
	for _, v := range h.Varied {
		parts = append(parts, fmt.Sprintf("%s %s vs %s", v.Input, short(v.Input, v.Candidate), short(v.Input, v.Reference)))
	}
	if len(parts) == 0 {
		return "nothing varied"
	}
	return strings.Join(parts, " · ")
}

// short trims a tool's name, a DB checksum or a config's sha256 to something a header can show.
func short(input, s string) string {
	s = strings.TrimPrefix(s, input+"@")
	if name, _, ok := strings.Cut(s, " (sha256:"); ok {
		return path.Base(name)
	}
	if after, ok := strings.CutPrefix(s, "sha256:"); ok && len(after) > 12 {
		return after[:12]
	}
	return s
}

// rowResponse is one row with everything the tile shows of it.
type rowResponse struct {
	Row         stateRow                `json:"row"`
	Subject     string                  `json:"subject"`
	Links       []Link                  `json:"links"`
	Label       *labelView              `json:"label,omitempty"`
	Hint        *hint                   `json:"hint,omitempty"`
	Explanation *agentstore.Explanation `json:"explanation,omitempty"`
}

// labelView is the label deciding a row, as its file holds it, and every source holding its key.
type labelView struct {
	Label   claimsv1.Label `json:"label"`
	File    string         `json:"file"`
	Global  bool           `json:"global,omitempty"`
	Sources []string       `json:"sources"`
}

func (s *Server) handleRow(w http.ResponseWriter, req *http.Request) {
	e, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	r := v.rows[req.PathValue("id")]
	if r == nil {
		http.Error(w, "no such row", http.StatusNotFound)
		return
	}
	idx, err := s.researchIndex()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := rowResponse{Row: v.listRow(r, idx), Subject: e.rec.Subjects[r.si].Name, Links: Links(r.match), Hint: v.hints[r.match.Row]}
	if b := r.pm.Label; b != nil {
		lv := &labelView{Label: b.Label.Label, File: b.File, Global: b.Global}
		for _, h := range b.Held {
			lv.Sources = append(lv.Sources, h.Source+": "+string(h.Verdict))
		}
		resp.Label = lv
	}
	if ev := v.rowExplanation[r.match.Row]; ev != nil {
		resp.Explanation = &ev.Explanation
	}
	writeJSON(w, resp)
}

// handleGateList lists every gate scanned under the run, scanned last first.
func (s *Server) handleGateList(w http.ResponseWriter, _ *http.Request) {
	all, err := s.entries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type listed struct {
		runSummary
		GateOutcome analysis.State `json:"gateOutcome,omitempty"`
		GateNote    string         `json:"gateNote,omitempty"`
		Error       string         `json:"error,omitempty"`
	}
	out := struct {
		Open  string   `json:"open"`
		Gates []listed `json:"gates"`
	}{Open: s.opts.Open, Gates: []listed{}}
	for _, e := range all {
		v, err := s.view(e)
		if err != nil {
			out.Gates = append(out.Gates, listed{runSummary: runSummary{ID: e.name, Created: e.rec.Created, Gate: e.gate.Path}, Error: err.Error()})
			continue
		}
		if out.Open == "" {
			out.Open = e.name // the gate scanned last that can be scored, as / opens
		}
		l := listed{runSummary: summarize(e, v), GateOutcome: analysis.Undecided, GateNote: v.stale}
		if v.stale == "" {
			l.GateOutcome = v.verdict.Outcome
		}
		out.Gates = append(out.Gates, l)
	}
	writeJSON(w, out)
}
