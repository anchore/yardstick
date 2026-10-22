package labelserver

import (
	"fmt"
	"maps"
	"net/http"
	"path"
	"regexp"
	"slices"
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
	case r.pm.Label != nil && r.pm.Label.Verdict == claimsv1.Unclear:
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

type State struct {
	Scans        RunSummary         `json:"scans"`
	Author       string             `json:"author"`
	Subjects     []StateSubject     `json:"subjects"`
	Causes       []StateCause       `json:"causes"`
	Gate         *GateStatus        `json:"gate"`
	Explanations []StateExplanation `json:"explanations"`
	// Candidate and Reference are each setup as resolved, for the header.
	Candidate  *setup.Prepared `json:"candidate,omitempty"`
	Reference  *setup.Prepared `json:"reference,omitempty"`
	Vocabulary *Vocabulary     `json:"vocabulary,omitempty"`
	Warnings   []string        `json:"warnings,omitempty"`
	// OutdatedLookups says the computed reasons read DB lookups an older yardstick made, and how
	// to redo them; empty when they are current.
	OutdatedLookups string `json:"outdatedLookups,omitempty"`
	// ResearchConcurrency is how many research jobs run at once, absent when research cannot
	// start, which hides the UI's research controls; Research says why.
	ResearchConcurrency int                    `json:"researchConcurrency,omitempty"`
	Research            *research.Availability `json:"research,omitempty"`
	// ResearchEstimate is what one research job costs on the configured model, set while research can start.
	ResearchEstimate *research.Basis `json:"researchEstimate,omitempty"`
}

// Vocabulary is what the UI needs of vocabulary.yaml: the justifications by verdict.
type Vocabulary struct {
	Justifications map[claimsv1.Verdict]map[string]string `json:"justifications"`
}

func vocabOf(v *claimsv1.Vocabulary) *Vocabulary {
	if v == nil {
		return nil
	}
	return &Vocabulary{Justifications: v.Justifications}
}

type StateSubject struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
	// Changes tallies the rows only one setup reports, for the image rail: total is how many changed.
	Changes Tally      `json:"changes"`
	Rows    []StateRow `json:"rows"`
}

// StateRow is a report row in delta's row shape: the fields named the same pass through, and
// these shadow the ones that differ.
type StateRow struct {
	report.Match `tstype:",extends"`
	ID           string       `json:"id"`
	MatchID      string       `json:"match"`
	Package      PkgRef       `json:"package"`
	Verdict      string       `json:"verdict"`
	Hint         *HintSummary `json:"hint,omitempty"`
	Causes       []string     `json:"causes,omitempty"`
	Explanation  string       `json:"explanation,omitempty"`
	Gate         *RowEffect   `json:"gate,omitempty"`
	// Effect is the row's strongest effect over the gate's checks (decides, could-move or counted),
	// as their findings say it; absent when no check counts it. Only /state sets it.
	Effect string `json:"effect,omitempty"`
	// ResearchLevel is "", "triaged" or "researched"; Researched is it being "researched".
	ResearchLevel string           `json:"researchLevel,omitempty"`
	Researched    bool             `json:"researched,omitempty"`
	ResearchedBy  []string         `json:"researchedBy,omitempty"`
	Research      *ResearchSummary `json:"research,omitempty"` // the newest job covering the row
	// ResearchShares are the other rows a research job on this one covers (sibling packages).
	ResearchShares []string `json:"researchShares,omitempty"`
}

type PkgRef struct {
	Ref string `json:"ref"`
}

// RowEffect is what labeling an open row does to the gate.
type RowEffect struct {
	Bears     []string      `json:"bears,omitempty"`
	CouldFlip []string      `json:"couldFlip,omitempty"`
	IfTP      OutcomeEffect `json:"ifTP"`
	IfFP      OutcomeEffect `json:"ifFP"`
}

type OutcomeEffect struct {
	Outcome analysis.State `json:"outcome"`
	// Fails are the checks that would fail with the label and don't now.
	Fails []string `json:"fails,omitempty"`
}

// effectOf is a row's effect when its label bears on some check, else nil.
func (v *view) effectOf(id string) *RowEffect {
	eff, ok := v.effects[id]
	if !ok {
		return nil
	}
	out := &RowEffect{Bears: eff.Narrows, IfTP: OutcomeEffect{Outcome: eff.Outcome[claimsv1.TP]}, IfFP: OutcomeEffect{Outcome: eff.Outcome[claimsv1.FP]}}
	for _, c := range v.verdict.Checks {
		if eff.States[claimsv1.TP][c.Name] != c.State || eff.States[claimsv1.FP][c.Name] != c.State {
			out.CouldFlip = append(out.CouldFlip, c.Name)
		}
		for v, o := range map[claimsv1.Verdict]*OutcomeEffect{claimsv1.TP: &out.IfTP, claimsv1.FP: &out.IfFP} {
			if eff.States[v][c.Name] == analysis.Fail && c.State != analysis.Fail {
				o.Fails = append(o.Fails, c.Name)
			}
		}
	}
	if len(out.Bears) == 0 && len(out.CouldFlip) == 0 {
		return nil
	}
	return out
}

// HintSummary is what lists show of a hint.
type HintSummary struct {
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

func (h *Hint) summary() *HintSummary {
	p := h.Proposal
	out := &HintSummary{ID: p.ID, Verdict: p.Verdict, Justification: p.Justification, Confidence: p.Confidence, Skill: p.Author.Skill,
		Model: p.Author.Model, ResearchJob: p.Author.ResearchJob, Problems: len(h.Policy.Problems), Status: h.Status, Written: p.Timestamp}
	if r := h.Policy.Rule; r != nil {
		out.Rule, out.Decision, out.Title = r.Name, r.Decision, r.Title
	}
	return out
}

// listRow is a row as lists show it, with its research from idx.
func (v *view) listRow(r *rowRef, idx *researchIndex) StateRow {
	m := r.match
	lvl := v.rowResearchLevel(idx, m.Row)
	sr := StateRow{Match: *m, ID: m.Row, MatchID: m.ID, Package: PkgRef{m.Package}, Verdict: verdictOf(r),
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

// GateStatus is a gate and its result, as delta's gate.Status.
type GateStatus struct {
	Name        string      `json:"name"`
	Locator     string      `json:"locator"`
	Description string      `json:"description,omitempty"`
	Note        string      `json:"note,omitempty"`
	Rerun       bool        `json:"rerun,omitempty"`
	Result      *GateResult `json:"result,omitempty"`
}

type GateResult struct {
	Outcome analysis.State `json:"outcome"`
	// CI is what CI reads the outcome as under the gate's undecided policy.
	CI     analysis.State `json:"ci"`
	Checks []CheckResult  `json:"checks"`
}

type CheckResult struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Summary is the check's meaning in a short line, for a list row; Description is in full.
	Summary    string             `json:"summary,omitempty"`
	ValueMeans string             `json:"valueMeans"`
	Counts     string             `json:"counts,omitempty"`
	Direction  string             `json:"direction"`
	Params     map[string]float64 `json:"params,omitempty"`
	Threshold  float64            `json:"threshold"`
	Value      analysis.Value     `json:"value"`
	State      analysis.State     `json:"state"`
	// FailsOn are the rows whose label decides the check: behind its failing (decidingRows).
	FailsOn []string `json:"failsOn,omitempty"`
}

// which side of a check's threshold passes
const (
	atMost  = "atMost"
	atLeast = "atLeast"
)

// checkWords say what each check's value is, what it counts, which side of the threshold passes,
// and its meaning in a short line: the UI's words for checks it draws.
var checkWords = map[string]struct{ means, counts, direction, summary string }{
	analysis.F1NotWorse:             {"the reference's F1 less the candidate's", "f1", atMost, "Candidate F1 must not fall below the reference's"},
	analysis.NoNewFalseNegatives:    {"new false negatives", "fn", atMost, "No true matches lost by the candidate"},
	analysis.NoNewFalsePositives:    {"new false positives", "fp", atMost, "No false matches added by the candidate"},
	analysis.UnjudgedChangesAtMost:  {"unlabeled deltas", "unjudged", atMost, "Unlabeled changes stay under the limit"},
	analysis.UnlabeledPercentAtMost: {"percent of the candidate's matches unlabeled", "unjudged", atMost, "Unlabeled share of the candidate's matches stays under the limit"},
	analysis.ExpectationsMetAtLeast: {"expectations the candidate meets", "", atLeast, "Enough expectations met by the candidate"},
	analysis.NoNewMisses:            {"expectations the candidate newly misses", "", atMost, "No expectations newly missed by the candidate"},
	analysis.MatchesAtLeast:         {"matches both setups report", "", atLeast, "Both setups together report enough matches on every subject"},
}

func (v *view) gateStatus(e *entry) *GateStatus {
	g := v.verdict
	st := &GateStatus{Name: e.name, Locator: e.gate.Path, Description: e.gate.Description}
	if v.stale != "" {
		st.Note, st.Rerun = v.stale, true
		return st
	}
	st.Result = v.result(e.gate, g.Outcome, g.Checks)
	return st
}

// result is a gate's evaluation in delta's result shape.
func (v *view) result(g *gatefile.Gate, outcome analysis.State, checks []analysis.Check) *GateResult {
	res := &GateResult{Outcome: outcome, CI: analysis.Fail}
	if outcome == analysis.Pass || (outcome == analysis.Undecided && g.Undecided == gatefile.UndecidedPass) {
		res.CI = analysis.Pass
	}
	for _, c := range checks {
		w := checkWords[c.Name]
		cr := CheckResult{Name: c.Name, Description: analysis.Registry[c.Name].Description, Summary: w.summary, ValueMeans: w.means, Counts: w.counts,
			Direction: w.direction, Params: c.Params, Threshold: c.Threshold, Value: c.Value, State: c.State}
		if c.Message != "" {
			cr.Description += "; " + c.Message
		}
		cr.FailsOn = v.decidingRows(c)
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
	st := State{Scans: summarize(e, v), Author: s.opts.Author, Gate: v.gateStatus(e), Vocabulary: vocabOf(v.vocab), Warnings: v.verdict.Warnings, OutdatedLookups: v.paired.OutdatedLookups,
		Causes: v.stateCauses(), Explanations: v.stateExplanations()}
	if s.opts.Research != nil {
		a := s.opts.ResearchAvailability
		st.Research = &a
		if a.Available {
			st.ResearchConcurrency = s.opts.Research.Concurrency()
			b := research.Estimate(slices.Collect(maps.Values(idx.byID)), s.opts.Research.Model())
			st.ResearchEstimate = &b
		}
	}
	if c, ok := e.rec.Setups[pairing.Candidate]; ok {
		st.Candidate = &c
	}
	if r, ok := e.rec.Setups[pairing.Reference]; ok {
		st.Reference = &r
	}
	changes, effects, siblings := v.changes(), v.rowEffects(), research.Siblings(v.verdict)
	for si, sub := range v.verdict.Subjects {
		ss := StateSubject{Name: st.Scans.Subjects[si].Name, Slug: st.Scans.Subjects[si].Slug, Changes: changes[si], Rows: []StateRow{}}
		for j := range sub.Matches {
			sr := v.listRow(v.rows[sub.Matches[j].Row], idx)
			sr.Effect = effects[sr.ID]
			sr.ResearchShares = shares(siblings, sr.ID)
			ss.Rows = append(ss.Rows, sr)
		}
		st.Subjects = append(st.Subjects, ss)
	}
	writeJSON(w, st)
}

// shares is the rows researched with id, less id.
func shares(siblings map[string][]string, id string) []string {
	var out []string
	for _, x := range siblings[id] {
		if x != id {
			out = append(out, x)
		}
	}
	return out
}

// changes tallies each subject's changed rows (the ones only one setup reports), in subject order:
// the image rail's counts and the gate list's strip.
func (v *view) changes() []Tally {
	out := make([]Tally, len(v.verdict.Subjects))
	for si, sub := range v.verdict.Subjects {
		for j := range sub.Matches {
			if r := v.rows[sub.Matches[j].Row]; r.match.InCandidate != r.match.InReference {
				out[si].add(verdictOf(r), v.hintFor(r) != nil)
			}
		}
	}
	return out
}

// RunSummary is a gate's scans as the gate list and every page's header show them.
type RunSummary struct {
	ID       string        `json:"id"` // the gate's name
	Created  string        `json:"created"`
	Gate     string        `json:"gate"` // the gate file
	Label    string        `json:"label"`
	Compared string        `json:"compared"`
	Subjects []SubjectInfo `json:"subjects"`
}

type SubjectInfo struct {
	Name string `json:"name"`          // what a person calls it, e.g. wolfi-base
	Slug string `json:"slug"`          // unique within the gate, for URLs
	Ref  string `json:"ref,omitempty"` // the gate's reference, shown on hover
}

// uniqueSlug is name's slug, numbered past any already used, and marks it used: subjects x, x
// and x-2 are x, x-2 and x-2-2.
func uniqueSlug(used map[string]bool, name string) string {
	base := slugify(name)
	slug := base
	for n := 2; used[slug]; n++ {
		slug = fmt.Sprintf("%s-%d", base, n)
	}
	used[slug] = true
	return slug
}

func summarize(e *entry, v *view) RunSummary {
	sum := RunSummary{ID: e.name, Created: e.rec.Created, Gate: e.gate.Path, Compared: compared(v.verdict.Header)}
	used := map[string]bool{}
	var names []string
	for _, s := range e.rec.Subjects {
		name := subjectName(s.Name)
		sum.Subjects = append(sum.Subjects, SubjectInfo{Name: name, Slug: uniqueSlug(used, name), Ref: s.Name})
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

// RowResponse is one row with everything the tile shows of it.
type RowResponse struct {
	Row         StateRow                `json:"row"`
	Subject     string                  `json:"subject"`
	Links       []Link                  `json:"links"`
	Label       *LabelView              `json:"label,omitempty"`
	Hint        *Hint                   `json:"hint,omitempty"`
	Explanation *agentstore.Explanation `json:"explanation,omitempty"`
}

// LabelView is the label deciding a row, as its file holds it, and every source holding its key.
type LabelView struct {
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
	resp := RowResponse{Row: v.listRow(r, idx), Subject: e.rec.Subjects[r.si].Name, Links: Links(r.match), Hint: v.hints[r.match.Row]}
	resp.Row.ResearchShares = shares(research.Siblings(v.verdict), r.match.Row)
	if b := r.pm.Label; b != nil {
		lv := &LabelView{Label: b.Label.Label, File: b.File, Global: b.Global}
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
	out := GateList{Open: s.opts.Open, Gates: []GateListItem{}, LabelSources: []string{}}
	// a label several gates count is one label, as the workspace Labels tab lists it
	distinct := map[string]bool{}
	for _, e := range all {
		v, err := s.view(e)
		if err != nil {
			out.Gates = append(out.Gates, GateListItem{RunSummary: RunSummary{ID: e.name, Created: e.rec.Created, Gate: e.gate.Path}, Error: err.Error(), LabelSources: []string{}})
			continue
		}
		if out.Open == "" {
			out.Open = e.name // the gate scanned last that can be scored
		}
		// stale scans fail the gate, as yardstick score reports them
		l := GateListItem{RunSummary: summarize(e, v), Changes: v.changes(), GateOutcome: analysis.Fail, GateNote: v.stale, LabelSources: []string{}}
		if v.stale == "" {
			l.GateOutcome = v.verdict.Outcome
		}
		for _, gl := range v.gateLabels(images(e, v)) {
			l.Labels++
			ref := "global"
			if gl.Image != nil {
				ref = gl.Image.Ref
			}
			distinct[strings.Join([]string{string(gl.Verdict), gl.Vulnerability, gl.Package.PURL, ref, gl.Source, gl.LastUpdated}, "|")] = true
			for _, srcs := range []*[]string{&l.LabelSources, &out.LabelSources} {
				if !slices.Contains(*srcs, gl.Source) {
					*srcs = append(*srcs, gl.Source)
				}
			}
		}
		slices.Sort(l.LabelSources)
		out.Gates = append(out.Gates, l)
	}
	out.Labels = len(distinct)
	slices.Sort(out.LabelSources)
	writeJSON(w, out)
}

// GateListItem is one gate of GET /api/gates.
type GateListItem struct {
	RunSummary `tstype:",extends"`
	// Changes tallies each subject's changed rows, in Subjects order.
	Changes     []Tally        `json:"changes,omitempty"`
	GateOutcome analysis.State `json:"gateOutcome,omitempty"`
	GateNote    string         `json:"gateNote,omitempty"`
	Error       string         `json:"error,omitempty"`
	// Labels counts the labels the gate counts, as GET labels' total with no filter, and
	// LabelSources names the claims sources they come from, sorted.
	Labels       int      `json:"labels"`
	LabelSources []string `json:"labelSources"`
}

// GateList is GET /api/gates: every gate scanned under the run, and the one to open first: the one
// the command line named, else the one scanned last that can be scored.
type GateList struct {
	Open  string         `json:"open"`
	Gates []GateListItem `json:"gates"`
	// Labels counts the labels across every gate, one counted by several gates once, and
	// LabelSources names their claims sources, sorted: what the gates screen shows without
	// reading every label.
	Labels       int      `json:"labels"`
	LabelSources []string `json:"labelSources"`
}
