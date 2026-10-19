package labelserver

import (
	"cmp"
	"net/http"
	"slices"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
)

// The cross-gate view: a label is about a package in a subject and a vulnerability, not about a
// gate, so one label counts in every gate whose scans report that match. This joins the open rows
// of every gate on what a label is about, and says, per gate, what labeling the match would do.

type SharedState struct {
	Gates      []GateSummary  `json:"gates"`
	Findings   []CrossFinding `json:"findings"`
	Vocabulary *Vocabulary    `json:"vocabulary,omitempty"`
}

type GateSummary struct {
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Compared    string             `json:"compared"`
	Images      int                `json:"images"`
	Outcome     analysis.State     `json:"outcome"`
	Note        string             `json:"note,omitempty"`
	Checks      []GateCheckSummary `json:"checks,omitempty"`
	Open        int                `json:"open"` // open rows that bear on a check
}

type GateCheckSummary struct {
	Name       string         `json:"name"`
	State      analysis.State `json:"state"`
	ValueMeans string         `json:"valueMeans"`
}

// CrossFinding is one open match, as a label would name it, and where it appears.
type CrossFinding struct {
	Key           string       `json:"key"`
	Vulnerability string       `json:"vulnerability"`
	Package       PkgRef       `json:"package"`
	SourcePackage string       `json:"sourcePackage"`
	Image         string       `json:"image"`
	Hint          *HintSummary `json:"hint,omitempty"`
	Cause         *CrossCause  `json:"cause,omitempty"`
	// In is every gate whose scans report it; Bears and Flips count the gates where its label
	// narrows a check, or alone changes one.
	In    []CrossAppearance `json:"in"`
	Bears int               `json:"bears"`
	Flips int               `json:"flips"`
}

type CrossCause struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Gate  string `json:"gate"` // a gate to accept it in
}

type CrossAppearance struct {
	Gate   string     `json:"gate"`
	Row    string     `json:"row"`
	Dir    string     `json:"dir"`
	Effect *RowEffect `json:"effect,omitempty"`
}

func (s *Server) handleShared(w http.ResponseWriter, _ *http.Request) {
	all, err := s.entries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := SharedState{Gates: []GateSummary{}, Findings: []CrossFinding{}}
	j := &join{byKey: map[string]*CrossFinding{}}
	for _, e := range all {
		v, err := s.view(e)
		if err != nil {
			// one gate that cannot be scored (a remote claims source offline) leaves the rest
			out.Gates = append(out.Gates, GateSummary{Name: e.name, Description: e.gate.Description, Outcome: analysis.Undecided, Note: err.Error()})
			continue
		}
		if out.Vocabulary == nil {
			out.Vocabulary = vocabOf(v.vocab)
		}
		out.Gates = append(out.Gates, j.add(e, v))
	}
	for _, k := range j.order {
		if f := j.byKey[k]; f.Bears > 0 {
			out.Findings = append(out.Findings, *f)
		}
	}
	// the most gates decided first, then the most gates narrowed
	slices.SortStableFunc(out.Findings, func(a, b CrossFinding) int {
		return cmp.Or(cmp.Compare(b.Flips, a.Flips), cmp.Compare(b.Bears, a.Bears))
	})
	writeJSON(w, out)
}

// join collects the open deltas of every gate, by what a label about them is about.
type join struct {
	byKey map[string]*CrossFinding
	order []string // first seen first
}

// add summarizes a gate and joins its open deltas.
func (j *join) add(e *entry, v *view) GateSummary {
	sum := summarize(e, v)
	g := GateSummary{Name: e.name, Description: e.gate.Description, Compared: sum.Compared, Images: len(sum.Subjects), Outcome: analysis.Undecided, Note: v.stale}
	if v.stale != "" {
		return g // nothing is open in a gate that cannot be judged
	}
	g.Outcome = v.verdict.Outcome
	for _, c := range v.verdict.Checks {
		g.Checks = append(g.Checks, GateCheckSummary{Name: c.Name, State: c.State, ValueMeans: checkWords[c.Name].means})
	}
	for _, r := range v.orderedRows() {
		dir := direction(r.match)
		if !r.open() || (dir != "added" && dir != "dropped") {
			continue
		}
		key := subjectKey(&e.rec.Subjects[r.si]) + "|" + r.match.Package + "|" + cmp.Or(r.match.Group, r.match.Vulnerability)
		f := j.byKey[key]
		if f == nil {
			f = &CrossFinding{Key: key, Vulnerability: r.match.Vulnerability, Package: PkgRef{r.match.Package}, SourcePackage: r.match.SourcePackage,
				Image: sum.Subjects[r.si].Name}
			j.byKey[key] = f
			j.order = append(j.order, key)
		}
		if h := v.hints[r.match.Row]; f.Hint == nil && h != nil {
			f.Hint = h.summary()
		}
		if cs := v.rowCauses[r.match.Row]; f.Cause == nil && len(cs) > 0 {
			f.Cause = &CrossCause{ID: cs[0].ID, Title: cs[0].Title, Gate: e.name}
		}
		eff := v.effectOf(r.match.Row)
		f.In = append(f.In, CrossAppearance{Gate: e.name, Row: r.match.Row, Dir: dir, Effect: eff})
		if eff != nil {
			f.Bears++
			g.Open++
			if len(eff.CouldFlip) > 0 {
				f.Flips++
			}
		}
	}
	return g
}
