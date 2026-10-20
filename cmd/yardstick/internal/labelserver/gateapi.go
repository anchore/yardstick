package labelserver

import (
	"cmp"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
)

// The tables of the /ui/gates/ pages: a check's findings and the labels a gate counts.

// ImageRef is an image as the tables name it: name and slug as SubjectInfo, and the full reference.
type ImageRef struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
	Ref  string `json:"ref"`
}

// PackageInfo is a package as the tables show it.
type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

// Tally counts findings by label state. Open is unlabeled (unclear is apart), and Hinted counts
// the open ones with a pending agent hint or cause, so tp, fp, unclear, hinted and open less
// hinted add up to total, which the UI's verdict bars rely on.
type Tally struct {
	TP      int `json:"tp"`
	FP      int `json:"fp"`
	Unclear int `json:"unclear"`
	Hinted  int `json:"hinted"`
	Open    int `json:"open"`
	Total   int `json:"total"`
}

func (t *Tally) add(verdict string, hinted bool) {
	t.Total++
	switch verdict {
	case string(claimsv1.TP):
		t.TP++
	case string(claimsv1.FP):
		t.FP++
	case string(claimsv1.Unclear):
		t.Unclear++
	default:
		t.Open++
		if hinted {
			t.Hinted++
		}
	}
}

// what a finding's label does for the check
const (
	effectDecides   = "decides"    // a label behind the check failing
	effectCouldMove = "could-move" // open, and a tp or fp label alone changes the check's state
	effectCounted   = "counted"    // anything else the check counts
)

type FindingLabel struct {
	Verdict       string `json:"verdict"` // tp, fp or unclear
	Justification string `json:"justification,omitempty"`
	Source        string `json:"source"`
}

// FindingHint is the agent's pending suggestion on an open row: its own proposal, else a cause
// listing it.
type FindingHint struct {
	Verdict    claimsv1.Verdict `json:"verdict"`
	Confidence string           `json:"confidence,omitempty"`
	Kind       string           `json:"kind"` // proposal or cause
}

type Finding struct {
	// Row is absent for an unmet expectation no match of either setup pairs.
	Row           string        `json:"row,omitempty"`
	Image         ImageRef      `json:"image"`
	Vulnerability string        `json:"vulnerability"`
	Package       PackageInfo   `json:"package"`
	Direction     string        `json:"direction"` // added, dropped, both or neither
	Label         *FindingLabel `json:"label" tstype:"FindingLabel | null"`
	Hint          *FindingHint  `json:"hint" tstype:"FindingHint | null"`
	Effect        string        `json:"effect"` // decides, could-move or counted
}

// CheckFindings is GET checks/{check}/findings.
type CheckFindings struct {
	Check CheckResult `json:"check"`
	Note  string      `json:"note,omitempty"` // why the scans no longer apply, when they do not
	// Images tallies the findings per image slug, every image of the gate present.
	Images   map[string]Tally `json:"images"`
	Findings []Finding        `json:"findings"`
}

// images are the gate's subjects as the tables name them, in gate order.
func images(e *entry, v *view) []ImageRef {
	var out []ImageRef
	for _, s := range summarize(e, v).Subjects {
		out = append(out, ImageRef(s))
	}
	return out
}

func labelOf(b *pairing.Bound, verdict string) *FindingLabel {
	if b == nil || verdict == unlabeled {
		return nil
	}
	return &FindingLabel{Verdict: verdict, Justification: b.Justification, Source: b.Held[0].Source}
}

// hintFor is an open row's pending hint: its proposal, else a cause it is a pending member of.
func (v *view) hintFor(r *rowRef) *FindingHint {
	id := r.match.Row
	if h := v.hints[id]; h != nil && r.open() { // a hint on an open row is pending
		return &FindingHint{Verdict: h.Proposal.Verdict, Confidence: h.Proposal.Confidence, Kind: "proposal"}
	}
	for _, cv := range v.rowCauses[id] {
		if v.memberState(cv, id) == memberPending {
			return &FindingHint{Verdict: cv.Verdict, Confidence: cv.Confidence, Kind: "cause"}
		}
	}
	return nil
}

func (v *view) finding(r *rowRef, imgs []ImageRef, effect string) Finding {
	verdict := verdictOf(r)
	return Finding{Row: r.match.Row, Image: imgs[r.si], Vulnerability: r.match.Vulnerability,
		Package:   PackageInfo{Name: r.pm.Package.Name, Version: r.pm.Package.Version, PURL: r.match.Package},
		Direction: direction(r.match), Label: labelOf(r.pm.Label, verdict), Hint: v.hintFor(r), Effect: effect}
}

// checkFindings are every finding a check counts. Per subject: the labeled matches behind its
// value (decides where the subject fails it, else counted), the open ones it counts, and any open
// row whose label narrows or changes it (could-move when a label alone changes its state). A
// per-gate check counts its unmet expectations, which decide it when it fails.
func (v *view) checkFindings(c analysis.Check, imgs []ImageRef) []Finding {
	var out []Finding
	seen := map[string]bool{}
	add := func(id, effect string) {
		if r := v.rows[id]; r != nil && !seen[id] {
			seen[id] = true
			out = append(out, v.finding(r, imgs, effect))
		}
	}
	for _, sc := range c.Subjects {
		for _, id := range sc.FailsOn {
			add(pairing.RowID(sc.Subject, id), map[bool]string{true: effectDecides, false: effectCounted}[sc.State == analysis.Fail])
		}
	}
	// open rows in report order: what the analysis counts, and what a label moves
	counted := map[string]bool{}
	for _, sc := range c.Subjects {
		for _, id := range sc.Rows {
			counted[pairing.RowID(sc.Subject, id)] = true
		}
	}
	for _, r := range v.orderedRows() {
		id := r.match.Row
		eff := v.effectOf(id)
		switch {
		case eff != nil && slices.Contains(eff.CouldFlip, c.Name):
			add(id, effectCouldMove)
		case counted[id] || (eff != nil && slices.Contains(eff.Bears, c.Name)):
			add(id, effectCounted)
		}
	}
	for _, x := range c.Unmet {
		out = append(out, v.unmetFinding(x, imgs, map[bool]string{true: effectDecides, false: effectCounted}[c.State == analysis.Fail]))
	}
	rank := map[string]int{effectDecides: 0, effectCouldMove: 1, effectCounted: 2}
	slices.SortStableFunc(out, func(a, b Finding) int { return cmp.Compare(rank[a.Effect], rank[b.Effect]) })
	return out
}

// unmetFinding is an unmet expectation as a finding, on the row of a match its label pairs when
// one does.
func (v *view) unmetFinding(x analysis.Expectation, imgs []ImageRef, effect string) Finding {
	f := Finding{Vulnerability: x.Vulnerability, Package: PackageInfo{PURL: x.Package}, Direction: "neither", Effect: effect,
		Label: &FindingLabel{Verdict: string(x.Verdict)}}
	for si, in := range v.paired.Inputs {
		if in.Name != x.Subject {
			continue
		}
		f.Image = imgs[si]
		for _, b := range in.Result.Labels {
			if b.Package != x.Package || b.Vulnerability != x.Vulnerability || b.Verdict != x.Verdict || b.Disagrees() {
				continue
			}
			f.Package.Name, f.Package.Version = b.Fields.Name, b.Fields.Version
			f.Label = labelOf(b, string(x.Verdict))
			if len(b.Matches) > 0 {
				if r := v.rows[pairing.RowID(x.Subject, analysis.MatchID(b.Matches[0]))]; r != nil {
					return v.finding(r, imgs, effect)
				}
			}
			return f
		}
	}
	return f
}

func (s *Server) handleCheckFindings(w http.ResponseWriter, req *http.Request) {
	e, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	i := slices.IndexFunc(v.verdict.Checks, func(c analysis.Check) bool { return c.Name == req.PathValue("check") })
	if i < 0 {
		http.Error(w, "the gate has no check "+req.PathValue("check"), http.StatusNotFound)
		return
	}
	c := v.verdict.Checks[i]
	imgs := images(e, v)
	out := CheckFindings{Check: v.result(e.gate, v.verdict.Outcome, []analysis.Check{c}).Checks[0], Note: v.stale, Images: map[string]Tally{},
		Findings: v.checkFindings(c, imgs)}
	for _, img := range imgs {
		out.Images[img.Slug] = Tally{}
	}
	for _, f := range out.Findings {
		t := out.Images[f.Image.Slug]
		verdict := unlabeled
		if f.Label != nil {
			verdict = f.Label.Verdict
		}
		t.add(verdict, f.Hint != nil)
		out.Images[f.Image.Slug] = t
	}
	writeJSON(w, out)
}

// GateLabel is one label the gate counts.
type GateLabel struct {
	Verdict       claimsv1.Verdict `json:"verdict"`
	Justification string           `json:"justification,omitempty"`
	Vulnerability string           `json:"vulnerability"`
	Package       PackageInfo      `json:"package"`
	// Image is the subject the label is about; null for a global label.
	Image       *ImageRef       `json:"image" tstype:"ImageRef | null"`
	Source      string          `json:"source"` // the first claims source holding it
	Author      string          `json:"author"`
	Notes       []claimsv1.Note `json:"notes,omitempty"`
	FirstIssued string          `json:"firstIssued"`
	LastUpdated string          `json:"lastUpdated"`
	// Decides are the checks this label is behind the failure of.
	Decides []string `json:"decides" tstype:"string[]"`
	// Row is the first changed row this label is the deciding label of (the most specific one
	// pairing it), absent when there is none.
	Row string `json:"row,omitempty"`
}

// GateLabels is GET labels: one page of the gate's labels, newest first. Counts are by verdict
// under every filter but verdict, and PerImage by image slug under every filter but image, so
// chips and the rail show what picking them would give.
type GateLabels struct {
	Total    int            `json:"total"`
	Counts   map[string]int `json:"counts"`
	PerImage map[string]int `json:"perImage"`
	Sources  []string       `json:"sources"`
	Labels   []GateLabel    `json:"labels"`
}

// gateLabel is a label the gate counts and the image indexes it applies to.
type gateLabel struct {
	GateLabel
	subjects []int
}

// deciders are the checks a label is behind the failure of: by the row it decides, and for a
// per-gate check by the unmet expectation (expectationKey) it is.
func (v *view) deciders() (byRow, byExpectation map[string][]string) {
	byRow, byExpectation = map[string][]string{}, map[string][]string{}
	for _, c := range v.verdict.Checks {
		for _, sc := range c.Subjects {
			for _, id := range sc.FailsOn {
				if sc.State == analysis.Fail {
					byRow[pairing.RowID(sc.Subject, id)] = append(byRow[pairing.RowID(sc.Subject, id)], c.Name)
				}
			}
		}
		for _, x := range c.Unmet {
			if c.State == analysis.Fail {
				k := expectationKey(x.Subject, x.Package, x.Vulnerability, x.Verdict)
				byExpectation[k] = append(byExpectation[k], c.Name)
			}
		}
	}
	return byRow, byExpectation
}

func expectationKey(subject, pkg, vuln string, verdict claimsv1.Verdict) string {
	return subject + "|" + pkg + "|" + vuln + "|" + string(verdict)
}

func newGateLabel(b *pairing.Bound) *gateLabel {
	l := b.Label.Label
	return &gateLabel{GateLabel: GateLabel{Verdict: l.Verdict, Justification: l.Justification, Vulnerability: l.Vulnerability,
		Package: PackageInfo{Name: b.Fields.Name, Version: b.Fields.Version, PURL: l.Package}, Source: b.Held[0].Source,
		Author: l.Author, Notes: l.Notes, FirstIssued: l.FirstIssued, LastUpdated: l.LastUpdated, Decides: []string{}}}
}

func (gl *gateLabel) decides(checks []string) {
	for _, c := range checks {
		if !slices.Contains(gl.Decides, c) {
			gl.Decides = append(gl.Decides, c)
		}
	}
}

// gateLabels are the labels the gate counts, newest first: each subject's labels, and the global
// labels that apply to its packages once, across subjects.
func (v *view) gateLabels(imgs []ImageRef) []*gateLabel {
	byRow, byExpectation := v.deciders()
	var out []*gateLabel
	globals := map[claimsv1.Key]*gateLabel{}
	for si, in := range v.paired.Inputs {
		for _, b := range in.Result.Labels {
			gl := globals[b.Key()]
			if !b.Global || gl == nil {
				gl = newGateLabel(b)
				if b.Global {
					globals[b.Key()] = gl
				} else {
					gl.Image = &imgs[si]
				}
				out = append(out, gl)
			}
			gl.subjects = append(gl.subjects, si)
			for _, m := range b.Matches {
				if m.Label != b {
					continue // a more specific label decides it
				}
				id := pairing.RowID(in.Name, analysis.MatchID(m))
				gl.decides(byRow[id])
				if r := v.rows[id]; gl.Row == "" && r != nil && r.match.InCandidate != r.match.InReference {
					gl.Row = id
				}
			}
			gl.decides(byExpectation[expectationKey(in.Name, b.Package, b.Vulnerability, b.Verdict)])
		}
	}
	slices.SortStableFunc(out, func(a, b *gateLabel) int { return strings.Compare(b.LastUpdated, a.LastUpdated) })
	return out
}

// labelQuery is GET labels' query: filters, and the page.
type labelQuery struct {
	verdict, source, text string
	image                 int // index into the gate's images, -1 for any
	offset, limit         int
}

func parseLabelQuery(q url.Values, imgs []ImageRef) (labelQuery, int, error) {
	lq := labelQuery{verdict: q.Get("verdict"), source: q.Get("source"), text: strings.ToLower(q.Get("q")), image: -1, limit: 50}
	for name, into := range map[string]*int{"offset": &lq.offset, "limit": &lq.limit} {
		if s := q.Get(name); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 0 {
				return lq, http.StatusBadRequest, fmt.Errorf("%s must be a whole number", name)
			}
			*into = n
		}
	}
	if slug := q.Get("image"); slug != "" {
		if lq.image = slices.IndexFunc(imgs, func(i ImageRef) bool { return i.Slug == slug }); lq.image < 0 {
			return lq, http.StatusNotFound, fmt.Errorf("the gate has no image %s", slug)
		}
	}
	return lq, 0, nil
}

func (s *Server) handleGateLabels(w http.ResponseWriter, req *http.Request) {
	e, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	imgs := images(e, v)
	lq, code, err := parseLabelQuery(req.URL.Query(), imgs)
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	out := GateLabels{Counts: map[string]int{string(claimsv1.TP): 0, string(claimsv1.FP): 0, string(claimsv1.Unclear): 0}, PerImage: map[string]int{},
		Sources: []string{}, Labels: []GateLabel{}}
	for _, img := range imgs {
		out.PerImage[img.Slug] = 0
	}
	for _, l := range v.gateLabels(imgs) {
		if !slices.Contains(out.Sources, l.Source) {
			out.Sources = append(out.Sources, l.Source)
		}
		if (lq.source != "" && l.Source != lq.source) || (lq.text != "" && !matchesText(&l.GateLabel, lq.text)) {
			continue
		}
		inImage, isVerdict := lq.image < 0 || slices.Contains(l.subjects, lq.image), lq.verdict == "" || string(l.Verdict) == lq.verdict
		if inImage {
			out.Counts[string(l.Verdict)]++
		}
		for _, si := range l.subjects {
			if isVerdict {
				out.PerImage[imgs[si].Slug]++
			}
		}
		if !inImage || !isVerdict {
			continue
		}
		if out.Total >= lq.offset && len(out.Labels) < lq.limit {
			out.Labels = append(out.Labels, l.GateLabel)
		}
		out.Total++
	}
	slices.Sort(out.Sources)
	writeJSON(w, out)
}

// matchesText is the free-text filter: vulnerability, package, justification, author or a note.
func matchesText(l *GateLabel, text string) bool {
	for _, s := range []string{l.Vulnerability, l.Package.PURL, l.Justification, l.Author} {
		if strings.Contains(strings.ToLower(s), text) {
			return true
		}
	}
	return slices.ContainsFunc(l.Notes, func(n claimsv1.Note) bool { return strings.Contains(strings.ToLower(n.Text), text) })
}
