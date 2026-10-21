package analysis

import (
	"fmt"
	"math"
	"sort"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
)

// State is a check's or a gate's outcome.
type State string

const (
	Pass      State = "pass"
	Fail      State = "fail"
	Undecided State = "undecided"
)

// worse orders states: fail over undecided over pass.
func worse(a, b State) State {
	rank := map[State]int{Pass: 0, Undecided: 1, Fail: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// Value is a check's value in the worst and the best case for the candidate.
type Value struct {
	Worst float64 `json:"worst"`
	Best  float64 `json:"best"`
}

// Subject is one subject's paired matches and labels.
type Subject struct {
	Name   string
	Result *pairing.Result
}

// SubjectCheck is a per-subject check on one subject.
type SubjectCheck struct {
	Subject string `json:"subject"`
	Value   Value  `json:"value"`
	State   State  `json:"state"`
	Message string `json:"message,omitempty"`
	// FailsOn are the labeled matches that put the value over the threshold.
	FailsOn []string `json:"failsOn,omitempty"`
	// Rows are the unlabeled matches whose label can still move the value.
	Rows []string `json:"rows,omitempty"`
}

// Expectation is a tp or fp label that applies to a subject, and whether each setup met it.
type Expectation struct {
	Subject       string           `json:"subject"`
	Package       string           `json:"package,omitempty"`
	Vulnerability string           `json:"vulnerability"`
	Verdict       claimsv1.Verdict `json:"verdict"`
	Met           map[string]bool  `json:"met"`
}

// Check is one check's result for a gate.
type Check struct {
	Name      string             `json:"name"`
	Scope     Scope              `json:"scope"`
	Params    map[string]float64 `json:"params,omitempty"`
	Threshold float64            `json:"threshold"`
	// Value is the worst subject's for a per-subject check, the gate's sum for a per-gate one.
	Value    Value          `json:"value"`
	State    State          `json:"state"`
	Message  string         `json:"message,omitempty"`
	FailsOn  []string       `json:"failsOn,omitempty"`
	Subjects []SubjectCheck `json:"subjects,omitempty"`
	// Unmet are the expectations a per-gate check found unmet.
	Unmet []Expectation `json:"unmet,omitempty"`
}

// Effect is what labeling one unlabeled match only one setup reports would do.
type Effect struct {
	Subject string `json:"subject"`
	Match   string `json:"match"`
	// Narrows are the undecided checks whose range labeling the match narrows.
	Narrows []string `json:"narrows,omitempty"`
	// States are each check's state, and Outcome the gate's, were the match labeled tp or fp.
	States  map[claimsv1.Verdict]map[string]State `json:"states"`
	Outcome map[claimsv1.Verdict]State            `json:"outcome"`
}

// Gate is a gate's checks evaluated.
type Gate struct {
	Outcome State    `json:"outcome"`
	Checks  []Check  `json:"checks"`
	Effects []Effect `json:"effects,omitempty"`
}

// MatchID names a match within its subject.
func MatchID(m *pairing.Match) string {
	return m.PackageID + "/" + m.Group
}

// Evaluate computes every check of a gate over its subjects at the worst and the best case for the
// candidate, and, per unlabeled delta, what labeling it would change. Nothing here reads a flag:
// the result is the verdict set renderers show.
func Evaluate(checks []gatefile.Check, subjects []Subject) Gate {
	e := evaluator{checks: checks, subjects: subjects}
	g := e.gate()
	g.Effects = e.effects(g)
	return g
}

// EvaluateAs computes every check as if the given matches were labeled so, leaving out the
// per-delta effects: what the label server previews before anything is written.
func EvaluateAs(checks []gatefile.Check, subjects []Subject, hyp map[*pairing.Match]claimsv1.Verdict) Gate {
	return evaluator{checks: checks, subjects: subjects, hyp: hyp}.gate()
}

type evaluator struct {
	checks   []gatefile.Check
	subjects []Subject
	// hyp labels matches hypothetically, to work out what labeling them would do
	hyp map[*pairing.Match]claimsv1.Verdict
}

func (e evaluator) gate() Gate {
	g := Gate{Outcome: Pass}
	for _, c := range e.checks {
		res := e.check(c)
		g.Outcome = worse(g.Outcome, res.State)
		g.Checks = append(g.Checks, res)
	}
	return g
}

func (e evaluator) check(c gatefile.Check) Check {
	defer log.Timed("evaluating check %s", c.Name)()
	res := e.evalCheck(c)
	log.Debugf("check %s: worst %v, best %v, %s", c.Name, res.Value.Worst, res.Value.Best, res.State)
	return res
}

func (e evaluator) evalCheck(c gatefile.Check) Check {
	def := Registry[c.Name]
	res := Check{Name: c.Name, Scope: def.Scope, Params: c.Params, State: Pass}
	if def.Scope == PerGate {
		return e.gateCheck(c, res)
	}
	res.Threshold = threshold(c)
	// the worst subject is the highest value, or for an at-least check the lowest
	beyond := func(a, b float64) bool { return a > b }
	if c.Name == MatchesAtLeast {
		beyond = func(a, b float64) bool { return a < b }
	}
	first := true
	for _, s := range e.subjects {
		sc := e.subjectCheck(c, s)
		res.Subjects = append(res.Subjects, sc)
		res.State = worse(res.State, sc.State)
		res.FailsOn = append(res.FailsOn, sc.FailsOn...)
		if first || beyond(sc.Value.Worst, res.Value.Worst) {
			res.Value.Worst = sc.Value.Worst
		}
		if first || beyond(sc.Value.Best, res.Value.Best) {
			res.Value.Best = sc.Value.Best
		}
		first = false
	}
	return res
}

func threshold(c gatefile.Check) float64 {
	for _, k := range []string{"tolerance", paramMax, paramMin} {
		if v, ok := c.Params[k]; ok {
			return v
		}
	}
	return 0
}

// decide is a check's state from its value at both extremes: a check fails when its value is
// above the threshold, so it passes when even the worst case is not, and fails when even the best
// case is.
func decide(v Value, threshold float64) State {
	switch {
	case v.Worst <= threshold:
		return Pass
	case v.Best > threshold:
		return Fail
	}
	return Undecided
}

// the two cases a check is computed in
type extreme int

const (
	worstCase extreme = iota
	bestCase
	// asLabeled counts only labeled matches, for the counts a report prints
	asLabeled
)

// Counts are a setup's counts on a subject as labeled: unlabeled matches are left out of the
// ratios and counted apart.
func Counts(r *pairing.Result, setup string) Stats {
	return evaluator{}.stats(r, setup, asLabeled)
}

// verdict is how a match counts in a case: its own verdict, a hypothetical one, or for an
// unlabeled match only one setup reports, the one the case gives it. Empty leaves it out.
func (e evaluator) verdict(m *pairing.Match, x extreme) claimsv1.Verdict {
	if v, ok := e.hyp[m]; ok {
		return v
	}
	if !m.Unlabeled() {
		return m.Verdict
	}
	if x == asLabeled {
		return ""
	}
	cand, ref := m.In(pairing.Candidate), m.In(pairing.Reference)
	switch {
	case cand && !ref && x == worstCase, ref && !cand && x == bestCase:
		return claimsv1.FP
	case cand && !ref, ref && !cand:
		return claimsv1.TP
	}
	return ""
}

// unit is a tp label of a subject, real or hypothetical, and the setups satisfying it.
type unit struct {
	cand, ref bool
	// matches are the matches satisfying it, for failsOn
	matches []*pairing.Match
}

// units are a subject's tp labels in a case: every tp label that applies, plus each match the
// case or a hypothesis calls tp that no tp label pairs.
func (e evaluator) units(r *pairing.Result, x extreme) []unit {
	var out []unit
	for _, b := range r.Labels {
		if b.Verdict == claimsv1.TP {
			out = append(out, unit{cand: b.PairedIn(pairing.Candidate), ref: b.PairedIn(pairing.Reference), matches: b.Matches})
		}
	}
	for _, m := range r.Matches {
		if (m.Unlabeled() || e.hyp[m] != "") && e.verdict(m, x) == claimsv1.TP && !pairedByTP(m) {
			out = append(out, unit{cand: m.In(pairing.Candidate), ref: m.In(pairing.Reference), matches: []*pairing.Match{m}})
		}
	}
	return out
}

func pairedByTP(m *pairing.Match) bool {
	for _, b := range m.Paired {
		if b.Verdict == claimsv1.TP {
			return true
		}
	}
	return false
}

// Stats are one setup's counts on one subject in one case.
type Stats struct {
	TP, FP, Unlabeled int
	Labels, Satisfied int
}

func (s Stats) Precision() float64 {
	if s.TP+s.FP == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FP)
}

func (s Stats) Recall() float64 {
	if s.Labels == 0 {
		return 1
	}
	return float64(s.Satisfied) / float64(s.Labels)
}

// F1 is 2PR/(P+R) from precision over matches and recall over labels, never from one shared
// true-positive count.
func (s Stats) F1() float64 {
	p, r := s.Precision(), s.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func (e evaluator) stats(r *pairing.Result, setup string, x extreme) Stats {
	var s Stats
	for _, m := range r.Matches {
		if !m.In(setup) {
			continue
		}
		switch e.verdict(m, x) {
		case claimsv1.TP:
			s.TP++
		case claimsv1.FP:
			s.FP++
		default:
			s.Unlabeled++
		}
	}
	for _, u := range e.units(r, x) {
		s.Labels++
		if (setup == pairing.Candidate && u.cand) || (setup == pairing.Reference && u.ref) {
			s.Satisfied++
		}
	}
	return s
}

// hasLabels says whether any tp or fp label applies to the subject, or a hypothesis would give it one.
func (e evaluator) hasLabels(r *pairing.Result) bool {
	for _, b := range r.Labels {
		if b.Verdict == claimsv1.TP || b.Verdict == claimsv1.FP {
			return true
		}
	}
	for _, m := range r.Matches {
		if v := e.hyp[m]; v == claimsv1.TP || v == claimsv1.FP {
			return true
		}
	}
	return false
}

func delta(m *pairing.Match) bool {
	return m.In(pairing.Candidate) != m.In(pairing.Reference)
}

func (e evaluator) subjectCheck(c gatefile.Check, s Subject) SubjectCheck {
	r := s.Result
	sc := SubjectCheck{Subject: s.Name}
	readsLabels := c.Name == F1NotWorse || c.Name == NoNewFalseNegatives || c.Name == NoNewFalsePositives
	if readsLabels && !e.hasLabels(r) {
		sc.State, sc.Message = Fail, "no tp or fp label applies to this subject"
		return sc
	}
	var values [2]float64
	for _, x := range []extreme{worstCase, bestCase} {
		switch c.Name {
		case F1NotWorse:
			values[x] = e.stats(r, pairing.Reference, x).F1() - e.stats(r, pairing.Candidate, x).F1()
		case NoNewFalseNegatives:
			values[x] = float64(len(e.newFalseNegatives(r, x)))
		case NoNewFalsePositives:
			values[x] = float64(len(e.newFalsePositives(r, x)))
		case UnjudgedChangesAtMost:
			if x == worstCase {
				values[x] = float64(len(e.unlabeledDeltas(r)))
			}
		case UnlabeledPercentAtMost:
			if x == worstCase {
				st := e.stats(r, pairing.Candidate, x)
				if n := st.TP + st.FP + st.Unlabeled; n > 0 {
					values[x] = 100 * float64(e.unlabeledIn(r, pairing.Candidate)) / float64(n)
				}
			}
		case MatchesAtLeast:
			// labels do not move a count of matches, so both cases are the same
			values[x] = float64(e.matchesIn(r, pairing.Candidate))
		}
	}
	sc.Value = Value{Worst: values[worstCase], Best: values[bestCase]}
	sc.State = decide(sc.Value, threshold(c))
	if c.Name == MatchesAtLeast {
		sc.State = Pass
		if sc.Value.Worst < c.Params[paramMin] {
			sc.State = Fail
		}
	}
	sc.FailsOn, sc.Rows = e.rows(c, r)
	return sc
}

// newFalseNegatives are the tp labels the reference satisfies and the candidate does not.
func (e evaluator) newFalseNegatives(r *pairing.Result, x extreme) []unit {
	var out []unit
	for _, u := range e.units(r, x) {
		if u.ref && !u.cand {
			out = append(out, u)
		}
	}
	return out
}

// newFalsePositives are the candidate matches counted fp that the reference did not report.
func (e evaluator) newFalsePositives(r *pairing.Result, x extreme) []*pairing.Match {
	var out []*pairing.Match
	for _, m := range r.Matches {
		if m.In(pairing.Candidate) && !m.In(pairing.Reference) && e.verdict(m, x) == claimsv1.FP {
			out = append(out, m)
		}
	}
	return out
}

// unlabeled says whether a match is unlabeled after any hypothesis.
func (e evaluator) unlabeled(m *pairing.Match) bool {
	return m.Unlabeled() && e.hyp[m] == ""
}

func (e evaluator) unlabeledDeltas(r *pairing.Result) []*pairing.Match {
	var out []*pairing.Match
	for _, m := range r.Matches {
		if e.unlabeled(m) && delta(m) {
			out = append(out, m)
		}
	}
	return out
}

func (e evaluator) matchesIn(r *pairing.Result, setup string) int {
	n := 0
	for _, m := range r.Matches {
		if m.In(setup) {
			n++
		}
	}
	return n
}

func (e evaluator) unlabeledIn(r *pairing.Result, setup string) int {
	n := 0
	for _, m := range r.Matches {
		if m.In(setup) && e.unlabeled(m) {
			n++
		}
	}
	return n
}

// rows are, for a check on a subject, the labeled matches behind its value (failsOn) and the
// unlabeled ones whose label can still move it.
func (e evaluator) rows(c gatefile.Check, r *pairing.Result) (failsOn, rows []string) {
	for _, m := range r.Matches {
		if e.unlabeled(m) && counts(c.Name, m) {
			rows = append(rows, MatchID(m))
		}
	}
	var behind []*pairing.Match
	switch c.Name {
	case NoNewFalseNegatives:
		for _, u := range e.newFalseNegatives(r, bestCase) {
			behind = append(behind, u.matches...)
		}
	case NoNewFalsePositives:
		behind = e.newFalsePositives(r, bestCase)
	case F1NotWorse:
		for _, m := range r.Matches {
			if !e.unlabeled(m) && delta(m) {
				behind = append(behind, m)
			}
		}
	}
	for _, m := range behind {
		if c.Name != NoNewFalseNegatives || m.In(pairing.Reference) {
			failsOn = append(failsOn, MatchID(m))
		}
	}
	return unique(failsOn), unique(rows)
}

// counts says whether a check counts an unlabeled match: its label can move the check's value.
func counts(check string, m *pairing.Match) bool {
	cand, ref := m.In(pairing.Candidate), m.In(pairing.Reference)
	switch check {
	case F1NotWorse, UnjudgedChangesAtMost:
		return cand != ref
	case NoNewFalseNegatives:
		return ref && !cand
	case NoNewFalsePositives:
		return cand && !ref
	case UnlabeledPercentAtMost:
		return cand
	}
	return false
}

func unique(s []string) []string {
	sort.Strings(s)
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// expectations are the tp and fp labels that apply to the gate's subjects, each met or not per
// setup: a tp when some match of the setup pairs it, an fp when none does.
func (e evaluator) expectations() []Expectation {
	var out []Expectation
	for _, s := range e.subjects {
		for _, b := range s.Result.Labels {
			if b.Verdict != claimsv1.TP && b.Verdict != claimsv1.FP {
				continue
			}
			x := Expectation{Subject: s.Name, Package: b.Package, Vulnerability: b.Vulnerability, Verdict: b.Verdict, Met: map[string]bool{}}
			for _, setup := range []string{pairing.Candidate, pairing.Reference} {
				x.Met[setup] = b.PairedIn(setup) == (b.Verdict == claimsv1.TP)
			}
			out = append(out, x)
		}
	}
	return out
}

func (e evaluator) gateCheck(c gatefile.Check, res Check) Check {
	exps := e.expectations()
	if len(exps) == 0 {
		res.State, res.Message = Fail, "no expectations apply to the gate's subjects: no tp or fp label applies to any of them"
		return res
	}
	met, lost := 0, 0
	for _, x := range exps {
		if x.Met[pairing.Candidate] {
			met++
		} else {
			res.Unmet = append(res.Unmet, x)
		}
		if x.Met[pairing.Reference] && !x.Met[pairing.Candidate] {
			lost++
		}
	}
	switch c.Name {
	case ExpectationsMetAtLeast:
		atLeast := c.Params[paramMin]
		required := atLeast
		if atLeast < 1 {
			// a fraction of all of them; the small epsilon keeps 0.95 of 80 at 76
			required = math.Ceil(atLeast*float64(len(exps)) - 1e-9)
		}
		res.Threshold = required
		res.Value = Value{Worst: float64(met), Best: float64(met)}
		res.Message = fmt.Sprintf("met %d of %d", met, len(exps))
		if float64(met) < required {
			res.State = Fail
		}
	case NoNewMisses:
		res.Threshold = c.Params[paramMax]
		res.Value = Value{Worst: float64(lost), Best: float64(lost)}
		res.Message = fmt.Sprintf("%d expectation(s) the reference met and the candidate did not", lost)
		res.State = decide(res.Value, res.Threshold)
		res.Unmet = nil
		for _, x := range exps {
			if x.Met[pairing.Reference] && !x.Met[pairing.Candidate] {
				res.Unmet = append(res.Unmet, x)
			}
		}
	}
	return res
}

// effects works out, for each unlabeled match only one setup reports, what labeling it tp or fp
// would do to each check and to the gate.
func (e evaluator) effects(current Gate) []Effect {
	var out []Effect
	for _, s := range e.subjects {
		for _, m := range e.unlabeledDeltas(s.Result) {
			eff := Effect{Subject: s.Name, Match: MatchID(m), States: map[claimsv1.Verdict]map[string]State{}, Outcome: map[claimsv1.Verdict]State{}}
			narrows := map[string]bool{}
			for _, v := range []claimsv1.Verdict{claimsv1.TP, claimsv1.FP} {
				h := evaluator{checks: e.checks, subjects: e.subjects, hyp: map[*pairing.Match]claimsv1.Verdict{m: v}}
				g := h.gate()
				eff.Outcome[v] = g.Outcome
				eff.States[v] = map[string]State{}
				for i, c := range g.Checks {
					eff.States[v][c.Name] = c.State
					if cur := current.Checks[i]; cur.State == Undecided && rangeOf(cur, s.Name) != rangeOf(c, s.Name) {
						narrows[c.Name] = true
					}
				}
			}
			for n := range narrows {
				eff.Narrows = append(eff.Narrows, n)
			}
			sort.Strings(eff.Narrows)
			out = append(out, eff)
		}
	}
	return out
}

// rangeOf is a check's value range on a subject, or the gate's for a per-gate check.
func rangeOf(c Check, subject string) Value {
	for _, sc := range c.Subjects {
		if sc.Subject == subject {
			return sc.Value
		}
	}
	return c.Value
}
