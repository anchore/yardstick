package analysis

import (
	"fmt"
	"math"
	"slices"
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

// Rank orders states from best to worst: pass, undecided, fail.
func (s State) Rank() int {
	switch s {
	case Undecided:
		return 1
	case Fail:
		return 2
	}
	return 0
}

// worse is the worse of two states.
func worse(a, b State) State {
	if b.Rank() > a.Rank() {
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
	// FailsOn are the labeled matches that put the value over the threshold; none when the subject
	// passes.
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
	// Narrows are the checks labeling the match moves short of flipping: an undecided check whose
	// range it narrows, or a failing measured one whose value it lowers.
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
	e := newEvaluator(checks, subjects, nil)
	g := e.gate()
	g.Effects = e.effects(g)
	return g
}

// EvaluateAs computes every check as if the given matches were labeled so, leaving out the
// per-delta effects: what the label server previews before anything is written.
func EvaluateAs(checks []gatefile.Check, subjects []Subject, hyp map[*pairing.Match]claimsv1.Verdict) Gate {
	return newEvaluator(checks, subjects, hyp).gate()
}

type evaluator struct {
	checks   []gatefile.Check
	subjects []Subject
	// hyp labels matches hypothetically, to work out what labeling them would do
	hyp map[*pairing.Match]claimsv1.Verdict
	// implicit says the last check is the matchesAtLeast every gate gets unless it lists one
	implicit bool
}

// sameMatches is why the identical-results guard passed a check.
const sameMatches = "both setups report the same matches"

// newEvaluator holds the gate-level guards python yardstick ran before any check, so no check
// repeats them. An empty match set fails: a gate listing no matchesAtLeast gets it with min 1, as
// fail_on_empty_match_set defaulted on. Identical results pass: see unchanged.
func newEvaluator(checks []gatefile.Check, subjects []Subject, hyp map[*pairing.Match]claimsv1.Verdict) evaluator {
	e := evaluator{checks: checks, subjects: subjects, hyp: hyp}
	if !slices.ContainsFunc(checks, func(c gatefile.Check) bool { return c.Name == MatchesAtLeast }) {
		e.checks = append(slices.Clip(checks), gatefile.Check{Name: MatchesAtLeast, Params: map[string]float64{paramMin: 1}})
		e.implicit = true
	}
	return e
}

// unchanged says whether the identical-results guard passes a check over these subjects: python
// yardstick passed an image both setups reported the same matches on before reading a label. The
// at-least checks are floors on what the candidate reports, not comparisons, so it leaves them.
func unchanged(check string, rs ...*pairing.Result) bool {
	if check == MatchesAtLeast || check == ExpectationsMetAtLeast {
		return false
	}
	for _, r := range rs {
		if slices.ContainsFunc(r.Matches, delta) {
			return false
		}
	}
	return true
}

func (e evaluator) gate() Gate {
	g := Gate{Outcome: Pass}
	for i, c := range e.checks {
		res := e.check(c)
		if e.implicit && i == len(e.checks)-1 && res.State == Fail {
			res.Message = "every gate runs this unless it lists matchesAtLeast, as python yardstick's fail_on_empty_match_set did"
		}
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
	def := registry[c.Name]
	res := Check{Name: c.Name, Scope: def.Scope, Params: c.Params, State: Pass}
	if def.Scope == PerGate {
		rs := make([]*pairing.Result, len(e.subjects))
		for i, s := range e.subjects {
			rs[i] = s.Result
		}
		if unchanged(c.Name, rs...) {
			res.Message = sameMatches
			return res
		}
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
	for _, k := range []string{paramTolerance, paramMax, paramMin} {
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
	case v.Worst <= threshold+epsilon:
		return Pass
	case v.Best > threshold+epsilon:
		return Fail
	}
	return Undecided
}

// epsilon absorbs float error at a threshold: an F1 drop of 0.30000000000000004 is at tolerance 0.3.
const epsilon = 1e-9

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
	if unchanged(c.Name, r) {
		sc.State, sc.Message = Pass, sameMatches
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
		// an unlabeled count is known exactly, so both cases agree and the check passes or fails
		// outright, as python yardstick's max_unlabeled_percent did
		case UnlabeledChangesAtMost:
			values[x] = float64(len(e.unlabeledDeltas(r)))
		case UnlabeledPercentAtMost:
			if n := e.matchesIn(r, pairing.Candidate); n > 0 {
				values[x] = 100 * float64(e.unlabeledIn(r, pairing.Candidate)) / float64(n)
			}
		case MatchesAtLeast:
			// both setups' matches, as python yardstick's fail_on_empty_match_set summed them: only a
			// subject where both are empty fails min 1. Labels do not move a count, so both cases agree
			values[x] = float64(e.matchesIn(r, pairing.Candidate) + e.matchesIn(r, pairing.Reference))
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
	// a subject the setups disagree on that no label judges fails the checks reading labels, still
	// with its bounds and the rows a label would move, so there is something to act on
	if (c.Name == F1NotWorse || c.Name == NoNewFalseNegatives || c.Name == NoNewFalsePositives) && !e.hasLabels(r) {
		sc.State, sc.Message = Fail, "no tp or fp label applies to this subject"
	}
	sc.FailsOn, sc.Rows = e.rows(c, r)
	if sc.State == Pass {
		sc.FailsOn = nil
	}
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
		// only the labeled changes that lower the candidate's F1: an fp it added, a tp it dropped
		for _, m := range r.Matches {
			v := e.verdict(m, bestCase)
			if !e.unlabeled(m) && (m.In(pairing.Candidate) && !m.In(pairing.Reference) && v == claimsv1.FP ||
				m.In(pairing.Reference) && !m.In(pairing.Candidate) && v == claimsv1.TP) {
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
	case F1NotWorse, UnlabeledChangesAtMost:
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
		required := c.Params[paramMin]
		if f, ok := c.Params[paramMinFraction]; ok {
			// epsilon keeps 0.95 of 80 at 76
			required = math.Ceil(f*float64(len(exps)) - epsilon)
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
					if cur := current.Checks[i]; (cur.State == Undecided || cur.State == Fail && measured(c.Name)) && rangeOf(cur, s.Name) != rangeOf(c, s.Name) {
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

// measured says whether a check's value is known exactly rather than bounded: an unlabeled count,
// which labeling moves without any case to choose between.
func measured(check string) bool {
	return check == UnlabeledChangesAtMost || check == UnlabeledPercentAtMost
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
