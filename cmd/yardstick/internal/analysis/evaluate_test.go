package analysis

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

func scan(t *testing.T, path string) *models.Document {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// decoded as collect.Decode does, which imports this package
	var doc models.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return &doc
}

var packageCache = map[string][]subject.Package{}

func packagesOf(t *testing.T, image string) []subject.Package {
	t.Helper()
	if p, ok := packageCache[image]; ok {
		return p
	}
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	r, err := ref.Parse("sbom:" + fixture.SBOM(image, "syft"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := (&subject.Resolver{}).Resolve(context.Background(), gatefile.Subject{Ref: r, Name: image})
	if err != nil {
		t.Fatal(err)
	}
	packageCache[image] = res.Packages
	return res.Packages
}

// label is a person's call, as one claims source holds it: labels are people's data, not tool
// output, so tests write them.
func label(pkg, vuln string, v claimsv1.Verdict) claims.Label {
	l := claims.Label{Label: claimsv1.Label{Package: pkg, Vulnerability: vuln, Verdict: v}, File: "x.json"}
	l.Held = []claims.SourceVerdict{{Source: "corpus", Verdict: v}}
	return l
}

// without is a scan with the matches on a vulnerability and package name removed: a setup that
// stopped reporting them.
func without(doc *models.Document, vuln, pkg string) *models.Document {
	out := *doc
	out.Matches = nil
	for _, m := range doc.Matches {
		if m.Vulnerability.ID != vuln || m.Artifact.Name != pkg {
			out.Matches = append(out.Matches, m)
		}
	}
	return &out
}

// pairOne pairs one image's labels with a candidate and a reference scan (nil for none).
func pairOne(t *testing.T, name, image string, candidate, reference *models.Document, ls ...claims.Label) Subject {
	t.Helper()
	a := pairing.NewAliases(nil)
	a.AddScan(candidate)
	a.AddScan(reference)
	a.AddLabels(ls)
	scans := map[string]*models.Document{pairing.Candidate: candidate}
	if reference != nil {
		scans[pairing.Reference] = reference
	}
	return Subject{Name: name, Result: pairing.Pair(a, pairing.Subject{Name: name, Packages: packagesOf(t, image), Labels: ls, Scans: scans})}
}

func grype(t *testing.T, image string) *models.Document {
	t.Helper()
	return scan(t, fixture.Grype("v0.120.1", image))
}

func check(name string, params map[string]float64) gatefile.Check {
	c := gatefile.Check{Name: name, Params: map[string]float64{}}
	for _, p := range Registry[name].Params {
		if p.Default != nil {
			c.Params[p.Name] = *p.Default
		}
	}
	for k, v := range params {
		c.Params[k] = v
	}
	return c
}

func evaluate(checks []gatefile.Check, subjects ...Subject) Gate {
	return Evaluate(checks, subjects)
}

const (
	ncursesBase = "pkg:deb/debian/ncurses-base"
	libc        = "pkg:deb/debian/libc6"
	log4j       = "pkg:maven/org.apache.logging.log4j/log4j-core"
)

func TestCheckRegistry(t *testing.T) {
	want := map[string]struct {
		scope Scope
		reads bool
	}{
		F1NotWorse: {PerSubject, true}, NoNewFalseNegatives: {PerSubject, true}, NoNewFalsePositives: {PerSubject, true},
		UnjudgedChangesAtMost: {PerSubject, true}, UnlabeledPercentAtMost: {PerSubject, false},
		ExpectationsMetAtLeast: {PerGate, false}, NoNewMisses: {PerGate, true}, MatchesAtLeast: {PerSubject, false},
	}
	if len(Registry) != len(want) {
		t.Fatalf("expected exactly %d checks, got %v", len(want), Names())
	}
	for name, w := range want {
		c, ok := Registry[name]
		if !ok || c.Scope != w.scope || c.ReadsReference != w.reads || len(c.Params) != 1 || c.Description == "" {
			t.Errorf("%s: expected scope %s, reads reference %v, one param and a description, got %+v", name, w.scope, w.reads, c)
		}
	}

	// min is a count from 1 and a fraction of all expectations below it: 80 expectations, 75 met
	sub := expectationSubject(t, 75, 80)
	for _, tc := range []struct {
		min  float64
		want State
	}{{0.95, Fail}, {0.9, Pass}, {76, Fail}, {75, Pass}} {
		g := evaluate([]gatefile.Check{check(ExpectationsMetAtLeast, map[string]float64{"min": tc.min})}, sub)
		if g.Checks[0].State != tc.want || g.Checks[0].Message != "met 75 of 80" {
			t.Errorf("min %v over 75 of 80: expected %s, got %s (%s)", tc.min, tc.want, g.Checks[0].State, g.Checks[0].Message)
		}
	}
}

// expectationSubject is a subject with total tp expectations of which met are reported by the
// candidate: image-level labels, built in memory over one real match.
func expectationSubject(t *testing.T, met, total int) Subject {
	t.Helper()
	cand := grype(t, "deb")
	res := &pairing.Result{}
	m := &pairing.Match{Rows: map[string][]int{pairing.Candidate: {0}}}
	for i := range total {
		b := &pairing.Bound{Label: label("", cand.Matches[i%len(cand.Matches)].Vulnerability.ID, claimsv1.TP), Present: true}
		if i < met {
			b.Matches = []*pairing.Match{m}
		}
		res.Labels = append(res.Labels, b)
	}
	return Subject{Name: "presence", Result: res}
}

// pooled F1 cannot hide a small subject
func TestF1PerSubject(t *testing.T) {
	deb := pairOne(t, "deb", "deb", grype(t, "deb"), grype(t, "deb"),
		label(ncursesBase, "CVE-2023-50495", claimsv1.TP), label(libc, "CVE-2026-5450", claimsv1.TP))
	// the candidate stops reporting log4j's CVE-2021-44228 in one jar... and in the other
	javaCand := without(grype(t, "java"), "GHSA-jfh8-c2jp-5v3q", "log4j-core")
	java := pairOne(t, "java", "java", javaCand, grype(t, "java"),
		label(log4j, "CVE-2021-44228", claimsv1.TP), label(log4j, "CVE-2021-45046", claimsv1.TP))
	g := evaluate([]gatefile.Check{check(F1NotWorse, nil)}, deb, java)
	c := g.Checks[0]
	if c.State != Fail {
		t.Fatalf("expected f1NotWorse to fail, got %s", c.State)
	}
	for _, sc := range c.Subjects {
		switch sc.Subject {
		case "deb":
			if sc.State != Pass || sc.Value.Worst != 0 {
				t.Errorf("deb's F1 did not change, got %+v", sc)
			}
		case "java":
			if sc.State != Fail || sc.Value.Best <= 0 {
				t.Errorf("expected java named as failing, got %+v", sc)
			}
		}
	}
}

// one versionless label pairs two matches: precision counts matches, recall counts labels
func TestPrecisionCountsMatchesRecallCountsLabels(t *testing.T) {
	java := pairOne(t, "java", "java", grype(t, "java"), grype(t, "java"), label(log4j, "CVE-2021-44228", claimsv1.TP))
	e := evaluator{}
	st := e.stats(java.Result, pairing.Candidate, worstCase)
	if st.TP != 2 || st.FP != 0 || st.Labels != 1 || st.Satisfied != 1 || st.Precision() != 1 || st.Recall() != 1 {
		t.Errorf("expected precision 2/2 and recall 1/1, got %+v", st)
	}

	// one tp label pairs two matches, one fp label pairs one, another tp label pairs nothing
	java = pairOne(t, "java", "java", grype(t, "java"), grype(t, "java"),
		label(log4j, "CVE-2021-44228", claimsv1.TP), label(log4j, "CVE-2021-45046", claimsv1.FP), label(log4j, "CVE-2020-9999", claimsv1.TP))
	st = e.stats(java.Result, pairing.Candidate, worstCase)
	// CVE-2021-45046's fp pairs it in both jars, so precision is 2 of 4
	if st.TP != 2 || st.FP != 2 || st.Labels != 2 || st.Satisfied != 1 {
		t.Errorf("expected 2 tp and 2 fp matches, 1 of 2 tp labels, got %+v", st)
	}
	if want := 2 * 0.5 * 0.5 / (0.5 + 0.5); st.F1() != want {
		t.Errorf("expected F1 from precision 0.5 and recall 0.5, got %v", st.F1())
	}
}

func TestUnlabeledMeans(t *testing.T) {
	const ncurses = "pkg:deb/debian/ncurses-base@6.4-4"
	deb := pairOne(t, "deb", "deb", grype(t, "deb"), grype(t, "deb"),
		label(ncurses, "CVE-2023-50495", claimsv1.Unclear),
		label(ncurses, "CVE-2020-9999", claimsv1.Unclear), label(libc, "CVE-2026-5450", claimsv1.TP))
	st := evaluator{}.stats(deb.Result, pairing.Candidate, worstCase)
	// the unclear-only match counts toward no tp or fp; an unclear label pairing nothing is no
	// false negative
	if st.TP != 1 || st.FP != 0 || st.Labels != 1 || st.Satisfied != 1 {
		t.Errorf("expected one tp match and one tp label, got %+v", st)
	}
}

// the unit of a match: a changed fix version is not a delta
func TestFixVersionIsNotADelta(t *testing.T) {
	cand := grype(t, "deb")
	for i := range cand.Matches {
		cand.Matches[i].Vulnerability.Fix.Versions = []string{"99.0"}
	}
	deb := pairOne(t, "deb", "deb", cand, grype(t, "deb"), label(libc, "CVE-2026-5450", claimsv1.TP))
	g := evaluate([]gatefile.Check{check(UnjudgedChangesAtMost, map[string]float64{"max": 0}), check(NoNewFalseNegatives, nil)}, deb)
	for _, c := range g.Checks {
		if c.State != Pass || c.Value.Worst != 0 {
			t.Errorf("%s: expected nothing new, dropped or unjudged, got %+v", c.Name, c)
		}
	}
}

// the candidate's CPE matching adds rpm matches the reference does not report
func cpes(t *testing.T, ls ...claims.Label) Subject {
	t.Helper()
	return pairOne(t, "rpm", "rpm", scan(t, fixture.Path("grype", "v0.120.1-cpes", "rpm.json")), grype(t, "rpm"), ls...)
}

// a CPE-only match: one the candidate adds
func cpeOnly(t *testing.T, s Subject) *pairing.Match {
	t.Helper()
	for _, m := range s.Result.Matches {
		if m.In(pairing.Candidate) && !m.In(pairing.Reference) {
			return m
		}
	}
	t.Fatal("no candidate-only match")
	return nil
}

func TestUnlabeledDeltasAreBounded(t *testing.T) {
	tpLabel := label("pkg:rpm/rocky/openssl-libs", "CVE-2026-45447", claimsv1.TP)
	s := cpes(t, tpLabel)
	added := 0
	for _, m := range s.Result.Matches {
		if m.In(pairing.Candidate) && !m.In(pairing.Reference) {
			added++
		}
	}
	g := evaluate([]gatefile.Check{check(NoNewFalsePositives, nil), check(UnjudgedChangesAtMost, map[string]float64{"max": 0})}, s)
	for _, c := range g.Checks {
		if c.State != Undecided || c.Value.Worst != float64(added) || c.Value.Best != 0 {
			t.Errorf("%s: expected undecided between 0 and %d, got %s %+v", c.Name, added, c.State, c.Value)
		}
		if len(c.Subjects[0].Rows) != added {
			t.Errorf("%s: expected the %d unlabeled rows behind it, got %d", c.Name, added, len(c.Subjects[0].Rows))
		}
	}
	if g.Outcome != Undecided {
		t.Errorf("expected the gate undecided, got %s", g.Outcome)
	}

	// one unlabeled match only the reference reports: worst 1, best 0
	ref := pairOne(t, "deb", "deb", without(grype(t, "deb"), "CVE-2026-5450", "libc6"), grype(t, "deb"), label(ncursesBase, "CVE-2023-50495", claimsv1.TP))
	c := evaluate([]gatefile.Check{check(NoNewFalseNegatives, nil)}, ref).Checks[0]
	if c.State != Undecided || c.Value.Worst != 1 || c.Value.Best != 0 {
		t.Errorf("expected undecided with worst 1 and best 0, got %s %+v", c.State, c.Value)
	}
	// labeled tp, the same match fails in both cases
	ref = pairOne(t, "deb", "deb", without(grype(t, "deb"), "CVE-2026-5450", "libc6"), grype(t, "deb"), label(libc, "CVE-2026-5450", claimsv1.TP))
	c = evaluate([]gatefile.Check{check(NoNewFalseNegatives, nil)}, ref).Checks[0]
	if c.State != Fail || c.Value.Worst != 1 || c.Value.Best != 1 || len(c.FailsOn) != 1 {
		t.Errorf("expected a fail in both cases naming the match, got %s %+v %v", c.State, c.Value, c.FailsOn)
	}
}

func TestPerSubjectChecksTakeTheWorstSubject(t *testing.T) {
	var subjects []Subject
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		subjects = append(subjects, pairOne(t, name, "deb", grype(t, "deb"), grype(t, "deb"), label(libc, "CVE-2026-5450", claimsv1.TP)))
	}
	subjects = append(subjects, pairOne(t, "lost", "deb", without(grype(t, "deb"), "CVE-2026-5450", "libc6"), grype(t, "deb"), label(libc, "CVE-2026-5450", claimsv1.TP)))
	c := evaluate([]gatefile.Check{check(NoNewFalseNegatives, nil)}, subjects...).Checks[0]
	failed := []string{}
	for _, sc := range c.Subjects {
		if sc.State == Fail {
			failed = append(failed, sc.Subject)
		}
	}
	if c.State != Fail || strings.Join(failed, ",") != "lost" {
		t.Errorf("expected the check to fail on the one subject, got %s on %v", c.State, failed)
	}
}

func TestNewByIdentity(t *testing.T) {
	// the candidate loses one labeled match and gains another
	ref := without(grype(t, "deb"), "CVE-2023-50495", "ncurses-base")
	cand := without(grype(t, "deb"), "CVE-2026-5450", "libc6")
	s := pairOne(t, "deb", "deb", cand, ref, label(libc, "CVE-2026-5450", claimsv1.TP), label(ncursesBase+"@6.4-4", "CVE-2023-50495", claimsv1.TP))
	c := evaluate([]gatefile.Check{check(NoNewFalseNegatives, nil)}, s).Checks[0]
	if c.Value.Best != 1 || c.Value.Worst != 1 {
		t.Errorf("expected one new false negative, got %+v", c.Value)
	}
	// a false positive both setups report is not new
	s = pairOne(t, "deb", "deb", grype(t, "deb"), grype(t, "deb"), label(libc, "CVE-2026-5450", claimsv1.FP))
	if c := evaluate([]gatefile.Check{check(NoNewFalsePositives, nil)}, s).Checks[0]; c.State != Pass || c.Value.Worst != 0 {
		t.Errorf("expected no new false positive, got %+v", c)
	}
}

func TestUnjudgedChangesCountOnlyDeltas(t *testing.T) {
	// every match both report is unlabeled; two only the candidate reports
	ref := without(without(grype(t, "deb"), "CVE-2026-5450", "libc6"), "CVE-2023-50495", "ncurses-base")
	s := pairOne(t, "deb", "deb", grype(t, "deb"), ref, label(libc, "CVE-2026-5928", claimsv1.TP))
	c := evaluate([]gatefile.Check{check(UnjudgedChangesAtMost, map[string]float64{"max": 0})}, s).Checks[0]
	if c.State != Undecided || c.Value.Worst != 2 || c.Value.Best != 0 {
		t.Errorf("expected undecided at 2, got %s %+v", c.State, c.Value)
	}
}

func TestUnlabeledPercentReadsTheCandidate(t *testing.T) {
	// the java scan has 14 matches: label all but the two on GHSA-3pxv-7cmr-fjr4 (one per jar)
	java := grype(t, "java")
	var ls []claims.Label
	seen := map[string]bool{}
	for _, m := range java.Matches {
		if m.Vulnerability.ID != "GHSA-3pxv-7cmr-fjr4" && !seen[m.Vulnerability.ID] {
			seen[m.Vulnerability.ID] = true
			ls = append(ls, label(log4j, m.Vulnerability.ID, claimsv1.TP))
		}
	}
	s := pairOne(t, "java", "java", java, nil, ls...)
	c := evaluate([]gatefile.Check{check(UnlabeledPercentAtMost, map[string]float64{"max": 10})}, s).Checks[0]
	want := 100 * 2.0 / float64(len(java.Matches))
	if c.State != Undecided || c.Value.Worst != want || c.Value.Best != 0 {
		t.Errorf("expected undecided at %v percent, got %s %+v", want, c.State, c.Value)
	}
	// a subject with no candidate matches passes
	none := pairOne(t, "npm", "npm", &models.Document{}, nil)
	if c := evaluate([]gatefile.Check{check(UnlabeledPercentAtMost, map[string]float64{"max": 0})}, none).Checks[0]; c.State != Pass {
		t.Errorf("expected a subject with no matches to pass, got %s", c.State)
	}
}

func TestMatchesAtLeastTakesTheFewestMatches(t *testing.T) {
	deb := grype(t, "deb")
	cand := without(deb, "CVE-2026-5450", "libc6")
	// the reference's extra matches are unlabeled deltas, which a count of matches does not read
	full := pairOne(t, "deb", "deb", cand, deb)
	// only the reference reports anything: both setups count, as python's fail_on_empty_match_set did
	refOnly := pairOne(t, "deb-ref-only", "deb", &models.Document{}, deb)
	empty := pairOne(t, "npm", "npm", &models.Document{}, &models.Document{})
	c := evaluate([]gatefile.Check{check(MatchesAtLeast, map[string]float64{"min": 1})}, full, refOnly, empty).Checks[0]
	if c.State != Fail || c.Value.Worst != 0 || c.Value.Best != 0 || c.Threshold != 1 {
		t.Errorf("expected a fail at the empty subject's 0 matches, got %s %+v threshold %v", c.State, c.Value, c.Threshold)
	}
	if got, want := c.Subjects[0].Value.Worst, float64(len(cand.Matches)+len(deb.Matches)); got != want {
		t.Errorf("expected deb to count both setups' %v matches, got %v", want, got)
	}
	if c.Subjects[0].State != Pass || c.Subjects[0].Value.Worst != c.Subjects[0].Value.Best {
		t.Errorf("expected deb to pass with one value, got %+v", c.Subjects[0])
	}
	if s := c.Subjects[1]; s.State != Pass || s.Value.Worst != float64(len(deb.Matches)) {
		t.Errorf("expected an empty candidate to pass on the reference's matches, got %+v", s)
	}
	if c.Subjects[2].State != Fail {
		t.Errorf("expected npm, empty in both setups, to fail, got %+v", c.Subjects[2])
	}
	if c := evaluate([]gatefile.Check{check(MatchesAtLeast, map[string]float64{"min": 0})}, full, refOnly, empty).Checks[0]; c.State != Pass {
		t.Errorf("expected min 0 to pass, got %s", c.State)
	}
}

func TestExpectations(t *testing.T) {
	deb := pairOne(t, "deb", "deb", without(grype(t, "deb"), "CVE-2005-2541", "tar"), grype(t, "deb"),
		label("", "CVE-2023-50495", claimsv1.TP), // reported: met
		label("", "CVE-2005-2541", claimsv1.TP),  // only on tar, which the candidate dropped: unmet, and a new miss
		label("", "CVE-2020-9999", claimsv1.FP),  // nothing reports it: met
		label("", "CVE-2019-0001", claimsv1.TP),  // nothing reports it: unmet
		label("", "CVE-2023-50495", claimsv1.Unclear))
	g := evaluate([]gatefile.Check{check(ExpectationsMetAtLeast, map[string]float64{"min": 2}), check(NoNewMisses, nil)}, deb)
	met, misses := g.Checks[0], g.Checks[1]
	if met.State != Pass || met.Message != "met 2 of 4" || len(met.Unmet) != 2 || met.Unmet[0].Subject != "deb" {
		t.Errorf("expected met 2 of 4 with the two unmet listed, got %+v", met)
	}
	if misses.State != Fail || misses.Value.Worst != 1 || len(misses.Unmet) != 1 || misses.Unmet[0].Vulnerability != "CVE-2005-2541" {
		t.Errorf("expected one new miss, got %+v", misses)
	}
}

func TestNoLabels(t *testing.T) {
	// a misspelled digest: no label applies to the subject
	bare := pairOne(t, "typo", "deb", grype(t, "deb"), grype(t, "deb"))
	g := evaluate([]gatefile.Check{check(F1NotWorse, nil), check(NoNewFalseNegatives, nil), check(NoNewFalsePositives, nil), check(ExpectationsMetAtLeast, map[string]float64{"min": 1})}, bare)
	for _, c := range g.Checks[:3] {
		if c.State != Fail || !strings.Contains(c.Subjects[0].Message, "no tp or fp label applies") {
			t.Errorf("%s: expected a fail saying the subject has no labels, got %+v", c.Name, c)
		}
	}
	if c := g.Checks[3]; c.State != Fail || !strings.Contains(c.Message, "no expectations") {
		t.Errorf("expected the expectation check to fail with no expectations, got %+v", c)
	}
}

func TestAHypotheticalLabelCountsAsALabelOnTheSubject(t *testing.T) {
	// a subject with no label fails the checks that read labels; previewing a tp or fp on one of its
	// matches must lift that, since writing the label would
	s := pairOne(t, "deb", "deb", without(grype(t, "deb"), "CVE-2026-5450", "libc6"), grype(t, "deb"))
	checks := []gatefile.Check{check(NoNewFalseNegatives, nil)}
	if c := evaluate(checks, s).Checks[0]; c.State != Fail || !strings.Contains(c.Subjects[0].Message, "no tp or fp label applies") {
		t.Fatalf("expected the unlabeled subject to fail, got %+v", c)
	}
	m := anyDelta(t, s)
	if c := EvaluateAs(checks, []Subject{s}, map[*pairing.Match]claimsv1.Verdict{m: claimsv1.FP}).Checks[0]; strings.Contains(c.Subjects[0].Message, "no tp or fp label applies") {
		t.Errorf("a hypothetical fp should count as a label, got %+v", c)
	}
}

func anyDelta(t *testing.T, s Subject) *pairing.Match {
	t.Helper()
	for _, m := range s.Result.Matches {
		if m.In(pairing.Candidate) != m.In(pairing.Reference) {
			return m
		}
	}
	t.Fatal("no delta")
	return nil
}

func TestLabelingEffect(t *testing.T) {
	// the only unlabeled match is one the reference reports
	s := pairOne(t, "deb", "deb", without(grype(t, "deb"), "CVE-2026-5450", "libc6"), grype(t, "deb"))
	// label every other match so the one reference-only match is the only unlabeled one
	var ls []claims.Label
	for _, m := range s.Result.Matches {
		if m.In(pairing.Candidate) {
			ls = append(ls, label(m.Package.PURL, m.Vulnerability, claimsv1.TP))
		}
	}
	s = pairOne(t, "deb", "deb", without(grype(t, "deb"), "CVE-2026-5450", "libc6"), grype(t, "deb"), ls...)
	g := evaluate([]gatefile.Check{check(NoNewFalseNegatives, nil)}, s)
	if g.Checks[0].State != Undecided || len(g.Effects) != 1 {
		t.Fatalf("expected one undecided check and one effect, got %s %d", g.Checks[0].State, len(g.Effects))
	}
	eff := g.Effects[0]
	if eff.States[claimsv1.TP][NoNewFalseNegatives] != Fail || eff.States[claimsv1.FP][NoNewFalseNegatives] != Pass ||
		eff.Outcome[claimsv1.TP] != Fail || eff.Outcome[claimsv1.FP] != Pass || strings.Join(eff.Narrows, ",") != NoNewFalseNegatives {
		t.Errorf("expected tp to fail it and fp to pass it, got %+v", eff)
	}

	// labeling a candidate-added match fp makes noNewFalsePositives fail, naming the match
	m := cpeOnly(t, cpes(t))
	labeled := cpes(t, label(m.Package.PURL, m.Vulnerability, claimsv1.FP))
	c := evaluate([]gatefile.Check{check(NoNewFalsePositives, nil)}, labeled).Checks[0]
	found := false
	for _, id := range c.FailsOn {
		found = found || id == MatchID(m)
	}
	if c.State == Pass || !found {
		t.Errorf("expected the labeled fp to fail the check and be listed in failsOn, got %s %v", c.State, c.FailsOn)
	}
}
