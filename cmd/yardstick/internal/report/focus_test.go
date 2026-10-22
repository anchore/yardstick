package report

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
)

const (
	openssl = "pkg:deb/debian/openssl@3.0.11?arch=amd64&distro=debian-12"
	libssl3 = "pkg:deb/debian/libssl3@3.0.11?arch=amd64&distro=debian-12"
)

// focusGate fails noNewFalseNegatives on CVE-2024-1234, dropped on openssl and on libssl3, and on
// CVE-2024-5678, dropped on openssl, each a tp label the candidate misses and the gate expects.
func focusGate() Gate {
	var rows []Match
	var misses []Miss
	var unmet []analysis.Expectation
	for _, r := range []struct{ pkgID, vuln, pkg string }{{"aa", "CVE-2024-1234", openssl}, {"bb", "CVE-2024-1234", libssl3}, {"aa", "CVE-2024-5678", openssl}} {
		ref := LabelRef{Package: basePURL(r.pkg), Vulnerability: r.vuln, Verdict: claimsv1.TP, File: "deb.json"}
		rows = append(rows, Match{ID: r.pkgID + "/" + r.vuln, Row: pairing.RowID("img", r.pkgID+"/"+r.vuln), Vulnerability: r.vuln, Package: r.pkg, InReference: true, Verdict: claimsv1.TP, Label: &ref, Direction: Introduced})
		misses = append(misses, Miss{Label: ref, InReference: true, Cause: NoCause})
		unmet = append(unmet, analysis.Expectation{Subject: "img", Package: ref.Package, Vulnerability: r.vuln, Verdict: claimsv1.TP})
	}
	ids := []string{"aa/CVE-2024-1234", "bb/CVE-2024-1234", "aa/CVE-2024-5678"}
	var rowIDs []string
	for _, id := range ids {
		rowIDs = append(rowIDs, pairing.RowID("img", id))
	}
	three := analysis.Value{Worst: 3, Best: 3}
	return Gate{Name: "deb", Path: "gates/deb.yaml", Outcome: analysis.Fail, Undecided: "fail", Checks: []analysis.Check{
		{Name: analysis.NoNewFalseNegatives, Scope: analysis.PerSubject, State: analysis.Fail, Value: three, FailsOn: rowIDs,
			Subjects: []analysis.SubjectCheck{{Subject: "img", State: analysis.Fail, Value: three, FailsOn: ids}}},
		{Name: analysis.NoNewMisses, Scope: analysis.PerGate, State: analysis.Fail, Value: three, Unmet: unmet},
	}, Subjects: []Subject{{Name: "img", Counts: map[string]Counts{gatefile.Candidate: {Labels: 3}, gatefile.Reference: {TP: 3, Labels: 3, Satisfied: 3}},
		Matches: rows, Misses: misses}}}
}

// what a focus kept of each narrowed field, by match id or by vulnerability and package; the
// check's failsOn are row ids, read back as the match ids of the gate's one subject
func focusKept(g Gate) (matches, failsOn, subjectFailsOn, misses, unmet []string) {
	for _, m := range g.Subjects[0].Matches {
		matches = append(matches, m.ID)
	}
	for _, row := range g.Checks[0].FailsOn {
		for _, m := range focusGate().Subjects[0].Matches {
			if m.Row == row {
				failsOn = append(failsOn, m.ID)
			}
		}
	}
	for _, m := range g.Subjects[0].Misses {
		misses = append(misses, m.Label.Vulnerability+" "+m.Label.Package)
	}
	for _, x := range g.Checks[1].Unmet {
		unmet = append(unmet, x.Vulnerability+" "+x.Package)
	}
	return matches, failsOn, g.Checks[0].Subjects[0].FailsOn, misses, unmet
}

// focus-narrows-rows, package by name or purl prefix: a name equals the purl's name, a pkg: value
// is a purl prefix
func TestFocusPackage(t *testing.T) {
	g := focusGate()
	before, _ := json.Marshal(g)
	for pkg, want := range map[string][]string{
		"openssl":                {"aa/CVE-2024-1234", "aa/CVE-2024-5678"},
		"pkg:deb/debian/libssl3": {"bb/CVE-2024-1234"},
		// a name is the whole name, never a part of it
		"ssl": nil,
	} {
		n := NewFocus(nil, []string{pkg}).Narrow(g, pairing.NewAliases(nil))
		matches, failsOn, subjectFailsOn, misses, unmet := focusKept(n)
		if !slices.Equal(matches, want) || !slices.Equal(failsOn, want) || !slices.Equal(subjectFailsOn, want) {
			t.Errorf("--package %s: expected rows %v, got matches %v, failsOn %v, subject failsOn %v", pkg, want, matches, failsOn, subjectFailsOn)
		}
		if len(misses) != len(want) || len(unmet) != len(want) {
			t.Errorf("--package %s: expected %d misses and unmet, got %v and %v", pkg, len(want), misses, unmet)
		}
	}
	if after, _ := json.Marshal(g); string(after) != string(before) {
		t.Error("narrowing changed the gate it was given")
	}
}

// focus-narrows-rows, both flags narrow together: any-of within a flag, both across them
func TestFocusBothFlags(t *testing.T) {
	g := focusGate()
	n := NewFocus([]string{"CVE-2024-1234"}, []string{"openssl"}).Narrow(g, pairing.NewAliases(nil))
	matches, failsOn, _, misses, unmet := focusKept(n)
	if !slices.Equal(matches, []string{"aa/CVE-2024-1234"}) || !slices.Equal(failsOn, matches) {
		t.Errorf("expected only the openssl row of CVE-2024-1234, got %v and failsOn %v", matches, failsOn)
	}
	if !slices.Equal(misses, []string{"CVE-2024-1234 pkg:deb/debian/openssl"}) || !slices.Equal(unmet, misses) {
		t.Errorf("expected only openssl's CVE-2024-1234 miss and expectation, got %v and %v", misses, unmet)
	}
	n = NewFocus([]string{"CVE-2024-1234", "CVE-2024-5678"}, []string{"openssl", "libssl3"}).Narrow(g, pairing.NewAliases(nil))
	if matches, _, _, _, _ := focusKept(n); len(matches) != 3 {
		t.Errorf("expected values of one flag to combine as any-of, got %v", matches)
	}
}

// focus-narrows-rows, an alias selects the row: grype reports CVE-2024-1234 relating
// GHSA-aaaa-bbbb-cccc, and the GHSA id, which no row carries, selects the CVE's rows
func TestFocusAlias(t *testing.T) {
	related := pairing.NewAliases(nil)
	related.AddScan(&models.Document{Matches: []models.Match{{
		Vulnerability:          models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "CVE-2024-1234"}},
		RelatedVulnerabilities: []models.VulnerabilityMetadata{{ID: "GHSA-aaaa-bbbb-cccc"}},
	}}})
	n := NewFocus([]string{"GHSA-aaaa-bbbb-cccc"}, nil).Narrow(focusGate(), related)
	if matches, _, _, misses, unmet := focusKept(n); !slices.Equal(matches, []string{"aa/CVE-2024-1234", "bb/CVE-2024-1234"}) || len(misses) != 2 || len(unmet) != 2 {
		t.Errorf("expected the GHSA alias to select CVE-2024-1234's rows, misses and expectations, got %v, %v and %v", matches, misses, unmet)
	}

	// in the java fixture grype reports Log4Shell as GHSA-jfh8-c2jp-5v3q relating CVE-2021-44228,
	// and either id selects its two rows, one per jar
	doc := scan(t, fixture.Grype("v0.120.1", "java"))
	a := pairing.NewAliases(nil)
	a.AddScan(doc)
	r := pairing.Pair(a, pairing.Subject{Name: "java", Packages: packagesOf(t, "java"),
		Scans: map[string]*models.Document{gatefile.Candidate: doc, gatefile.Reference: doc}})
	g := Build(&gatefile.Gate{Name: "java", Path: "gates/java.yaml", Undecided: gatefile.UndecidedFail}, header(), analysis.Evaluate(nil, nil), []SubjectInput{{Name: "java", Result: r}}, nil)
	for _, id := range []string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"} {
		var got []string
		for _, m := range NewFocus([]string{id}, nil).Narrow(g, a).Subjects[0].Matches {
			got = append(got, m.Vulnerability)
		}
		if !slices.Equal(got, []string{"GHSA-jfh8-c2jp-5v3q", "GHSA-jfh8-c2jp-5v3q"}) {
			t.Errorf("--vulnerability %s: expected the two GHSA-jfh8-c2jp-5v3q rows, got %v", id, got)
		}
	}
}

// rowless is a json document without its focus and rows: what a focus leaves as it was.
func rowless(t *testing.T, doc string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	var strip func(any)
	strip = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for _, k := range []string{"focus", "matches", "misses", "loose", "effects", "failsOn", "rows", "unmet"} {
				delete(v, k)
			}
			for _, x := range v {
				strip(x)
			}
		case []any:
			for _, x := range v {
				strip(x)
			}
		}
	}
	strip(v)
	out, _ := json.Marshal(v)
	return string(out)
}

// focus-narrows-rows, json names the focus: only rows in focus, every count, value and outcome
// the whole gate's, and a focus field only on the focused document
func TestFocusJSON(t *testing.T) {
	// an unlabeled delta on libssh, which counts toward a failing unlabeledChangesAtMost and has an effect
	const vuln = "CVE-2023-48795"
	failing, _ := rpmGate(t)
	focus := NewFocus([]string{vuln}, nil)
	whole := Summarize([]Gate{passing(t), failing})
	narrowed := Summarize([]Gate{focus.Narrow(passing(t), pairing.NewAliases(nil)), focus.Narrow(failing, pairing.NewAliases(nil))})
	narrowed.Focus = focus
	wholeDoc, focusedDoc := render(t, whole, Options{Format: "json"}), render(t, narrowed, Options{Format: "json"})

	var doc, plain map[string]any
	_ = json.Unmarshal([]byte(focusedDoc), &doc)
	_ = json.Unmarshal([]byte(wholeDoc), &plain)
	if want := map[string]any{"vulnerabilities": []any{vuln}, "packages": []any{}}; !reflect.DeepEqual(doc["focus"], want) {
		t.Errorf("expected focus %v, got %v", want, doc["focus"])
	}
	if _, ok := plain["focus"]; ok {
		t.Error("expected no focus field without a focus")
	}
	if rowless(t, focusedDoc) != rowless(t, wholeDoc) {
		t.Error("the focus moved a count, value, state or outcome")
	}
	// the focused rows and effects are the whole document's of that vulnerability
	var rows, effects int
	for _, m := range failing.Subjects[0].Matches {
		if m.Vulnerability == vuln {
			rows++
			if failing.effect("rpm", m.ID) != nil {
				effects++
			}
		}
	}
	got := narrowed.Gates[1]
	if rows == 0 || effects == 0 || len(got.Subjects[0].Matches) != rows || len(got.Effects) != effects {
		t.Errorf("expected %d rows and %d effects of %s, got %d and %d", rows, effects, vuln, len(got.Subjects[0].Matches), len(got.Effects))
	}
	for _, m := range got.Subjects[0].Matches {
		if m.Vulnerability != vuln {
			t.Errorf("expected only rows of %s, got %s", vuln, m.ID)
		}
	}
	for _, c := range got.Checks {
		for _, sc := range c.Subjects {
			for _, id := range append(slices.Clone(sc.FailsOn), sc.Rows...) {
				if !strings.HasSuffix(id, "/"+vuln) {
					t.Errorf("%s: expected only rows of %s, got %s", c.Name, vuln, id)
				}
			}
		}
	}
}

// focus-narrows-rows: every layout's header names the focus, and a gate with no row in focus says
// so in one line under its outcome
func TestFocusLayouts(t *testing.T) {
	narrow := func(focus *Focus) Set {
		failing, _ := rpmGate(t)
		s := Summarize([]Gate{focus.Narrow(passing(t), pairing.NewAliases(nil)), focus.Narrow(failing, pairing.NewAliases(nil))})
		s.Focus = focus
		return s
	}
	set := narrow(NewFocus([]string{"CVE-2020-12762"}, nil))
	none := narrow(NewFocus([]string{"CVE-2099-0001"}, nil))
	snap := snaps.WithConfig(snaps.Filename("focus_test"))
	for _, f := range textFormats() {
		t.Run(f, func(t *testing.T) {
			out := render(t, set, Options{Format: f})
			if !strings.Contains(out, "focus  rows of CVE-2020-12762; counts, values and outcomes are the whole gate's\n") {
				t.Errorf("expected the header to name the focus, got\n%s", out)
			}
			if f != "table" {
				snap.MatchSnapshot(t, out)
			}
			out = render(t, none, Options{Format: f})
			if want := map[bool]int{true: 0, false: 2}[f == "table"]; strings.Count(out, "\n  "+noFocusRows+"\n") != want || !strings.HasSuffix(out, "FAILED 1 of 2 gates\n") {
				t.Errorf("expected %d no-rows lines, one per gate, and the summary unchanged, got\n%s", want, out)
			}
		})
	}
}
