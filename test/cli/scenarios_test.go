package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// each scenario is described, with the numbers its run produces, in testdata/<scenario>/SCENARIO.md

var (
	allPass = map[string]string{"f1NotWorse": "pass", "noNewFalseNegatives": "pass", "noNewFalsePositives": "pass", "unlabeledChangesAtMost": "pass"}
	// the dropped glibc rows nobody has labeled: a tp would be a new false negative, and their count
	// is over the max of 0
	glibcOpen = map[string]string{"f1NotWorse": "undecided", "noNewFalseNegatives": "undecided", "noNewFalsePositives": "pass", "unlabeledChangesAtMost": "fail"}
)

// a regression labels can't fix: the newer grype stops matching the Go stdlib by CPE
func TestGoStdlib(t *testing.T) {
	w := newWorkspace(t, "go-stdlib")

	step(t, "validate", func(t *testing.T) {
		w.yardstick(t, []string{"config", "validate", "gates/go-upgrade.yaml", "gates/stdlib-cpe.yaml"},
			assertReturnCode(0), assertInOutput("all 2 gate files valid"))
	})

	step(t, "run", func(t *testing.T) {
		r := w.run(t, "go-upgrade", assertReturnCode(1), assertInOutput("6 dropped by the candidate, 0 added"))
		assertOutcome(t, r, "fail")
		assertStates(t, r, map[string]string{"f1NotWorse": "fail", "noNewFalseNegatives": "fail", "noNewFalsePositives": "pass", "unlabeledChangesAtMost": "fail"})
		assertHeader(t, r, "grype")
		assertChanged(t, r, map[string][]string{
			"introduced": {"CVE-2020-29509", "CVE-2020-29511", "CVE-2021-29923"},
			"fixed":      {"CVE-2021-44716"},
			"review":     {"CVE-2022-1705", "CVE-2022-1962"},
		})
		// no verdict on an open row changes the outcome
		for _, e := range r.Effects {
			for verdict, states := range e.States {
				if states["noNewFalseNegatives"] != "fail" {
					t.Errorf("expected labeling %s %s to leave noNewFalseNegatives failing, the effect says %s", e.Match, verdict, states["noNewFalseNegatives"])
				}
			}
		}

		// the same rows come back as added when the candidate matches the stdlib by CPE again
		r = w.run(t, "stdlib-cpe", assertReturnCode(1), assertInOutput("0 dropped by the candidate, 6 added"))
		assertOutcome(t, r, "fail")
		assertStates(t, r, map[string]string{"f1NotWorse": "pass", "noNewFalseNegatives": "pass", "noNewFalsePositives": "fail", "unlabeledChangesAtMost": "fail"})
		assertHeader(t, r, "config")
		assertChanged(t, r, map[string][]string{
			"introduced": {"CVE-2021-44716"},
			"fixed":      {"CVE-2020-29509", "CVE-2020-29511", "CVE-2021-29923"},
			"review":     {"CVE-2022-1705", "CVE-2022-1962"},
		})
	})

	step(t, "predictions hold", func(t *testing.T) {
		w.labelAsPredicted(t, "go-upgrade", "tp", "")
	})

	step(t, "label through", func(t *testing.T) {
		r := w.labelThrough(t, "go-upgrade", "tp", "")
		assertOutcome(t, r, "fail")
		assertStates(t, r, map[string]string{"f1NotWorse": "fail", "noNewFalseNegatives": "fail", "noNewFalsePositives": "pass", "unlabeledChangesAtMost": "pass"})

		// stdlib-cpe shares the rows: its labels arrived with no label written for it
		r = w.score(t, "stdlib-cpe")
		assertOutcome(t, r, "fail")
		assertStates(t, r, map[string]string{"f1NotWorse": "pass", "noNewFalseNegatives": "pass", "noNewFalsePositives": "fail", "unlabeledChangesAtMost": "pass"})
	})

	step(t, "valid corpus", func(t *testing.T) {
		w.validateLabels(t, w.score(t, "go-upgrade"))
	})
}

// a change that needs labels: the newer grype honors secureos saying glibc-2.42 is not affected
func TestSecureosGlibc(t *testing.T) {
	w := newWorkspace(t, "secureos-glibc")

	step(t, "validate", func(t *testing.T) {
		w.yardstick(t, []string{"config", "validate", "gates/glibc.yaml"}, assertReturnCode(0), assertInOutput("gate glibc"))
	})

	step(t, "run", func(t *testing.T) {
		r := w.run(t, "glibc", assertReturnCode(1), assertInOutput("9 dropped by the candidate, 0 added"))
		assertOutcome(t, r, "fail")
		assertStates(t, r, glibcOpen)
		assertHeader(t, r, "grype")
		assertChanged(t, r, map[string][]string{
			"fixed":  {"CVE-2010-4756", "CVE-2019-1010022"},
			"review": {"CVE-2025-15281", "CVE-2026-0861", "CVE-2026-0915", "CVE-2026-18374", "CVE-2026-19499", "CVE-2026-89092", "CVE-2026-95818"},
		})
		// the candidate's DB has the secureos record saying not affected, which the newer grype honors
		assertWhy(t, r, "record/distro-not-affected")
	})

	step(t, "predictions hold", func(t *testing.T) {
		w.labelAsPredicted(t, "glibc", "fp", "vendor-not-affected")
	})

	step(t, "proposals don't count", func(t *testing.T) {
		before := w.score(t, "glibc")
		// the proposals were recorded for the demo's gate, and propose refuses one about another
		// gate, so that field is dropped; the rest is the agent's output as it was
		data, err := os.ReadFile(filepath.Join("testdata", "secureos-glibc", "proposals.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var p map[string]any
			if err := json.Unmarshal([]byte(line), &p); err != nil {
				t.Fatal(err)
			}
			delete(p, "gate")
			out, _ := json.Marshal(p)
			lines = append(lines, string(out))
		}
		in := filepath.Join(t.TempDir(), "proposals.jsonl")
		if err := os.WriteFile(in, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		w.yardstick(t, []string{"claims", "agent", "propose", "--gate", "gates/glibc.yaml", in},
			assertReturnCode(0), assertInOutput("recorded 6 proposal(s)"))

		recorded, err := os.ReadFile(filepath.Join(w.dir, ".yardstick", "proposals.jsonl"))
		if err != nil || strings.Count(string(recorded), "\n") != 6 {
			t.Errorf("expected 6 proposals in .yardstick/proposals.jsonl, got %d (%v)", strings.Count(string(recorded), "\n"), err)
		}
		after := w.score(t, "glibc")
		assertStates(t, after, before.states())
		if len(after.Effects) != len(before.Effects) {
			t.Errorf("expected the proposals to leave %d open rows, got %d", len(before.Effects), len(after.Effects))
		}
		for i, c := range after.Checks {
			if c.Value != before.Checks[i].Value {
				t.Errorf("expected the proposals to leave %s at %v, got %v", c.Name, before.Checks[i].Value, c.Value)
			}
		}
	})

	step(t, "label through", func(t *testing.T) {
		r := w.labelThrough(t, "glibc", "fp", "vendor-not-affected")
		assertOutcome(t, r, "pass")
		assertStates(t, r, allPass)
	})

	step(t, "valid corpus", func(t *testing.T) {
		w.validateLabels(t, w.score(t, "glibc"))
	})
}

// nothing changed, and a gate moves when rows it shares with another are labeled there
func TestStable(t *testing.T) {
	w := newWorkspace(t, "stable")

	step(t, "validate", func(t *testing.T) {
		w.yardstick(t, []string{"config", "validate", "gates/stable.yaml", "gates/shared.yaml", "gates/glibc.yaml"},
			assertReturnCode(0), assertInOutput("all 3 gate files valid"))
	})

	step(t, "run", func(t *testing.T) {
		r := w.run(t, "stable", assertReturnCode(0), assertInOutput("PASS stable"))
		assertOutcome(t, r, "pass")
		assertStates(t, r, allPass)
		assertHeader(t, r, "grype")
		assertChanged(t, r, map[string][]string{})
		tp := 0
		for _, s := range r.Subjects {
			for _, m := range s.Matches {
				if m.Verdict == "tp" && m.InCandidate && m.InReference {
					tp++
				}
			}
		}
		if tp != 8 {
			t.Errorf("expected 8 tp matches both setups report, got %d", tp)
		}

		for _, gate := range []string{"shared", "glibc"} {
			r = w.run(t, gate, assertReturnCode(1))
			assertOutcome(t, r, "fail")
			assertStates(t, r, glibcOpen)
			assertChanged(t, r, map[string][]string{"review": {"CVE-2025-15281", "CVE-2026-95818"}})
			assertWhy(t, r, "record/distro-not-affected")
		}
	})

	step(t, "label through", func(t *testing.T) {
		r := w.labelThrough(t, "glibc", "fp", "vendor-not-affected")
		assertOutcome(t, r, "pass")

		// shared moves with no label written for it, and stable never had those rows
		for _, gate := range []string{"shared", "stable"} {
			r = w.score(t, gate)
			assertOutcome(t, r, "pass")
			assertStates(t, r, allPass)
		}
	})
}
