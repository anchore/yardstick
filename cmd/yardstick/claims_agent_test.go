package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/score"
)

const policyRules = `rules:
  nvd/fixed: {verdict: fp, justification: fix-installed, ceiling: medium, decision: P-1, basis: nvd range, title: Fixed per NVD}
`

const fact = `{"source":"nvd","about":{"vulnerability":"CVE-2005-2541"},"field":"status","value":"fixed","observedAt":"2026-10-16T00:00:00Z"}`

// the skill-facing commands: propose, propose-cause, explain propose/ls, ls, overrides, policy
func TestClaimsAgentCommands(t *testing.T) {
	w := newWorkspace(t)
	writeFile(t, filepath.Join(w.dir, "claims", labels.VocabularyFile), vocabulary+policyRules)
	whole := w.grype("whole")
	w.grype("no-tar", "CVE-2005-2541 tar")
	// the candidate logs two lines, for an explanation to quote
	noTar := stubTool(t, w.tools, "no-tar-logged", "#!/bin/sh\necho 'searching tar' >&2\necho 'no record for tar' >&2\ncat \""+filepath.Join(w.tools, "no-tar.json")+"\"\n")
	w.label(libc, "CVE-2026-5450")
	w.gate("deb", noTar, whole, "", "  - name: noNewFalseNegatives\n")
	if _, stderr, code := yardstick(t, w.dir, "gates/deb.yaml"); code == 2 {
		t.Fatalf("scan failed: %s", stderr)
	}

	t.Chdir(w.dir)
	rec, err := runrecord.Load(runrecord.DefaultName, "deb")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := score.Rows(runrecord.DefaultName, rec, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tarRow string
	for id, r := range rows {
		if r.Match.Vulnerability == "CVE-2005-2541" && r.Match.Package.Name == "tar" {
			tarRow = id
		}
	}
	if tarRow == "" {
		t.Fatal("no tar row in the scan")
	}
	store := agentstore.Open(filepath.Join(w.dir, agentstore.Dir))

	propose := func(input string, args ...string) (string, string, int) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "in.jsonl")
		writeFile(t, p, input)
		return yardstick(t, w.dir, append(args, p)...)
	}

	// a confidence above the rule's ceiling is refused, and nothing is recorded
	call := `{"row":"` + tarRow + `","verdict":"fp","justification":"fix-installed","confidence":"%s","evidence":[{"rule":"nvd/fixed","facts":[` + fact + `]}],"author":{"skill":"triage-deltas"}}`
	_, stderr, code := propose(strings.Replace(call, "%s", "high", 1), "claims", "propose", "--gate", "gates/deb.yaml")
	if code != 2 || !strings.Contains(stderr, "above the medium ceiling for nvd/fixed") {
		t.Fatalf("expected the high confidence refused, got %d: %s", code, stderr)
	}
	// an unknown field is refused
	if _, stderr, code := propose(`{"row":"`+tarRow+`","verdict":"tp","bogus":1}`, "claims", "propose", "--gate", "deb"); code != 2 || !strings.Contains(stderr, "bogus") {
		t.Fatalf("expected the unknown field refused, got %d: %s", code, stderr)
	}
	if got, _ := store.Proposals.Current(); len(got) != 0 {
		t.Fatalf("expected nothing recorded, got %+v", got)
	}

	// by row, the gate named by YARDSTICK_GATE: subject, package and vulnerability come from the row
	t.Setenv("YARDSTICK_GATE", "deb")
	t.Setenv("YARDSTICK_RESEARCH_JOB", "job-1")
	stdout, stderr, code := propose(strings.Replace(call, "%s", "medium", 1), "claims", "propose")
	if code != 0 || !strings.Contains(stdout, "\tfp\tCVE-2005-2541\tpkg:deb/debian/tar@") {
		t.Fatalf("expected the proposal recorded, got %d: %s %s", code, stdout, stderr)
	}
	got, err := store.Proposals.Current()
	if err != nil || len(got) != 1 {
		t.Fatalf("expected one proposal, got %v %+v", err, got)
	}
	p := got[0]
	if p.Gate != "deb" || p.Subject.Image == "" || p.Author.Kind != agentstore.Agent || p.Author.ResearchJob != "job-1" || p.Confidence != "medium" {
		t.Errorf("expected the proposal filled in from the row and the env, got %+v", p)
	}

	// a cause by rows: members, source package and direction filled in
	stdout, stderr, code = propose(`{"rows":["`+tarRow+`"],"title":"tar is fixed","verdict":"fp","justification":"fix-installed","confidence":"medium"}`, "claims", "propose-cause")
	if code != 0 || !strings.Contains(stdout, "\tfp\ttar\t1 members\ttar is fixed") {
		t.Fatalf("expected the cause recorded, got %d: %s %s", code, stdout, stderr)
	}
	causes, _ := store.Causes.Current()
	if len(causes) != 1 || causes[0].Direction != "dropped" || causes[0].Subject == nil || causes[0].Members[0].Vulnerability != "CVE-2005-2541" {
		t.Errorf("expected the cause filled in from its row, got %+v", causes)
	}
	// a member naming another row's vulnerability is refused
	if _, stderr, code := propose(`{"members":[{"row":"`+tarRow+`","vulnerability":"CVE-1999-0001"}],"title":"x","verdict":"tp"}`, "claims", "propose-cause"); code != 2 || !strings.Contains(stderr, "not CVE-1999-0001") {
		t.Fatalf("expected the mismatched member refused, got %d: %s", code, stderr)
	}

	// an explanation quoting the candidate's log exactly
	logged := rec.Subjects[0].Logs["candidate"]
	explanation := func(id, text string) string {
		return `{"id":"` + id + `","title":"the candidate DB has no tar record","reason":"record/absent-in-candidate","members":[{"row":"` + tarRow + `"}],` +
			`"logExcerpts":[{"side":"candidate","file":"` + logged.Path + `","lines":[1,2],"text":"` + text + `","sha256":"` + logged.SHA256 + `"}]}`
	}
	if _, stderr, code := propose(explanation("e1", "searching tar\\nsomething else"), "claims", "explain", "propose"); code != 2 || !strings.Contains(stderr, "copy them exactly") {
		t.Fatalf("expected a misquoted excerpt refused, got %d: %s", code, stderr)
	}
	if stdout, stderr, code := propose(explanation("e1", "searching tar\\nno record for tar"), "claims", "explain", "propose"); code != 0 || !strings.Contains(stdout, "e1\tdeb\t1 members") {
		t.Fatalf("expected the explanation recorded, got %d: %s %s", code, stdout, stderr)
	}
	if _, stderr, code := propose(explanation("e2", "searching tar\\nno record for tar"), "claims", "explain", "propose"); code != 2 || !strings.Contains(stderr, "already in explanation e1") {
		t.Fatalf("expected a second explanation of the row refused, got %d: %s", code, stderr)
	}
	stdout, _, _ = yardstick(t, w.dir, "claims", "explain", "ls", "--gate", "deb", "-o", "json")
	var listed []agentstore.Explanation
	if err := json.Unmarshal([]byte(stdout), &listed); err != nil || len(listed) != 1 || listed[0].Run != runrecord.DefaultName || listed[0].Members[0].Package == "" {
		t.Errorf("expected the one explanation listed, got %v %s", err, stdout)
	}
	// --name filters by run name, as --gate does by gate
	if stdout, _, _ := yardstick(t, w.dir, "claims", "explain", "ls", "--gate", "deb", "--name", "other", "-o", "json"); strings.TrimSpace(stdout) != "[]" {
		t.Errorf("expected no explanation of another run, got %s", stdout)
	}
	if stdout, _, _ := yardstick(t, w.dir, "claims", "explain", "ls", "--name", runrecord.DefaultName, "-o", "json"); !strings.Contains(stdout, `"e1"`) {
		t.Errorf("expected the run's explanation listed by name, got %s", stdout)
	}

	// a person overriding the proposal shows under its rule, with the proposal as the hint
	if err := store.Overrides.Add(agentstore.Override{Schema: agentstore.Schema, Proposal: p.ID, Gate: "deb", Subject: p.Subject, Package: p.Package,
		Vulnerability: p.Vulnerability, Verdict: labels.TP, Reason: &agentstore.Reason{Kind: "stale-fact", Text: "NVD moved"}, Author: "alex", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	stdout, _, _ = yardstick(t, w.dir, "claims", "overrides", "-o", "json")
	var groups []struct {
		Rule      string
		Count     int
		Overrides []struct {
			HintID string
			Hint   *agentstore.Proposal
		}
	}
	if err := json.Unmarshal([]byte(stdout), &groups); err != nil || len(groups) != 1 || groups[0].Rule != "nvd/fixed" || groups[0].Overrides[0].Hint == nil {
		t.Errorf("expected one override under nvd/fixed with its hint, got %v %s", err, stdout)
	}

	// ls and policy read the claims sources named by --claims, with no gate
	stdout, _, _ = yardstick(t, w.dir, "claims", "ls", "--claims", "claims", "-s", "libc6", "-o", "json")
	var ls []struct{ Label labels.Label }
	if err := json.Unmarshal([]byte(stdout), &ls); err != nil || len(ls) != 1 || ls[0].Label.Vulnerability != "CVE-2026-5450" {
		t.Errorf("expected the libc6 label listed, got %v %s", err, stdout)
	}
	stdout, _, _ = yardstick(t, w.dir, "claims", "policy", "--claims", "claims", "-o", "json")
	var pol struct {
		Rules          map[string]labels.Rule
		Justifications map[string]map[string]string
	}
	if err := json.Unmarshal([]byte(stdout), &pol); err != nil || pol.Rules["nvd/fixed"].Title != "Fixed per NVD" || pol.Justifications["fp"]["fix-installed"] == "" {
		t.Errorf("expected the rules and justifications, got %v %s", err, stdout)
	}
	if _, err := os.Stat(filepath.Join(w.dir, agentstore.Dir, "explanations.jsonl")); err != nil {
		t.Error(err)
	}
}
