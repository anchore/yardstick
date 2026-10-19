package agentstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
)

const vocabYAML = `justifications:
  fp: {fix-installed: Installed version has the fix}
  tp: {fix-newer: Fix is in a newer version than installed}
  unclear: {not-assessed: Nobody has assessed this version}
fact-sources: [debian-security-tracker]
vulnerability-namespaces: [CVE]
rules:
  debian/installed-has-fix: {verdict: fp, justification: fix-installed, ceiling: high, decision: P-5, basis: x}
  cna/installed-past-range: {verdict: fp, justification: fix-installed, ceiling: medium, decision: P-4, basis: x}
`

var (
	now   = time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	image = claimsv1.Subject{Image: "docker.io/anchore/x@sha256:" + strings.Repeat("a", 64)}
)

func proposal(id, vuln string, verdict claimsv1.Verdict, rule, confidence string) Proposal {
	return Proposal{Schema: Schema, ID: id, Gate: "deb", Subject: image, Package: "pkg:deb/debian/zlib1g@1.2.13", Vulnerability: vuln,
		Verdict: verdict, Justification: "fix-installed", Confidence: confidence,
		Evidence: []claimsv1.Evidence{{Rule: rule, Facts: []claimsv1.Fact{{Source: "debian-security-tracker", About: map[string]string{"vulnerability": vuln}, Field: "fixed", Value: "1.2.13", ObservedAt: "2026-10-16T09:00:00Z"}}}},
		Author:   Author{Kind: Agent, Skill: "triage-deltas", Model: "opus"}, Timestamp: now}
}

// append-only logs: the newest line per key wins, a refused batch writes nothing, and the snapshot
// moves exactly when something is added
func TestLog(t *testing.T) {
	s := Open(t.TempDir())
	empty, err := s.Proposals.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if cur, err := s.Proposals.Current(); err != nil || len(cur) != 0 {
		t.Fatalf("expected an empty store before anything is added, got %v %v", cur, err)
	}
	first := proposal("p1", "CVE-2022-37434", claimsv1.FP, "debian/installed-has-fix", "high")
	other := proposal("p2", "CVE-2023-1", claimsv1.FP, "debian/installed-has-fix", "high")
	if err := s.Proposals.Add(first, other); err != nil {
		t.Fatal(err)
	}
	added, _ := s.Proposals.Snapshot()
	if added == empty {
		t.Error("expected the snapshot to move when proposals are added")
	}
	again, _ := s.Proposals.Snapshot()
	if again != added {
		t.Error("expected the snapshot steady when nothing is added")
	}
	rerun := proposal("p3", "CVE-2022-37434", claimsv1.FP, "debian/installed-has-fix", "medium")
	bad := proposal("", "CVE-2023-2", claimsv1.FP, "", "")
	if err := s.Proposals.Add(rerun, bad); err == nil || !strings.Contains(err.Error(), "missing an id") {
		t.Fatalf("expected the batch refused for the proposal with no id, got %v", err)
	}
	if after, _ := s.Proposals.Snapshot(); after != added {
		t.Error("expected a refused batch to write nothing")
	}
	if err := s.Proposals.Add(rerun); err != nil {
		t.Fatal(err)
	}
	cur, err := s.Proposals.Current()
	if err != nil || len(cur) != 2 || cur[0].ID != "p3" || cur[1].ID != "p2" {
		t.Fatalf("expected the newer proposal about the same match to supersede the older, in first-seen order, got %+v %v", cur, err)
	}
	path := filepath.Join(filepath.Dir(s.Proposals.path), proposalsFile)
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "pkg:deb/debian/zlib1g@1.2.13") || strings.Count(string(data), "\n") != 3 {
		t.Errorf("expected one line per record, purls unescaped, got %s", data)
	}
	if err := os.WriteFile(path, append(data, []byte(`{"schema":"v2","id":"p9"}`+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Proposals.Current(); err == nil || !strings.Contains(err.Error(), "line 4") {
		t.Errorf("expected a newer schema refused naming the line, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	noJust := proposal("p", "CVE-2023-1", claimsv1.FP, "", "")
	noJust.Justification = ""
	noSubject := proposal("p", "CVE-2023-1", claimsv1.FP, "", "")
	noSubject.Subject = claimsv1.Subject{}
	noFacts := proposal("p", "CVE-2023-1", claimsv1.FP, "", "")
	noFacts.Evidence[0].Facts = nil
	badConfidence := proposal("p", "CVE-2023-1", claimsv1.FP, "", "certain")
	cause := Cause{Schema: Schema, ID: "c", Gate: "deb", Title: "fixed in Debian", SourcePackage: "zlib", Verdict: claimsv1.FP, Justification: "fix-installed",
		Members: []Member{{Row: "r1", Vulnerability: "CVE-1", Package: "pkg:deb/debian/zlib1g"}, {Row: "r1", Vulnerability: "CVE-2", Package: "pkg:deb/debian/zlib1g"}},
		Author:  Author{Kind: Agent}}
	explanation := Explanation{Schema: Schema, ID: "e", Gate: "deb", Run: "default", Title: "VEX changed", Members: []Member{{Row: "r1", Vulnerability: "CVE-1", Package: "pkg:deb/debian/zlib1g"}},
		LogExcerpts: []LogExcerpt{{Side: "candidate", File: "../outside.log", Lines: [2]int{1, 2}, Text: "x", SHA256: strings.Repeat("0", 64)}}, Author: Author{Kind: Agent}}
	override := Override{Schema: Schema, Proposal: "p", Vulnerability: "CVE-1", Verdict: claimsv1.TP, Author: "Alex Goodman", Reason: &Reason{Kind: "vibes"}}
	for name, tt := range map[string]struct {
		r    record
		want string
	}{
		"fp without justification": {noJust, "fp needs a justification"},
		"no subject":               {noSubject, "needs an image or an sbom digest"},
		"evidence without facts":   {noFacts, "evidence[0] needs at least one fact"},
		"unknown confidence":       {badConfidence, `got "certain"`},
		"cause with a row twice":   {cause, "row r1) is listed twice"},
		"excerpt outside the run":  {explanation, "inside the run"},
		"unknown override reason":  {override, `got "vibes"`},
	} {
		if err := tt.r.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: expected %q, got %v", name, tt.want, err)
		}
	}
	if err := proposal("p", "CVE-2023-1", claimsv1.FP, "", "").Validate(); err != nil {
		t.Errorf("expected a valid proposal, got %v", err)
	}
}

// the policy check: a proposal's confidence at or under its rule's ceiling, its verdict the rule's
func TestProblems(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, claimsv1.VocabularyFile), []byte(vocabYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := claimsv1.LoadVocabulary(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	wrongVerdict := proposal("p", "CVE-2023-1", claimsv1.TP, "debian/installed-has-fix", "high")
	wrongVerdict.Justification = "fix-newer"
	for name, tt := range map[string]struct {
		p    Proposal
		want string
	}{
		"at the ceiling":     {proposal("p", "CVE-2023-1", claimsv1.FP, "debian/installed-has-fix", "high"), ""},
		"above the ceiling":  {proposal("p", "CVE-2023-1", claimsv1.FP, "cna/installed-past-range", "high"), "above the medium ceiling for cna/installed-past-range (P-4)"},
		"rule of the other":  {wrongVerdict, "supports fp, not tp"},
		"unknown rule":       {proposal("p", "CVE-2023-1", claimsv1.FP, "debian/guess", "medium"), `rule "debian/guess" is not listed`},
		"low-confidence fp":  {proposal("p", "CVE-2023-1", claimsv1.FP, "", "low"), "a low-confidence fp is not allowed"},
		"unlisted namespace": {proposal("p", "GHSA-xxxx", claimsv1.FP, "", ""), `namespace "GHSA"`},
	} {
		got := strings.Join(tt.p.Problems(v), "; ")
		if (tt.want == "") != (got == "") || !strings.Contains(got, tt.want) {
			t.Errorf("%s: expected %q, got %q", name, tt.want, got)
		}
	}
	cause := Cause{Verdict: claimsv1.FP, Justification: "fix-installed", Confidence: "high", Evidence: proposal("p", "CVE-1", claimsv1.FP, "cna/installed-past-range", "").Evidence}
	if got := cause.Problems(v); len(got) != 1 || !strings.Contains(got[0], "ceiling") {
		t.Errorf("expected a cause over its rule's ceiling flagged, got %v", got)
	}
}
