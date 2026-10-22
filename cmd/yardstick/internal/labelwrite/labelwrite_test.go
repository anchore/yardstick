package labelwrite

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

const vocabYAML = `justifications:
  fp: {fix-installed: Installed version has the fix}
fact-sources: [debian-security-tracker]
vulnerability-namespaces: [CVE]
rules:
  debian/installed-has-fix: {verdict: fp, justification: fix-installed, ceiling: high, decision: P-5, basis: x}
`

const written = "oci:docker.io/anchore/x@sha256:617d48dd2601779266746a9a382bfb9f3fee2744fba698733b320366f41718b0"

func runSubject(t *testing.T) *runrecord.Subject {
	t.Helper()
	r, err := ref.Parse(written)
	if err != nil {
		t.Fatal(err)
	}
	return &runrecord.Subject{Resolved: subject.Resolved{Subject: gatefile.Subject{Written: written, Name: "x", Platform: "linux/arm64"}, Dir: corpus.ImageDir(r)}}
}

// accepting a proposal writes the label it says, by the person accepting, with the run's seenIn and
// without the agent's confidence
func TestAccept(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, claimsv1.VocabularyFile), []byte(vocabYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := claims.OpenSet([]gatefile.Source{{Locator: dir}})
	if err != nil {
		t.Fatal(err)
	}
	p := agentstore.Proposal{Schema: agentstore.Schema, ID: "p1", Gate: "deb", Package: "pkg:deb/debian/zlib1g@1.2.13", Vulnerability: "CVE-2022-37434",
		Verdict: claimsv1.FP, Justification: "fix-installed", Confidence: "high", Note: "fixed in 1.2.13",
		Evidence: []claimsv1.Evidence{{Rule: "debian/installed-has-fix", Facts: []claimsv1.Fact{{Source: "debian-security-tracker", About: map[string]string{"vulnerability": "CVE-2022-37434"}, Field: "fixed", Value: "1.2.13", ObservedAt: "2026-10-16T09:00:00Z"}}}},
		Author:   agentstore.Author{Kind: agentstore.Agent}}
	seen := &claimsv1.SeenIn{SBOM: "sha256:" + strings.Repeat("b", 64), Tools: []claimsv1.Tool{{Name: claimsv1.ToolGrype, Version: "v0.120.1"}, {Name: claimsv1.ToolGrypeDB, Version: "sha256:db"}}}
	path, err := Accept(set, runSubject(t), p, "Alex Goodman", seen, time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := claimsv1.Parse(path, data)
	if err != nil || len(f.Labels) != 1 {
		t.Fatalf("expected one label in %s, got %v %v", path, f, err)
	}
	l := f.Labels[0]
	if l.Author != "Alex Goodman" || l.Verdict != claimsv1.FP || l.Justification != "fix-installed" || len(l.Notes) != 1 || l.Notes[0].Text != "fixed in 1.2.13" || l.Notes[0].Author != "Alex Goodman" ||
		len(l.Evidence) != 1 || l.Evidence[0].Rule != "debian/installed-has-fix" || l.SeenIn.Tool(claimsv1.ToolGrype) != "v0.120.1" || l.FirstIssued != "2026-10-16T09:00:00Z" {
		t.Errorf("expected the proposal's call, by the acceptor, with the run's seenIn, got %+v", l)
	}
	if strings.Contains(string(data), "confidence") || f.Subject.Platform != "linux/arm64" || !strings.HasSuffix(path, "/deb.json") {
		t.Errorf("expected no confidence, the subject's platform, and the deb type file, got %s at %s", data, path)
	}
}

func TestPlace(t *testing.T) {
	sub := runSubject(t)
	l := claimsv1.Label{Package: "pkg:deb/debian/zlib1g", Vulnerability: "CVE-1", SeenIn: &claimsv1.SeenIn{Tools: []claimsv1.Tool{{Name: claimsv1.ToolGrype, Version: "v0.120.1"}}}}
	if p, err := Place(sub, l, true); err != nil || p.File != corpus.GlobalFile("deb") || p.Subject != nil || p.Label.SeenIn != nil {
		t.Errorf("expected a global label in global/deb.json with no subject or seenIn, got %+v %v", p, err)
	}
	l.Package = ""
	if p, err := Place(sub, l, false); err != nil || p.File != sub.Dir+"/"+corpus.NoPackageFile {
		t.Errorf("expected a package-less label in image.json, got %+v %v", p, err)
	}
	if _, err := Place(sub, l, true); err == nil {
		t.Error("expected a global label naming no package refused")
	}
	l.Package = "pkg:nonsense/x"
	if _, err := Place(sub, l, false); err == nil || !strings.Contains(err.Error(), "names no package type") {
		t.Errorf("expected an unknown package type refused, got %v", err)
	}
}

// a label's seenIn names the setup that reported its match, pairing through the gate's aliases:
// here only another subject's scans relate the reference's GHSA to the label's CVE
func TestReportedByPairsWithTheGatesAliases(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	dir := t.TempDir()
	full, err := os.ReadFile(fixture.Grype("v0.120.1", "java"))
	if err != nil {
		t.Fatal(err)
	}
	var doc models.Document
	if err := json.Unmarshal(full, &doc); err != nil {
		t.Fatal(err)
	}
	// on subject a the candidate stops reporting the GHSA, and the reference reports it with no
	// related CVE
	cand, reference := doc, doc
	cand.Matches, reference.Matches = nil, nil
	for _, m := range doc.Matches {
		if m.Vulnerability.ID == "GHSA-jfh8-c2jp-5v3q" {
			m.RelatedVulnerabilities = nil
			reference.Matches = append(reference.Matches, m)
			continue
		}
		cand.Matches = append(cand.Matches, m)
		reference.Matches = append(reference.Matches, m)
	}
	files := map[string]any{"a-candidate.json": cand, "a-reference.json": reference, "b.json": doc}
	for name, d := range files {
		data, _ := json.Marshal(d)
		write(t, filepath.Join(dir, name), data)
	}
	r, err := ref.Parse("sbom:" + fixture.SBOM("java", "syft"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := (&subject.Resolver{}).Resolve(context.Background(), gatefile.Subject{Ref: r, Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	a, b := runrecord.Subject{Resolved: *res, Scans: map[string]string{"candidate": "a-candidate.json", "reference": "a-reference.json"}}, runrecord.Subject{Resolved: *res, Scans: map[string]string{"candidate": "b.json", "reference": "b.json"}}
	b.Name = "b"
	rec := &runrecord.Record{Subjects: []runrecord.Subject{a, b}}
	l := claimsv1.Label{Package: "pkg:maven/org.apache.logging.log4j/log4j-core", Vulnerability: "CVE-2021-44228", Verdict: claimsv1.TP}
	if got, err := reportedBy(rec, dir, &rec.Subjects[0], l, nil); err != nil || got != "reference" {
		t.Errorf("expected the reference, which alone reports the label's match, got %s %v", got, err)
	}
}

func write(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
