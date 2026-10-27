package v1

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// the corpus's own data: categories people write, not tool output
const vocabYAML = `justifications:
  fp:
    fix-installed: Installed version has the fix
    vulnerable_code_not_present: Vulnerable code is not in this package
  tp:
    fix-newer: Fix is in a newer version than installed
    no-fix: Vulnerable code present, no fix for this version
  unclear:
    not-assessed: Nobody has assessed this version
    sources-disagree: Sources disagree about the affected versions
fact-sources: [debian-security-tracker, nvd, sbom]
advisory-ids: ["ALAS*", ELSA, ALSA, RLSA, RHSA, AVG]
vulnerability-namespaces: [CVE, GHSA]
rules:
  debian/installed-has-fix: {verdict: fp, justification: fix-installed, ceiling: high, decision: P-5, basis: the installed version has Debian's fix}
  debian/affected-unfixed: {verdict: tp, justification: no-fix, ceiling: medium, decision: P-4, basis: Debian lists it as affected with no fix}
  judgement/prior-claims-pattern: {verdict: any, ceiling: medium, decision: P-4, basis: prior claims on the same package}
`

// debDigest is the manifest the fixture deb SBOM was cataloged from, so the corpus subject below
// is that image.
const debDigest = "sha256:617d48dd2601779266746a9a382bfb9f3fee2744fba698733b320366f41718b0"

var (
	debImage = &Subject{Image: "docker.io/anchore/yardstick-fixture-deb@" + debDigest}
	vocab    = mustVocab()
	now      = "2026-10-14T10:00:00Z"
)

func mustVocab() *Vocabulary {
	dir, _ := os.MkdirTemp("", "vocab")
	_ = os.WriteFile(filepath.Join(dir, VocabularyFile), []byte(vocabYAML), 0o600)
	v, err := LoadVocabulary(os.DirFS(dir))
	if err != nil || v == nil {
		panic(err)
	}
	return v
}

func tp(pkg, vuln string) Label {
	return Label{Package: pkg, Vulnerability: vuln, Verdict: TP, Justification: "fix-newer", Author: "Alex Goodman", FirstIssued: now, LastUpdated: now}
}

func fp(pkg, vuln string) Label {
	return Label{Package: pkg, Vulnerability: vuln, Verdict: FP, Justification: "fix-installed", Author: "Will Murphy", FirstIssued: now, LastUpdated: now,
		Evidence: []Evidence{{
			Rule:           "debian/installed-has-fix",
			Facts:          []Fact{{Source: "debian-security-tracker", About: map[string]string{"vulnerability": vuln}, Field: "fixed", Value: "2.36-9", ObservedAt: now}},
			Interpretation: "the installed version has the fix",
		}},
	}
}

const (
	libc   = "pkg:deb/debian/libc6@2.36-9+deb12u14?arch=arm64&distro=debian-12"
	ncurse = "pkg:deb/debian/ncurses-base?distro=debian-12"
	zlib   = "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=arm64&distro=debian-12"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// format-major-check: a newer major is refused naming the major this yardstick reads
func TestFormatMajor(t *testing.T) {
	_, err := Parse("deb.json", []byte(`{"schema": "2.0.0", "labels": []}`))
	if err == nil || !strings.Contains(err.Error(), `"2.0.0"`) || !strings.Contains(err.Error(), "reads v1 ("+Version+")") {
		t.Errorf("expected 2.0.0 refused naming v1, got %v", err)
	}
	// the MODEL alone, as publish.yaml spells it, is not a file's version
	if _, err := Parse("deb.json", []byte(`{"schema": "v1", "labels": []}`)); err == nil {
		t.Error("expected a bare v1 refused")
	}
}

func TestFindVocabulary(t *testing.T) {
	published, local := t.TempDir(), t.TempDir()
	write(t, filepath.Join(published, VocabularyFile), vocabYAML)
	v, err := FindVocabulary(os.DirFS(local), os.DirFS(published), os.DirFS(local))
	if err != nil || v == nil || len(v.FactSources) != 3 {
		t.Fatalf("expected the published vocabulary when the writable source has none, got %+v %v", v, err)
	}
	write(t, filepath.Join(local, VocabularyFile), "fact-sources: [sbom]\nsomethingNew: true\n")
	if v, _ := FindVocabulary(os.DirFS(local), os.DirFS(published)); len(v.FactSources) != 1 {
		t.Errorf("expected the writable source's own vocabulary first, got %+v", v)
	}
	if _, err := FindVocabulary(os.DirFS(t.TempDir())); err == nil {
		t.Error("expected an error with no vocabulary anywhere")
	}
	if !vocab.IsAdvisory("ALAS2-2023-1234") || !vocab.IsAdvisory("RHSA-2023:1234") || vocab.IsAdvisory("CVE-2023-1234") {
		t.Error("expected ALAS* to cover ALAS2 and RHSA listed")
	}
}

func TestMarshalIsStable(t *testing.T) {
	f := &File{Schema: Version, Subject: debImage, Labels: []Label{fp(zlib, "CVE-2022-37434")}}
	a, _ := Marshal(f)
	var round File
	if err := json.Unmarshal(a, &round); err != nil {
		t.Fatal(err)
	}
	b, _ := Marshal(&round)
	if !bytes.Equal(a, b) || !bytes.HasSuffix(a, []byte("}\n")) {
		t.Errorf("expected a read and rewrite to give the same bytes:\n%s\n%s", a, b)
	}
}

// the policy's ceilings and verdicts, and the corpus's own rules holding together
func TestProblems(t *testing.T) {
	cite := func(verdict Verdict, rule string) Label {
		l := fp(libc, "CVE-2024-1")
		l.Verdict, l.Justification = verdict, ""
		l.Evidence[0].Rule = rule
		return l
	}
	for name, tt := range map[string]struct {
		label      Label
		confidence string
		want       string
	}{
		"within the ceiling": {cite(TP, "debian/affected-unfixed"), "medium", ""},
		"no confidence":      {cite(TP, "debian/affected-unfixed"), "", ""},
		"above the ceiling":  {cite(TP, "debian/affected-unfixed"), "high", "high confidence is above the medium ceiling for debian/affected-unfixed (P-4)"},
		"other verdict":      {cite(FP, "debian/affected-unfixed"), "low", "rule debian/affected-unfixed supports tp, not fp"},
		"any verdict":        {cite(Unclear, "judgement/prior-claims-pattern"), "low", ""},
		"unknown rule":       {cite(TP, "debian/guess"), "", `rule "debian/guess" is not listed`},
	} {
		got := strings.Join(vocab.Problems(tt.label, tt.confidence), "; ")
		if (tt.want == "") != (got == "") || !strings.Contains(got, tt.want) {
			t.Errorf("%s: expected %q, got %q", name, tt.want, got)
		}
	}
	v, err := LoadVocabulary(os.DirFS("testdata"))
	if err != nil || v == nil || len(v.Rules) == 0 {
		t.Fatalf("expected the corpus's vocabulary with its rules, got %v", err)
	}
	if problems := v.CheckRules(); len(problems) > 0 {
		t.Errorf("expected the corpus's rules consistent with its justifications, got %v", problems)
	}
}

// every key of the published schema says what it is, so the schema is the format's documentation
func TestSchemaDescribesEveryKey(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(schema, &doc); err != nil {
		t.Fatal(err)
	}
	var walk func(path string, node map[string]any)
	walk = func(path string, node map[string]any) {
		if props, ok := node["properties"].(map[string]any); ok {
			for name, p := range props {
				p := p.(map[string]any)
				if d, _ := p["description"].(string); d == "" {
					t.Errorf("%s.%s has no description", path, name)
				}
				walk(path+"."+name, p)
			}
		}
		if items, ok := node["items"].(map[string]any); ok {
			walk(path+"[]", items)
		}
	}
	walk("$", doc)
	for name, def := range doc["$defs"].(map[string]any) {
		walk("$defs."+name, def.(map[string]any))
	}
}

// aliases are only on an advisory label, and only name disclosures
func TestCheckAliases(t *testing.T) {
	v := &Vocabulary{AdvisoryIDs: []string{"ELSA"}, Namespaces: []string{"CVE"}}
	for _, tc := range []struct {
		vuln    string
		aliases []string
		ok      bool
	}{
		{"ELSA-2021-9137", nil, true},
		{"ELSA-2021-9137", []string{"CVE-2020-1971"}, true},
		{"CVE-2020-1971", []string{"CVE-2020-1972"}, false},
		{"ELSA-2021-9137", []string{"ELSA-2021-9138"}, false},
		{"ELSA-2021-9137", []string{"XYZ-1"}, false},
	} {
		if err := v.CheckAliases(Label{Vulnerability: tc.vuln, Aliases: tc.aliases}); (err == nil) != tc.ok {
			t.Errorf("%s with aliases %v: expected ok=%v, got %v", tc.vuln, tc.aliases, tc.ok, err)
		}
	}
}
