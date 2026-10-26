// Package testkit builds workspaces for yardstick's end to end tests and for the label UI's seed
// (seed/): a claims corpus holding the deb fixture image's SBOM and labels, and stub grypes
// printing its fixture grype output, whole or with matches dropped.
package testkit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// author is who the labels and the label server write as in the end to end material.
const author = "e2e"

// TB is the part of testing.TB the builders use, so the seed can build without a test.
type TB interface {
	Helper()
	Fatal(args ...any)
}

const DebImage = "oci:docker.io/anchore/yardstick-fixture-deb@sha256:617d48dd2601779266746a9a382bfb9f3fee2744fba698733b320366f41718b0"

const Libc = "pkg:deb/debian/libc6"

const Vocabulary = `justifications:
  fp: {fix-installed: Installed version has the fix}
  tp: {no-fix: Vulnerable code present, no fix for this version}
  unclear: {not-assessed: Nobody has assessed this version}
fact-sources: [nvd]
advisory-ids: [ELSA, ALSA]
vulnerability-namespaces: [CVE, GHSA]
`

const PolicyRules = `rules:
  nvd/fixed: {verdict: fp, justification: fix-installed, ceiling: medium, decision: P-1, basis: nvd range, title: Fixed per NVD}
`

// Workspace is a claims corpus under Dir and stub grypes under Tools.
type Workspace struct {
	T     TB
	Dir   string
	Tools string
}

func NewWorkspace(t TB, dir, tools string) *Workspace {
	t.Helper()
	w := &Workspace{T: t, Dir: dir, Tools: tools}
	r, _ := ref.Parse(DebImage)
	sbom, err := os.ReadFile(fixture.SBOM("deb", "syft"))
	if err != nil {
		t.Fatal(err)
	}
	WriteFile(t, filepath.Join(dir, "claims", corpus.ImageDir(r), corpus.ImageSBOMFile), string(sbom))
	WriteFile(t, filepath.Join(dir, "claims", claimsv1.VocabularyFile), Vocabulary)
	return w
}

// Grype is a stub printing the fixture deb output without the named vulnerability-on-package
// matches: a setup that does not report them.
func (w *Workspace) Grype(name string, drop ...string) string {
	w.T.Helper()
	data, err := os.ReadFile(fixture.Grype("v0.120.1", "deb"))
	if err != nil {
		w.T.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		w.T.Fatal(err)
	}
	var kept []any
	for _, m := range doc["matches"].([]any) {
		mm := m.(map[string]any)
		key := mm["vulnerability"].(map[string]any)["id"].(string) + " " + mm["artifact"].(map[string]any)["name"].(string)
		if !slices.Contains(drop, key) {
			kept = append(kept, m)
		}
	}
	doc["matches"] = kept
	out, _ := json.Marshal(doc)
	output := filepath.Join(w.Tools, name+".json")
	WriteFile(w.T, output, string(out))
	return StubTool(w.T, w.Tools, name, "#!/bin/sh\ncat \""+output+"\"\n")
}

// Label writes a tp label into the deb image's deb.json.
func (w *Workspace) Label(pkg, vuln string) {
	w.T.Helper()
	r, _ := ref.Parse(DebImage)
	f := corpus.TypeFile(corpus.ImageDir(r), "deb")
	p := filepath.Join(w.Dir, "claims", filepath.FromSlash(f))
	file := claimsv1.File{Schema: claimsv1.Version, Subject: &claimsv1.Subject{Image: r.Image()}}
	if data, err := os.ReadFile(p); err == nil {
		parsed, err := claimsv1.Parse(f, data)
		if err != nil {
			w.T.Fatal(err)
		}
		file = *parsed
	}
	file.Labels = append(file.Labels, claimsv1.Label{Package: pkg, Vulnerability: vuln, Verdict: claimsv1.TP, Author: author, FirstIssued: "2026-10-14T10:00:00Z", LastUpdated: "2026-10-14T10:00:00Z"})
	data, _ := claimsv1.Marshal(&file)
	WriteFile(w.T, p, string(data))
}

func (w *Workspace) Gate(name, candidate, reference, extra string, checks string) {
	w.T.Helper()
	WriteFile(w.T, filepath.Join(w.Dir, "gates", name+".yaml"), `schema: v1
claims: [../claims]
candidate: {grype: `+candidate+`, db: "dir:`+w.Tools+`"}
reference: {grype: `+reference+`, db: "dir:`+w.Tools+`"}
subjects: [{ref: "`+DebImage+`", name: deb}`+extra+`]
checks:
`+checks)
}

// DebGate writes gates/deb.yaml, ready to scan: its candidate drops the tar match, libc is
// labeled, and the vocabulary carries the policy rules. It returns the whole stub, the reference.
func (w *Workspace) DebGate() string {
	w.T.Helper()
	WriteFile(w.T, filepath.Join(w.Dir, "claims", claimsv1.VocabularyFile), Vocabulary+PolicyRules)
	whole := w.Grype("whole")
	noTar := w.Grype("no-tar", "CVE-2005-2541 tar")
	w.Label(Libc, "CVE-2026-5450")
	w.Gate("deb", noTar, whole, "", "  - name: unlabeledChangesAtMost\n    params: {max: 0}\n")
	return whole
}

func WriteFile(t TB, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil { //nolint:gosec // test paths
		t.Fatal(err)
	}
}

// StubTool writes an executable script.
func StubTool(t TB, dir, name, script string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	WriteFile(t, p, script)
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}
