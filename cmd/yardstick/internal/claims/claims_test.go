package claims

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// the corpus's own data: categories people write, not tool output
const vocabYAML = `justifications:
  fp: {fix-installed: Installed version has the fix}
  tp: {fix-newer: Fix is in a newer version than installed}
  unclear: {not-assessed: Nobody has assessed this version}
fact-sources: [sbom]
advisory-ids: ["ALAS*", ELSA, RHSA]
vulnerability-namespaces: [CVE, GHSA]
`

const (
	digest = "sha256:f0f8e8ee94f8b5d9364f21ceffd50b7db7e19b1938271295eff8229b3cf56db2"
	other  = "sha256:9c1d0000000000000000000000000000000000000000000000000000000000aa"
	libudv = "pkg:deb/ubuntu/libudev1@245.4-4ubuntu3.16?distro=ubuntu-20.04"
	urllib = "pkg:pypi/urllib3@1.26.5"
	struts = "pkg:maven/org.apache.struts/struts2-core@2.3.12"
)

var (
	image, _  = ref.Parse("oci:docker.io/anchore/test_images@" + digest)
	dir       = claimsv1.ImageDir(image)
	subject   = &claimsv1.Subject{Image: image.Image()}
	otherR, _ = ref.Parse("oci:docker.io/anchore/test_images@" + other)
	otherDir  = claimsv1.ImageDir(otherR)
)

func label(pkg, vuln string, v claimsv1.Verdict) claimsv1.Label {
	l := claimsv1.Label{Package: pkg, Vulnerability: vuln, Verdict: v, Author: "Alex Goodman", FirstIssued: "2026-10-14T10:00:00Z", LastUpdated: "2026-10-14T10:00:00Z"}
	switch v {
	case claimsv1.FP:
		l.Justification = "fix-installed"
	case claimsv1.TP:
		l.Justification = "fix-newer"
	case claimsv1.Unclear:
		l.Justification = "not-assessed"
	}
	return l
}

// corpus writes a corpus through the label writer: the files every source kind is tested over.
func corpus(t *testing.T, placed ...claimsv1.Placed) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, claimsv1.VocabularyFile), []byte(vocabYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := claimsv1.LoadVocabulary(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := (claimsv1.Writer{Dir: root, Vocab: v}).Write(placed); err != nil {
		t.Fatal(err)
	}
	return root
}

func at(file string, l claimsv1.Label) claimsv1.Placed {
	p := claimsv1.Placed{File: file, Label: l, Subject: subject}
	switch {
	case strings.HasPrefix(file, "global/"):
		p.Subject = nil
	case strings.HasPrefix(file, otherDir):
		p.Subject = &claimsv1.Subject{Image: otherR.Image()}
	}
	return p
}

// opener opens a corpus directory as one kind of source. Every kind passes the same suite.
type opener func(t *testing.T, root string) *Source

func openLocal(t *testing.T, root string) *Source {
	t.Helper()
	s, err := Open(gatefile.Source{Locator: root})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func setOf(t *testing.T, sources ...*Source) *Set {
	t.Helper()
	set := &Set{Sources: sources}
	for _, s := range sources {
		if v, _ := claimsv1.LoadVocabulary(s.FS); v != nil {
			set.vocab = v
			break
		}
	}
	return set
}

func TestLocalCorpus(t *testing.T) {
	conformance(t, openLocal)
}

func conformance(t *testing.T, open opener) {
	t.Run("reads limited to the gate's subjects", func(t *testing.T) { readsLimited(t, open) })
	t.Run("a subject with no labels", func(t *testing.T) { noLabels(t, open) })
	t.Run("format major", func(t *testing.T) { formatMajor(t, open) })
	t.Run("union across sources", func(t *testing.T) { union(t, open) })
	t.Run("sources that disagree", func(t *testing.T) { disagree(t, open) })
	t.Run("snapshot identity", func(t *testing.T) { snapshot(t, open) })
	t.Run("advisory id refused", func(t *testing.T) { advisory(t, open) })
}

// reads-limited-to-gate-subjects
func readsLimited(t *testing.T, open opener) {
	root := corpus(t,
		at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP)),
		at(claimsv1.TypeFile(dir, "python"), label(urllib, "CVE-2021-33503", claimsv1.TP)),
		at(claimsv1.TypeFile(dir, "java-archive"), label(struts, "CVE-2017-5638", claimsv1.TP)),
		at(dir+"/"+claimsv1.NoPackageFile, label("", "CVE-2017-5638", claimsv1.TP)),
		at(claimsv1.GlobalFile("deb"), label("pkg:deb/debian/libxml2@2.7.8.dfsg-2+squeeze1?distro=debian-7", "CVE-2016-1839", claimsv1.FP)),
		at(claimsv1.GlobalFile("python"), label(urllib, "CVE-2023-43804", claimsv1.TP)),
		at(claimsv1.GlobalFile("java-archive"), label(struts, "CVE-2018-11776", claimsv1.TP)),
		at(claimsv1.TypeFile(otherDir, "deb"), label(libudv, "CVE-2021-33910", claimsv1.TP)),
	)
	src := open(t, root)
	got, err := setOf(t, src).Read(Subject{Name: "test-image", Dir: dir, Types: []string{"python", "deb"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		dir + "/deb.json", dir + "/image.json", dir + "/python.json",
		"global/deb.json", "global/python.json",
	}
	read := src.Read()
	sortStrings(want)
	if !reflect.DeepEqual(read, want) {
		t.Errorf("expected exactly the subject's types, image.json and their globals read, got\n%v", read)
	}
	if len(got.Labels) != 5 {
		t.Errorf("expected 5 labels, got %d", len(got.Labels))
	}
	for _, l := range got.Labels {
		if l.Package == struts || l.Vulnerability == "CVE-2021-33910" {
			t.Errorf("expected nothing from a type or subject the gate does not need, got %+v", l)
		}
		if l.Global != strings.HasPrefix(l.File, "global/") {
			t.Errorf("expected global labels marked, got %+v", l)
		}
	}
}

func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

func noLabels(t *testing.T, open opener) {
	src := open(t, corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP))))
	got, err := setOf(t, src).Read(Subject{Name: "renamed", Dir: otherDir, Types: []string{"deb"}})
	if err != nil || len(got.Labels) != 0 {
		t.Errorf("expected a subject with no directory to load with no labels, got %+v %v", got, err)
	}
}

// format-major-check
func formatMajor(t *testing.T, open opener) {
	root := corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP)))
	p := filepath.Join(root, filepath.FromSlash(claimsv1.TypeFile(dir, "deb")))
	data, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(strings.Replace(string(data), `"schema": "1.0.0"`, `"schema": "2.0.0"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := setOf(t, open(t, root)).Read(Subject{Name: "test-image", Dir: dir, Types: []string{"deb"}})
	if err == nil || !strings.Contains(err.Error(), "deb.json") || !strings.Contains(err.Error(), `"2.0.0"`) || !strings.Contains(err.Error(), "reads v1") {
		t.Errorf("expected the file, its major and v1 named, got %v", err)
	}
}

// union-read-across-sources
func union(t *testing.T, open opener) {
	published := open(t, corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP))))
	local := open(t, corpus(t,
		at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP)),
		at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2021-33910", claimsv1.TP)),
	))
	got, err := setOf(t, published, local).Read(Subject{Name: "test-image", Dir: dir, Types: []string{"deb"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Labels) != 2 || len(got.Warnings) != 0 {
		t.Fatalf("expected the shared label once and the local one, got %+v", got)
	}
	shared := got.Labels[0]
	if shared.Vulnerability != "CVE-2020-13776" || shared.Disagrees() || len(shared.Held) != 2 {
		t.Errorf("expected one fp label held by both sources, got %+v", shared)
	}
}

// cross-source-disagreement-reads-unlabeled
func disagree(t *testing.T, open opener) {
	published := open(t, corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP))))
	local := open(t, corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.TP))))
	for _, order := range [][]*Source{{published, local}, {local, published}} {
		got, err := setOf(t, order...).Read(Subject{Name: "test-image", Dir: dir, Types: []string{"deb"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Labels) != 1 || !got.Labels[0].Disagrees() {
			t.Fatalf("expected one label that disagrees, whatever the order, got %+v", got.Labels)
		}
		w := strings.Join(got.Warnings, "\n")
		if !strings.Contains(w, "CVE-2020-13776 on "+libudv) || !strings.Contains(w, published.Locator+": fp") || !strings.Contains(w, local.Locator+": tp") {
			t.Errorf("expected the warning to name the key, each source and its verdict, got %q", w)
		}
	}
}

// each-source-has-a-snapshot-identity: it changes exactly when a file it read changes
func snapshot(t *testing.T, open opener) {
	root := corpus(t,
		at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP)),
		at(claimsv1.TypeFile(otherDir, "deb"), label(libudv, "CVE-2021-33910", claimsv1.TP)),
	)
	id := func() string {
		src := open(t, root)
		if _, err := setOf(t, src).Read(Subject{Name: "test-image", Dir: dir, Types: []string{"deb"}}); err != nil {
			t.Fatal(err)
		}
		return src.Snapshot()
	}
	first := id()
	if !strings.HasPrefix(first, "sha256:") || id() != first {
		t.Fatalf("expected a stable digest, got %s", first)
	}
	remote := open(t, root).Kind == Remote
	edit := func(rel, old, new string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		data, _ := os.ReadFile(p)
		if err := os.WriteFile(p, []byte(strings.Replace(string(data), old, new, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	edit(claimsv1.TypeFile(otherDir, "deb"), `"verdict": "tp"`, `"verdict": "fp"`)
	// a published snapshot is identified by the whole zip's digest, so any edit is a new one
	if changed := id() != first; changed != remote {
		t.Errorf("expected a file the gate did not read to change the identity only of a published snapshot, changed: %v", changed)
	}
	first = id()
	edit(claimsv1.TypeFile(dir, "deb"), `"author": "Alex Goodman"`, `"author": "Will Murphy"`)
	if id() == first {
		t.Error("expected a change to a file the gate read to change the identity")
	}
}

func advisory(t *testing.T, open opener) {
	root := corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP)))
	p := filepath.Join(root, filepath.FromSlash(claimsv1.TypeFile(dir, "deb")))
	data, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(strings.Replace(string(data), "CVE-2020-13776", "RHSA-2023:1234", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := setOf(t, open(t, root)).Read(Subject{Name: "test-image", Dir: dir, Types: []string{"deb"}})
	if err == nil || !strings.Contains(err.Error(), "deb.json") || !strings.Contains(err.Error(), "RHSA-2023:1234") {
		t.Errorf("expected the file and label named, got %v", err)
	}
}

// writes-to-last-local-source and ordered-claims-sources
func TestWritesGoToTheLastLocalSource(t *testing.T) {
	published := corpus(t)
	local := t.TempDir()
	set, err := OpenSet([]gatefile.Source{{Locator: published}, {Locator: local}})
	if err != nil {
		t.Fatal(err)
	}
	w, err := set.Writer()
	if err != nil {
		t.Fatal(err)
	}
	if w.Dir != local || w.Vocab == nil {
		t.Errorf("expected writes into %s checked against the published vocabulary, got %+v", local, w)
	}
	if err := w.Write([]claimsv1.Placed{at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.TP))}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(local, filepath.FromSlash(claimsv1.TypeFile(dir, "deb")))); err != nil {
		t.Errorf("expected the label in the last source: %v", err)
	}
	if entries, _ := os.ReadDir(published); len(entries) != 1 {
		t.Errorf("expected nothing written to the first source, got %v", entries)
	}

	remote := &Set{Sources: []*Source{set.Sources[0], {Locator: "github.com/anchore/delta-prototype@main", Kind: Remote}}}
	if _, err := remote.Writer(); err == nil || !strings.Contains(err.Error(), "--claims <path>") {
		t.Errorf("expected a remote last source refused for writes naming --claims, got %v", err)
	}

	if _, err := OpenSet([]gatefile.Source{{Locator: filepath.Join(t.TempDir(), "does-not-exist")}}); err == nil || !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("expected a missing directory named, got %v", err)
	}
}
