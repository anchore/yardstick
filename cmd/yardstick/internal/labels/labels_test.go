package labels

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
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
	debRef, _ = ref.Parse("oci:docker.io/anchore/yardstick-fixture-deb@" + debDigest)
	debDir    = ImageDir(debRef)
	debImage  = &Subject{Image: debRef.Image()}
	vocab     = mustVocab()
	now       = "2026-10-14T10:00:00Z"
	later     = "2026-10-15T09:30:00Z"
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

// corpus writes a valid corpus: vocabulary, catalog, the fixture deb image's SBOM, and labels
// written through the writer.
func corpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, VocabularyFile), vocabYAML)
	write(t, filepath.Join(dir, CatalogFile), "syft: syft@v1.54.1\nplatform: linux/arm64\n")
	sbom, err := os.ReadFile(fixture.SBOM("deb", "syft"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, filepath.FromSlash(debDir), ImageSBOMFile), string(sbom))
	w := Writer{Dir: dir, Vocab: vocab}
	err = w.Write([]Placed{
		{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "CVE-2023-4911")},
		{File: TypeFile(debDir, "deb"), Subject: debImage, Label: fp(zlib, "CVE-2022-37434")},
		{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(ncurse, "CVE-2023-29491")},
		{File: debDir + "/" + NoPackageFile, Subject: debImage, Label: tp("", "CVE-2023-4911")},
		{File: GlobalFile("deb"), Label: fp("pkg:deb/debian/libxml2@2.7.8.dfsg-2+squeeze1?distro=debian-7", "CVE-2016-1839")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// label-file-format: what the writer writes, the schema accepts; what breaks a rule, it refuses
func TestLabelFileFormat(t *testing.T) {
	dir := corpus(t)
	for _, f := range []string{TypeFile(debDir, "deb"), debDir + "/" + NoPackageFile, GlobalFile("deb")} {
		if err := ValidateSchema([]byte(read(t, filepath.Join(dir, f)))); err != nil {
			t.Errorf("%s: expected the writer's output to match the schema: %v", f, err)
		}
	}
	valid := read(t, filepath.Join(dir, TypeFile(debDir, "deb")))
	for name, broken := range map[string]string{
		"no author":                strings.Replace(valid, `"author": "Alex Goodman",`, "", 1),
		"fp without justification": strings.Replace(valid, `"justification": "fix-installed",`, "", 1),
		"unknown verdict":          strings.Replace(valid, `"verdict": "tp"`, `"verdict": "maybe"`, 1),
		"fact without a source":    strings.Replace(valid, `"source": "debian-security-tracker",`, "", 1),
		"evidence without facts":   strings.Replace(valid, `"rule": "debian/installed-has-fix",`, `"rule": "debian/installed-has-fix", "facts": [], "was":`, 1),
		"not a time":               strings.Replace(valid, `"firstIssued": "2026-10-14T10:00:00Z"`, `"firstIssued": "yesterday"`, 1),
	} {
		if broken == valid {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if err := ValidateSchema([]byte(broken)); err == nil {
			t.Errorf("%s: expected the schema to refuse it", name)
		}
	}
	unclear := strings.Replace(strings.Replace(valid, `"verdict": "tp"`, `"verdict": "unclear"`, 1), `"justification": "fix-newer",`, "", 1)
	if err := ValidateSchema([]byte(unclear)); err == nil {
		t.Error("expected an unclear label without a justification refused")
	}
}

// format-major-check and additive-changes-tolerated: a newer major is refused naming the major
// this yardstick reads; an unknown field and an unknown value are read, and survive a rewrite
func TestFormatMajorAndAdditiveChanges(t *testing.T) {
	_, err := Parse("deb.json", []byte(`{"schema": "v2", "labels": []}`))
	if err == nil || !strings.Contains(err.Error(), `"v2"`) || !strings.Contains(err.Error(), "reads v1") || !strings.Contains(err.Error(), "newer yardstick") {
		t.Errorf("expected v2 refused naming v1, got %v", err)
	}

	dir := corpus(t)
	file := filepath.Join(dir, TypeFile(debDir, "deb"))
	newer := strings.Replace(read(t, file), `"author": "Will Murphy",`, `"author": "Will Murphy", "reviewedBy": "Alex Goodman",`, 1)
	newer = strings.Replace(newer, `"justification": "fix-installed"`, `"justification": "binary-stripped"`, 1)
	write(t, file, newer)
	f, err := Parse("deb.json", []byte(newer))
	if err != nil {
		t.Fatal(err)
	}
	var stripped *Label
	for i := range f.Labels {
		if f.Labels[i].Justification == "binary-stripped" {
			stripped = &f.Labels[i]
		}
	}
	if stripped == nil || stripped.Verdict != FP || string(stripped.Extra["reviewedBy"]) != `"Alex Goodman"` {
		t.Fatalf("expected the label read with its unknown field and value, got %+v", f.Labels)
	}

	// another label written into the file keeps the unknown field on the one already there
	if err := (Writer{Dir: dir, Vocab: vocab}).Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "CVE-2024-2961")}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, file), `"reviewedBy": "Alex Goodman"`) {
		t.Error("expected the rewrite to keep the field this yardstick does not know")
	}
}

func TestPaths(t *testing.T) {
	// legible-addresses and content-addressed-subjects: the registry and repository are in the
	// path, and the digest is the image's, spelled sha256-<hex> so no committed path holds a ':'
	r, _ := ref.Parse("oci:docker.io/cloudbees/cloudbees-core-mm:2.277@" + debDigest)
	dirName := strings.Replace(debDigest, "sha256:", "sha256-", 1)
	if got := TypeFile(ImageDir(r), "rpm"); got != "pkg/oci/docker.io/cloudbees/cloudbees-core-mm/"+dirName+"/rpm.json" {
		t.Errorf("unexpected image path %s", got)
	}
	if got := DocumentDir(debDigest); got != "sbom/"+dirName {
		t.Errorf("unexpected document path %s", got)
	}
	if GlobalFile("java-archive") != "global/java-archive.json" {
		t.Error("unexpected global path")
	}

	// corpus-layout: every place a file belongs reads back, and nothing else does
	for p, want := range map[string]Location{
		"pkg/oci/docker.io/anchore/test_images/" + dirName + "/deb.json":       {Kind: ImageSubject, Type: "deb", Registry: "docker.io", Repository: "anchore/test_images", Digest: debDigest},
		"pkg/oci/ghcr.io/a/b/c/" + dirName + "/image.json":                     {Kind: ImageSubject, Registry: "ghcr.io", Repository: "a/b/c", Digest: debDigest},
		"pkg/oci/docker.io/anchore/test_images/" + dirName + "/sbom.syft.json": {Kind: ImageSubject, Registry: "docker.io", Repository: "anchore/test_images", Digest: debDigest},
		"sbom/" + dirName + "/npm.json":                                        {Kind: DocumentSubject, Type: "npm", Digest: debDigest},
		"sbom/" + dirName + "/sbom.json":                                       {Kind: DocumentSubject, Digest: debDigest},
		"global/java-archive.json":                                             {Kind: Global, Type: "java-archive"},
	} {
		got, ok := Locate(p)
		if !ok || got.Kind != want.Kind || got.Type != want.Type || got.Registry != want.Registry || got.Repository != want.Repository || got.Digest != want.Digest {
			t.Errorf("%s: expected %+v, got %+v (%v)", p, want, got, ok)
		}
	}
	for _, p := range []string{
		"images/centos/labels.json",
		"pkg/oci/docker.io/anchore/test_images/deb.json",
		"pkg/oci/docker.io/anchore/test_images/sha256-abc/deb.json",
		// the digest as a reference spells it is not a directory name
		"pkg/oci/docker.io/anchore/test_images/" + debDigest + "/deb.json",
		"sbom/" + debDigest + "/npm.json",
		"sbom/" + strings.Replace(debDigest, "sha256:", "sha256-", 1) + "/sbom.syft.json",
		"global/image.json",
		"global/sub/deb.json",
	} {
		if _, ok := Locate(p); ok {
			t.Errorf("%s: expected no place in the layout", p)
		}
	}
	// a package name never becomes a path segment: scoped npm names are keys inside one file, and
	// a type is one plain segment
	for _, bad := range []string{"npm/@babel", "../deb", "image", "sbom.syft"} {
		if ValidType(bad) {
			t.Errorf("expected %q refused as a package type", bad)
		}
	}
	// syft's types as syft spells them, R-package included
	for _, good := range []string{"deb", "java-archive", "R-package"} {
		if !ValidType(good) {
			t.Errorf("expected %q accepted as a package type", good)
		}
	}
}

// update-survivability: rebuilding a subject's SBOM moves no label and touches no label file
func TestUpdateSurvivability(t *testing.T) {
	dir := corpus(t)
	before := read(t, filepath.Join(dir, TypeFile(debDir, "deb")))
	if listed, err := NoLongerPairing(dir); err != nil || len(listed) != 0 {
		t.Fatalf("expected every label to pair the SBOM it was written against, got %v %v", listed, err)
	}
	// the rebuild renames ncurses-base's purl
	sbom := read(t, filepath.Join(dir, debDir, ImageSBOMFile))
	rebuilt := strings.Replace(sbom, `"purl":"pkg:deb/debian/ncurses-base@`, `"purl":"pkg:deb/debian/ncurses-base-renamed@`, 1)
	if rebuilt == sbom {
		t.Fatal("the rebuild did not apply")
	}
	write(t, filepath.Join(dir, debDir, ImageSBOMFile), rebuilt)
	if problems, err := ValidateCorpus(dir); err != nil || len(problems) != 0 {
		t.Errorf("expected the corpus still valid, got %v %v", problems, err)
	}
	if read(t, filepath.Join(dir, TypeFile(debDir, "deb"))) != before {
		t.Error("expected the label file untouched")
	}
	listed, err := NoLongerPairing(dir)
	if err != nil || len(listed) != 1 || listed[0].Label != "CVE-2023-29491 on "+ncurse || listed[0].File != TypeFile(debDir, "deb") {
		t.Errorf("expected the ncurses-base label listed as no longer pairing, got %v %v", listed, err)
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

// writes-keep-files-valid, one-label-per-key-sorted and labels-written-to-subject-files
func TestWriter(t *testing.T) {
	dir := corpus(t)
	file := filepath.Join(dir, TypeFile(debDir, "deb"))
	w := Writer{Dir: dir, Vocab: vocab}

	// labels landed in their files, package-less in image.json, global in global/
	if !strings.Contains(read(t, filepath.Join(dir, debDir, NoPackageFile)), `"vulnerability": "CVE-2023-4911"`) ||
		strings.Contains(read(t, filepath.Join(dir, debDir, NoPackageFile)), `"package"`) {
		t.Error("expected the package-less label in image.json, with no package")
	}
	if !strings.Contains(read(t, filepath.Join(dir, "global", "deb.json")), "libxml2") || strings.Contains(read(t, filepath.Join(dir, "global", "deb.json")), `"subject"`) {
		t.Error("expected the global label in global/deb.json, with no subject")
	}

	// sorted by package, then vulnerability; the & of a purl is written as it is
	f, _ := Parse("deb.json", []byte(read(t, file)))
	if got := keys(f); got != "CVE-2023-4911 on "+libc+"|CVE-2023-29491 on "+ncurse+"|CVE-2022-37434 on "+zlib {
		t.Errorf("unexpected order %s", got)
	}
	if strings.Contains(read(t, file), "\\u0026") {
		t.Error("expected purls written without HTML escaping")
	}

	// an insert lands in order and moves nothing else; the same key replaces, keeping firstIssued
	before := read(t, file)
	relabeled := tp(zlib, "CVE-2022-37434")
	relabeled.FirstIssued, relabeled.LastUpdated = later, later
	if err := w.Write([]Placed{
		{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp("pkg:deb/debian/apt@2.6.1?arch=arm64&distro=debian-12", "CVE-2011-3374")},
		{File: TypeFile(debDir, "deb"), Subject: debImage, Label: relabeled},
	}); err != nil {
		t.Fatal(err)
	}
	f, _ = Parse("deb.json", []byte(read(t, file)))
	if len(f.Labels) != 4 || f.Labels[0].Vulnerability != "CVE-2011-3374" || f.Labels[3].Verdict != TP ||
		f.Labels[3].FirstIssued != now || f.Labels[3].LastUpdated != later {
		t.Errorf("expected the insert first and one zlib label, now tp with both dates, got %+v", f.Labels)
	}
	if !strings.Contains(read(t, file), strings.Split(before, `"package": "pkg:deb/debian/libc6`)[1][:40]) {
		t.Error("expected the libc label untouched")
	}

	// identical input, identical bytes
	again := read(t, file)
	if err := w.Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: relabeled}}); err != nil {
		t.Fatal(err)
	}
	if read(t, file) != again {
		t.Error("expected rewriting the same label to leave the bytes as they were")
	}
}

func keys(f *File) string {
	var out []string
	for _, l := range f.Labels {
		out = append(out, l.Key().String())
	}
	return strings.Join(out, "|")
}

// required-fields-enforced-on-write: a refused label names the field and leaves the file as it
// was, and so does a batch holding one
func TestWriterRefuses(t *testing.T) {
	dir := corpus(t)
	file := filepath.Join(dir, TypeFile(debDir, "deb"))
	before := read(t, file)
	w := Writer{Dir: dir, Vocab: vocab}
	noJust := fp(libc, "CVE-2024-1")
	noJust.Justification = ""
	badJust := fp(libc, "CVE-2024-2")
	badJust.Justification = "binary-stripped"
	badSource := fp(libc, "CVE-2024-3")
	badSource.Evidence[0].Facts[0].Source = "suse-oval"
	noFacts := fp(libc, "CVE-2024-12")
	noFacts.Evidence[0].Facts = nil
	badTime := fp(libc, "CVE-2024-13")
	badTime.Evidence[0].Facts[0].ObservedAt = "yesterday"
	badRule := fp(libc, "CVE-2024-14")
	badRule.Evidence[0].Rule = "debian/guess"
	wrongVerdict := tp(libc, "CVE-2024-15")
	wrongVerdict.Evidence = fp(libc, "CVE-2024-15").Evidence
	tpOnly := tp(libc, "CVE-2024-4")
	tpOnly.Justification = ""
	noAuthor := tp(libc, "CVE-2024-5")
	noAuthor.Author = ""
	for name, tt := range map[string]struct {
		p    Placed
		want string
	}{
		"fp without justification":     {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: noJust}, "fp needs a justification (one of: fix-installed, vulnerable_code_not_present)"},
		"justification not listed":     {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: badJust}, `justification "binary-stripped" is not listed under fp`},
		"fact source not listed":       {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: badSource}, `"suse-oval"`},
		"no author":                    {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: noAuthor}, "author is required"},
		"package in image.json":        {Placed{File: debDir + "/" + NoPackageFile, Subject: debImage, Label: tp(libc, "CVE-2024-6")}, "package must be absent"},
		"no package in a type file":    {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp("", "CVE-2024-7")}, "package is required"},
		"advisory id":                  {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "RHSA-2023:1234")}, "is an advisory"},
		"unknown namespace":            {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "FOO-2024-1")}, `namespace "FOO"`},
		"subject not the path's":       {Placed{File: TypeFile(debDir, "deb"), Subject: &Subject{Image: "docker.io/anchore/other@" + debDigest}, Label: tp(libc, "CVE-2024-8")}, "which the path names"},
		"not a place in the layout":    {Placed{File: "images/centos/labels.json", Subject: debImage, Label: tp(libc, "CVE-2024-9")}, "not a label file"},
		"evidence without facts":       {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: noFacts}, "evidence[0] needs at least one fact"},
		"fact observedAt not a time":   {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: badTime}, "evidence[0].facts[0].observedAt must be an RFC 3339 time"},
		"rule not listed":              {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: badRule}, `rule "debian/guess" is not listed`},
		"rule of the other verdict":    {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: wrongVerdict}, "rule debian/installed-has-fix supports fp, not tp"},
		"batch with one refused label": {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: noJust}, "needs a justification"},
	} {
		batch := []Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "CVE-2024-10")}, tt.p}
		err := w.Write(batch)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: expected an error with %q, got %v", name, tt.want, err)
		}
		if read(t, file) != before {
			t.Fatalf("%s: expected the file unchanged", name)
		}
	}
	if err := w.Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tpOnly}}); err != nil {
		t.Errorf("expected a tp with no justification written, got %v", err)
	}
	anyRule := tp(libc, "CVE-2024-16")
	anyRule.Evidence = fp(libc, "CVE-2024-16").Evidence
	anyRule.Evidence[0].Rule = "judgement/prior-claims-pattern"
	anyRule.Evidence[0].Interpretation = ""
	if err := w.Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: anyRule}}); err != nil {
		t.Errorf("expected a rule supporting either verdict, and evidence with no interpretation, written; got %v", err)
	}
}

// a write that dies between the temp file and the rename leaves the previous file whole
func TestInterruptedWrite(t *testing.T) {
	dir := corpus(t)
	file := filepath.Join(dir, TypeFile(debDir, "deb"))
	before := read(t, file)
	saved := rename
	rename = func(*os.Root, string, string) error { return errors.New("killed") }
	defer func() { rename = saved }()
	if err := (Writer{Dir: dir, Vocab: vocab}).Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "CVE-2024-11")}}); err == nil {
		t.Fatal("expected the failed rename returned")
	}
	if read(t, file) != before {
		t.Error("expected the previous file whole")
	}
	entries, _ := os.ReadDir(filepath.Dir(file))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("expected the temp file removed, found %s", e.Name())
		}
	}
}

// the corpus validator: the corpus as written passes, and each copy broken one way fails naming
// the file, the label and the rule
func TestValidateCorpus(t *testing.T) {
	if problems, err := ValidateCorpus(corpus(t)); err != nil || len(problems) != 0 {
		t.Fatalf("expected a valid corpus, got %v %v", problems, err)
	}
	debFile := TypeFile(debDir, "deb")
	edit := func(rel, old, new string) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			p := filepath.Join(dir, filepath.FromSlash(rel))
			before := read(t, p)
			after := strings.Replace(before, old, new, 1)
			if after == before {
				t.Fatalf("the edit to %s did not apply", rel)
			}
			write(t, p, after)
		}
	}
	tests := []struct {
		name   string
		break_ func(t *testing.T, dir string)
		file   string
		label  string
		want   string
	}{
		{"unsorted labels", func(t *testing.T, dir string) {
			p := filepath.Join(dir, filepath.FromSlash(debFile))
			f, _ := Parse("deb.json", []byte(read(t, p)))
			f.Labels[0], f.Labels[2] = f.Labels[2], f.Labels[0]
			data, _ := Marshal(f)
			write(t, p, string(data))
		}, debFile, "CVE-2023-29491 on " + ncurse, "out of order"},
		{"duplicate key", func(t *testing.T, dir string) {
			p := filepath.Join(dir, filepath.FromSlash(debFile))
			f, _ := Parse("deb.json", []byte(read(t, p)))
			f.Labels = append(f.Labels, f.Labels[2])
			data, _ := Marshal(f)
			write(t, p, string(data))
		}, debFile, "CVE-2022-37434 on " + zlib, "listed twice"},
		{"two verdicts for one match", func(t *testing.T, dir string) {
			p := filepath.Join(dir, filepath.FromSlash(debFile))
			f, _ := Parse("deb.json", []byte(read(t, p)))
			dup := f.Labels[2]
			dup.Verdict, dup.Justification = TP, "fix-newer"
			f.Labels = append(f.Labels, dup)
			data, _ := Marshal(f)
			write(t, p, string(data))
		}, debFile, "CVE-2022-37434 on " + zlib, "two verdicts"},
		{"unknown justification", edit(debFile, `"fix-installed"`, `"binary-stripped"`), debFile, "CVE-2022-37434 on " + zlib, `"binary-stripped" is not listed under fp`},
		{"justification under the wrong verdict", edit(debFile, `"justification": "fix-newer"`, `"justification": "fix-installed"`), debFile, "CVE-2023-4911 on " + libc, `"fix-installed" is not listed under tp`},
		{"rule justification not under its verdict", edit(VocabularyFile, "verdict: tp, justification: no-fix", "verdict: tp, justification: fix-installed"), VocabularyFile, "", `rule debian/affected-unfixed: justification "fix-installed" is not listed under tp`},
		{"rule with an unknown ceiling", edit(VocabularyFile, "ceiling: medium, decision: P-4, basis: Debian", "ceiling: certain, decision: P-4, basis: Debian"), VocabularyFile, "", `ceiling "certain"`},
		{"unknown fact source", edit(debFile, `"debian-security-tracker"`, `"suse-oval"`), debFile, "CVE-2022-37434 on " + zlib, `"suse-oval"`},
		{"package in image.json", edit(debDir+"/"+NoPackageFile, `"vulnerability":`, `"package": "pkg:deb/debian/libc6", "vulnerability":`), debDir + "/" + NoPackageFile, "CVE-2023-4911 on pkg:deb/debian/libc6", "package must be absent"},
		{"advisory id", edit(debFile, `"CVE-2023-4911"`, `"ALAS2-2023-1234"`), debFile, "ALAS2-2023-1234 on " + libc, "is an advisory"},
		{"unlisted namespace", edit(debFile, `"CVE-2023-4911"`, `"FOO-2024-1"`), debFile, "FOO-2024-1 on " + libc, `namespace "FOO"`},
		{"descriptor not the catalog's", edit(CatalogFile, "syft@v1.54.1", "syft@v1.52.0"), debDir + "/" + ImageSBOMFile, "", "syft 1.54.1, where the catalog pins 1.52.0"},
		{"config not the catalog's", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "syft.yaml"), "search:\n  scope: all-layers\n")
			edit(CatalogFile, "platform:", "config: syft.yaml\nplatform:")(t, dir)
		}, debDir + "/" + ImageSBOMFile, "", `configuration search.scope is "squashed", where the catalog's config sets "all-layers"`},
		{"syft by path", edit(CatalogFile, "syft@v1.54.1", "./bin/syft"), CatalogFile, "", "not a path to a binary"},
		{"a variable other than syft's", edit(CatalogFile, "platform:", "env: {LD_PRELOAD: /tmp/x.so}\nplatform:"), CatalogFile, "", "only SYFT_* variables, got LD_PRELOAD"},
		{"config outside the corpus", func(t *testing.T, dir string) {
			write(t, filepath.Join(filepath.Dir(dir), "outside.yaml"), "search:\n  scope: all-layers\n")
			edit(CatalogFile, "platform:", "config: ../outside.yaml\nplatform:")(t, dir)
		}, CatalogFile, "", `config "../outside.yaml" must be a path inside the corpus`},
		{"config by absolute path", func(t *testing.T, dir string) {
			abs := filepath.Join(t.TempDir(), "syft.yaml")
			write(t, abs, "search:\n  scope: all-layers\n")
			edit(CatalogFile, "platform:", "config: "+abs+"\nplatform:")(t, dir)
		}, CatalogFile, "", "must be a path inside the corpus"},
		{"config by a symlink out of the corpus", func(t *testing.T, dir string) {
			abs := filepath.Join(t.TempDir(), "syft.yaml")
			write(t, abs, "search:\n  scope: all-layers\n")
			if err := os.Symlink(abs, filepath.Join(dir, "syft.yaml")); err != nil {
				t.Fatal(err)
			}
			edit(CatalogFile, "platform:", "config: syft.yaml\nplatform:")(t, dir)
		}, CatalogFile, "", "config: "},
		{"label file elsewhere", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "images/centos/labels.json"), `{"schema": "v1", "labels": []}`)
		}, "images/centos/labels.json", "", "not a place in the corpus layout"},
		{"labels without their SBOM", func(t *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, debDir, ImageSBOMFile)) }, debDir, "", "no sbom.syft.json"},
		{"path and subject disagree", edit(debFile, "docker.io/anchore/yardstick-fixture-deb@", "docker.io/bitnami/yardstick-fixture-deb@"), debFile, "", "subject.image docker.io/bitnami/yardstick-fixture-deb@" + debDigest + " is not docker.io/anchore/yardstick-fixture-deb"},
		{"index digest without platform", func(t *testing.T, dir string) {
			// the SBOM's manifest is another digest than the directory's: the directory's is an index
			edit(debDir+"/"+ImageSBOMFile, `"manifestDigest":"`+debDigest, `"manifestDigest":"sha256:`+strings.Repeat("0", 64))(t, dir)
		}, debFile, "", "subject.platform must say which platform"},
		{"a schema v2 file", edit(debFile, `"schema": "v1"`, `"schema": "v2"`), debFile, "", "reads v1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := corpus(t)
			tt.break_(t, dir)
			problems, err := ValidateCorpus(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range problems {
				if p.File == tt.file && p.Label == tt.label && strings.Contains(p.Rule, tt.want) {
					return
				}
			}
			t.Errorf("expected a problem in %s about %q with %q, got %v", tt.file, tt.label, tt.want, problems)
		})
	}
}

func TestMarshalIsStable(t *testing.T) {
	f := &File{Schema: Major, Subject: debImage, Labels: []Label{fp(zlib, "CVE-2022-37434")}}
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

// symlinkSubject replaces a subject directory of a corpus with a link to a directory outside it,
// as a pull request could, returning the outside directory.
func symlinkSubject(t *testing.T, corpusDir, subjectDir string) string {
	t.Helper()
	outside := t.TempDir()
	target := filepath.Join(corpusDir, filepath.FromSlash(subjectDir))
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}
	return outside
}

// a write follows no symlink out of the corpus, and validation refuses any symlink in it
func TestSymlinkedSubjectDirectory(t *testing.T) {
	dir := corpus(t)
	outside := symlinkSubject(t, dir, debDir)
	err := (Writer{Dir: dir, Vocab: vocab}).Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "CVE-2024-11")}})
	if err == nil {
		t.Error("expected a write through a symlink out of the corpus refused")
	}
	if err := WriteFile(dir, debDir+"/"+ImageSBOMFile, []byte("{}")); err == nil {
		t.Error("expected WriteFile through a symlink out of the corpus refused")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("a write landed outside the corpus: %v", entries)
	}
	problems, err := ValidateCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range problems {
		found = found || (p.File == debDir && strings.Contains(p.Rule, "a symlink"))
	}
	if !found {
		t.Errorf("expected validate to name the symlinked directory, got %v", problems)
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
