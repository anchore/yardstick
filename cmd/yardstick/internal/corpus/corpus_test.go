package corpus

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
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
	debImage  = &claimsv1.Subject{Image: debRef.Image()}
	vocab     = mustVocab()
	now       = "2026-10-14T10:00:00Z"
	later     = "2026-10-15T09:30:00Z"
)

func mustVocab() *claimsv1.Vocabulary {
	dir, _ := os.MkdirTemp("", "vocab")
	_ = os.WriteFile(filepath.Join(dir, claimsv1.VocabularyFile), []byte(vocabYAML), 0o600)
	v, err := claimsv1.LoadVocabulary(os.DirFS(dir))
	if err != nil || v == nil {
		panic(err)
	}
	return v
}

func tp(pkg, vuln string) claimsv1.Label {
	return claimsv1.Label{Package: pkg, Vulnerability: vuln, Verdict: claimsv1.TP, Justification: "fix-newer", Author: "Alex Goodman", FirstIssued: now, LastUpdated: now}
}

func fp(pkg, vuln string) claimsv1.Label {
	return claimsv1.Label{Package: pkg, Vulnerability: vuln, Verdict: claimsv1.FP, Justification: "fix-installed", Author: "Will Murphy", FirstIssued: now, LastUpdated: now,
		Evidence: []claimsv1.Evidence{{
			Rule:           "debian/installed-has-fix",
			Facts:          []claimsv1.Fact{{Source: "debian-security-tracker", About: map[string]string{"vulnerability": vuln}, Field: "fixed", Value: "2.36-9", ObservedAt: now}},
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
	write(t, filepath.Join(dir, claimsv1.VocabularyFile), vocabYAML)
	write(t, filepath.Join(dir, CatalogFile), "syft: syft@v1.54.1\nplatform: linux/arm64\n")
	sbom, err := os.ReadFile(fixture.SBOM("deb", "syft"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, filepath.FromSlash(debDir), ImageSBOMFile), string(sbom))
	w := Writer{Dir: dir, Vocab: vocab}
	_, err = w.Write([]Placed{
		{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "CVE-2023-4911")},
		{File: TypeFile(debDir, "deb"), Subject: debImage, Label: fp(zlib, "CVE-2022-37434")},
		{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(ncurse, "CVE-2023-29491")},
		{File: NoPackagePath(debDir), Subject: debImage, Label: tp("", "CVE-2023-4911")},
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
	for _, f := range []string{TypeFile(debDir, "deb"), NoPackagePath(debDir), GlobalFile("deb")} {
		if err := claimsv1.ValidateSchema([]byte(read(t, filepath.Join(dir, f)))); err != nil {
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
		if err := claimsv1.ValidateSchema([]byte(broken)); err == nil {
			t.Errorf("%s: expected the schema to refuse it", name)
		}
	}
	unclear := strings.Replace(strings.Replace(valid, `"verdict": "tp"`, `"verdict": "unclear"`, 1), `"justification": "fix-newer",`, "", 1)
	if err := claimsv1.ValidateSchema([]byte(unclear)); err == nil {
		t.Error("expected an unclear label without a justification refused")
	}
}

// additive-changes-tolerated: an unknown field and an unknown value are read, and survive a
// rewrite
func TestAdditiveChanges(t *testing.T) {
	dir := corpus(t)
	file := filepath.Join(dir, TypeFile(debDir, "deb"))
	newer := strings.Replace(read(t, file), `"author": "Will Murphy",`, `"author": "Will Murphy", "reviewedBy": "Alex Goodman",`, 1)
	newer = strings.Replace(newer, `"justification": "fix-installed"`, `"justification": "binary-stripped"`, 1)
	// a later ADDITION of the same MODEL is read, unlike syft refusing anything newer than itself
	newer = strings.Replace(newer, `"schema": "1.0.0"`, `"schema": "1.3.0"`, 1)
	write(t, file, newer)
	f, err := claimsv1.Parse("deb.json", []byte(newer))
	if err != nil {
		t.Fatal(err)
	}
	var stripped *claimsv1.Label
	for i := range f.Labels {
		if f.Labels[i].Justification == "binary-stripped" {
			stripped = &f.Labels[i]
		}
	}
	if stripped == nil || stripped.Verdict != claimsv1.FP || string(stripped.Extra["reviewedBy"]) != `"Alex Goodman"` {
		t.Fatalf("expected the label read with its unknown field and value, got %+v", f.Labels)
	}

	// another label written into the file keeps the unknown field on the one already there
	if _, err := (Writer{Dir: dir, Vocab: vocab}).Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "CVE-2024-2961")}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, file), `"reviewedBy": "Alex Goodman"`) {
		t.Error("expected the rewrite to keep the field this yardstick does not know")
	}
	if !strings.Contains(read(t, file), `"schema": "1.3.0"`) {
		t.Error("expected the rewrite to keep the newer version rather than stamp its own")
	}
}

func TestPaths(t *testing.T) {
	// legible-addresses and content-addressed-subjects: the registry and repository are in the
	// path, and the digest is the image's, spelled sha256-<hex> so no committed path holds a ':'
	r, _ := ref.Parse("oci:docker.io/cloudbees/cloudbees-core-mm:2.277@" + debDigest)
	dirName := strings.Replace(debDigest, "sha256:", "sha256-", 1)
	if got := TypeFile(ImageDir(r), "rpm"); got != "pkg/oci/docker.io/cloudbees/cloudbees-core-mm/"+dirName+"/matches/rpm.json" {
		t.Errorf("unexpected image path %s", got)
	}
	if got := DocumentDir(debDigest); got != "sbom/"+dirName {
		t.Errorf("unexpected document path %s", got)
	}
	if GlobalFile("java-archive") != "global/matches/java-archive.json" {
		t.Error("unexpected global path")
	}

	// corpus-layout: every place a file belongs reads back, and nothing else does
	for p, want := range map[string]Location{
		"pkg/oci/docker.io/anchore/test_images/" + dirName + "/matches/deb.json": {Kind: ImageSubject, Type: "deb", Registry: "docker.io", Repository: "anchore/test_images", Digest: debDigest},
		"pkg/oci/ghcr.io/a/b/c/" + dirName + "/matches/image.json":               {Kind: ImageSubject, Registry: "ghcr.io", Repository: "a/b/c", Digest: debDigest},
		"pkg/oci/docker.io/anchore/test_images/" + dirName + "/sbom.syft.json":   {Kind: ImageSubject, Registry: "docker.io", Repository: "anchore/test_images", Digest: debDigest},
		"sbom/" + dirName + "/matches/npm.json":                                  {Kind: DocumentSubject, Type: "npm", Digest: debDigest},
		"sbom/" + dirName + "/sbom.json":                                         {Kind: DocumentSubject, Digest: debDigest},
		"global/matches/java-archive.json":                                       {Kind: Global, Type: "java-archive"},
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
		"global/matches/image.json",
		"global/matches/sub/deb.json",
		// labels sit in matches/, and SBOMs beside it
		"pkg/oci/docker.io/anchore/test_images/" + dirName + "/deb.json",
		"pkg/oci/docker.io/anchore/test_images/" + dirName + "/matches/sbom.syft.json",
		"global/java-archive.json",
		"global/packages/deb.json",
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

// writes-keep-files-valid, one-label-per-key-sorted and labels-written-to-subject-files
func TestWriter(t *testing.T) {
	dir := corpus(t)
	file := filepath.Join(dir, TypeFile(debDir, "deb"))
	w := Writer{Dir: dir, Vocab: vocab}

	// labels landed in their files, package-less in image.json, global in global/
	if !strings.Contains(read(t, filepath.Join(dir, NoPackagePath(debDir))), `"vulnerability": "CVE-2023-4911"`) ||
		strings.Contains(read(t, filepath.Join(dir, NoPackagePath(debDir))), `"package"`) {
		t.Error("expected the package-less label in image.json, with no package")
	}
	if !strings.Contains(read(t, filepath.Join(dir, GlobalFile("deb"))), "libxml2") || strings.Contains(read(t, filepath.Join(dir, GlobalFile("deb"))), `"subject"`) {
		t.Error("expected the global label in global/matches/deb.json, with no subject")
	}

	// sorted by package, then vulnerability; the & of a purl is written as it is
	f, _ := claimsv1.Parse("deb.json", []byte(read(t, file)))
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
	if _, err := w.Write([]Placed{
		{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp("pkg:deb/debian/apt@2.6.1?arch=arm64&distro=debian-12", "CVE-2011-3374")},
		{File: TypeFile(debDir, "deb"), Subject: debImage, Label: relabeled},
	}); err != nil {
		t.Fatal(err)
	}
	f, _ = claimsv1.Parse("deb.json", []byte(read(t, file)))
	if len(f.Labels) != 4 || f.Labels[0].Vulnerability != "CVE-2011-3374" || f.Labels[3].Verdict != claimsv1.TP ||
		f.Labels[3].FirstIssued != now || f.Labels[3].LastUpdated != later {
		t.Errorf("expected the insert first and one zlib label, now tp with both dates, got %+v", f.Labels)
	}
	if !strings.Contains(read(t, file), strings.Split(before, `"package": "pkg:deb/debian/libc6`)[1][:40]) {
		t.Error("expected the libc label untouched")
	}

	// identical input, identical bytes
	again := read(t, file)
	if _, err := w.Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: relabeled}}); err != nil {
		t.Fatal(err)
	}
	if read(t, file) != again {
		t.Error("expected rewriting the same label to leave the bytes as they were")
	}
}

// a replacement carries the replaced label's notes forward and its evidence when the call is the
// same, says what it replaced, and reverting that puts the replaced label back byte for byte
func TestWriterReplaceAndRevert(t *testing.T) {
	dir := corpus(t)
	file := filepath.Join(dir, TypeFile(debDir, "deb"))
	w := Writer{Dir: dir, Vocab: vocab}
	at := func(l claimsv1.Label) Placed {
		return Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: l}
	}

	first := fp(zlib, "CVE-2022-37434")
	first.Evidence[0].Interpretation = "checked by hand"
	first.Notes = claimsv1.NotesOf("check the jar", "Will Murphy", now)
	if _, err := w.Write([]Placed{at(first)}); err != nil {
		t.Fatal(err)
	}
	before := read(t, file)

	again := fp(zlib, "CVE-2022-37434")
	again.Evidence, again.Notes, again.FirstIssued, again.LastUpdated = nil, claimsv1.NotesOf("still fp", "Alex Goodman", later), later, later
	newKey := tp("pkg:deb/debian/apt@2.6.1?arch=arm64&distro=debian-12", "CVE-2011-3374")
	written, err := w.Write([]Placed{at(again), at(newKey), at(again)})
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 2 {
		t.Fatalf("expected each key once, got %+v", written)
	}
	for _, wr := range written {
		switch wr.Key {
		case newKey.Key():
			if wr.Prior != nil {
				t.Errorf("expected no prior for a new key, got %+v", wr.Prior)
			}
		case first.Key():
			if wr.Prior == nil || wr.Prior.Notes[0].Text != "check the jar" || len(wr.Prior.Notes) != 1 {
				t.Errorf("expected the file's label as the prior, got %+v", wr.Prior)
			}
		default:
			t.Errorf("unexpected key %s", wr.Key)
		}
	}
	f, _ := claimsv1.Parse("deb.json", []byte(read(t, file)))
	i := slices.IndexFunc(f.Labels, func(l claimsv1.Label) bool { return l.Key() == first.Key() })
	got := f.Labels[i]
	if len(got.Notes) != 2 || got.Notes[0].Text != "check the jar" || got.Notes[1].Text != "still fp" {
		t.Errorf("expected both notes, the old one first, got %+v", got.Notes)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].Interpretation != "checked by hand" || got.FirstIssued != now {
		t.Errorf("expected the fp's evidence and firstIssued kept, got %+v", got)
	}

	// a call the other way keeps the notes but not evidence for the other verdict
	flipped := tp(zlib, "CVE-2022-37434")
	flip, err := w.Write([]Placed{at(flipped)})
	if err != nil {
		t.Fatal(err)
	}
	f, _ = claimsv1.Parse("deb.json", []byte(read(t, file)))
	got = f.Labels[slices.IndexFunc(f.Labels, func(l claimsv1.Label) bool { return l.Key() == first.Key() })]
	if len(got.Evidence) != 0 || len(got.Notes) != 2 {
		t.Errorf("expected the tp with the notes and no fp evidence, got %+v", got)
	}

	if err := w.Revert(flip); err != nil {
		t.Fatal(err)
	}
	if err := w.Revert(written); err != nil {
		t.Fatal(err)
	}
	if read(t, file) != before {
		t.Errorf("expected reverting both writes to restore the file, got\n%s", read(t, file))
	}

	// a prior that is not the key's label is refused
	bad := Written{File: TypeFile(debDir, "deb"), Key: first.Key(), Prior: &newKey}
	if err := w.Revert([]Written{bad}); err == nil {
		t.Error("expected a prior for another key refused")
	}
}

// revert without a prior drops labels by file and key, deletes a file it empties, and reverts
// nothing when one key is not there
func TestWriterRemove(t *testing.T) {
	dir := corpus(t)
	file, global := filepath.Join(dir, TypeFile(debDir, "deb")), filepath.Join(dir, GlobalFile("deb"))
	w := Writer{Dir: dir}
	key := func(file, pkg, vuln string) Written {
		return Written{File: file, Key: claimsv1.Key{Package: pkg, Vulnerability: vuln}}
	}

	before := read(t, file)
	for name, keys := range map[string][]Written{
		"a key not in the file":   {key(TypeFile(debDir, "deb"), zlib, "CVE-2022-37434"), key(TypeFile(debDir, "deb"), zlib, "CVE-2099-1")},
		"a file not there":        {key(TypeFile(debDir, "rpm"), zlib, "CVE-2022-37434")},
		"not a place in a layout": {key("images/centos/labels.json", zlib, "CVE-2022-37434")},
	} {
		if err := w.Revert(keys); err == nil {
			t.Errorf("%s: expected the remove refused", name)
		}
		if read(t, file) != before {
			t.Fatalf("%s: expected the file unchanged", name)
		}
	}

	if err := w.Revert([]Written{
		key(TypeFile(debDir, "deb"), zlib, "CVE-2022-37434"),
		key(TypeFile(debDir, "deb"), ncurse, "CVE-2023-29491"),
		key(GlobalFile("deb"), "pkg:deb/debian/libxml2@2.7.8.dfsg-2+squeeze1?distro=debian-7", "CVE-2016-1839"),
	}); err != nil {
		t.Fatal(err)
	}
	f, _ := claimsv1.Parse("deb.json", []byte(read(t, file)))
	if got := keys(f); got != "CVE-2023-4911 on "+libc {
		t.Errorf("expected only the libc label left, got %s", got)
	}
	if _, err := os.Stat(global); !os.IsNotExist(err) {
		t.Errorf("expected the emptied global file deleted, got %v", err)
	}
	if problems, err := ValidateCorpus(dir); err != nil || len(problems) != 0 {
		t.Errorf("expected the corpus valid after a remove, got %v %v", problems, err)
	}
}

func keys(f *claimsv1.File) string {
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
		"package in image.json":        {Placed{File: NoPackagePath(debDir), Subject: debImage, Label: tp(libc, "CVE-2024-6")}, "package must be absent"},
		"no package in a type file":    {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp("", "CVE-2024-7")}, "package is required"},
		"unknown namespace":            {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "FOO-2024-1")}, `namespace "FOO"`},
		"subject not the path's":       {Placed{File: TypeFile(debDir, "deb"), Subject: &claimsv1.Subject{Image: "docker.io/anchore/other@" + debDigest}, Label: tp(libc, "CVE-2024-8")}, "which the path names"},
		"not a place in the layout":    {Placed{File: "images/centos/labels.json", Subject: debImage, Label: tp(libc, "CVE-2024-9")}, "not a label file"},
		"evidence without facts":       {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: noFacts}, "evidence[0] needs at least one fact"},
		"fact observedAt not a time":   {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: badTime}, "evidence[0].facts[0].observedAt must be an RFC 3339 time"},
		"rule not listed":              {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: badRule}, `rule "debian/guess" is not listed`},
		"rule of the other verdict":    {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: wrongVerdict}, "rule debian/installed-has-fix supports fp, not tp"},
		"batch with one refused label": {Placed{File: TypeFile(debDir, "deb"), Subject: debImage, Label: noJust}, "needs a justification"},
	} {
		batch := []Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "CVE-2024-10")}, tt.p}
		_, err := w.Write(batch)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: expected an error with %q, got %v", name, tt.want, err)
		}
		if read(t, file) != before {
			t.Fatalf("%s: expected the file unchanged", name)
		}
	}
	if _, err := w.Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tpOnly}}); err != nil {
		t.Errorf("expected a tp with no justification written, got %v", err)
	}
	// a label on an advisory judges the match grype reported
	if _, err := w.Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "ELSA-2023-4428")}}); err != nil {
		t.Errorf("expected a label on an advisory id written, got %v", err)
	}
	anyRule := tp(libc, "CVE-2024-16")
	anyRule.Evidence = fp(libc, "CVE-2024-16").Evidence
	anyRule.Evidence[0].Rule = "judgement/prior-claims-pattern"
	anyRule.Evidence[0].Interpretation = ""
	if _, err := w.Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: anyRule}}); err != nil {
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
	if _, err := (Writer{Dir: dir, Vocab: vocab}).Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "CVE-2024-11")}}); err == nil {
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
			f, _ := claimsv1.Parse("deb.json", []byte(read(t, p)))
			f.Labels[0], f.Labels[2] = f.Labels[2], f.Labels[0]
			data, _ := claimsv1.Marshal(f)
			write(t, p, string(data))
		}, debFile, "CVE-2023-29491 on " + ncurse, "out of order"},
		{"duplicate key", func(t *testing.T, dir string) {
			p := filepath.Join(dir, filepath.FromSlash(debFile))
			f, _ := claimsv1.Parse("deb.json", []byte(read(t, p)))
			f.Labels = append(f.Labels, f.Labels[2])
			data, _ := claimsv1.Marshal(f)
			write(t, p, string(data))
		}, debFile, "CVE-2022-37434 on " + zlib, "listed twice"},
		{"two verdicts for one match", func(t *testing.T, dir string) {
			p := filepath.Join(dir, filepath.FromSlash(debFile))
			f, _ := claimsv1.Parse("deb.json", []byte(read(t, p)))
			dup := f.Labels[2]
			dup.Verdict, dup.Justification = claimsv1.TP, "fix-newer"
			f.Labels = append(f.Labels, dup)
			data, _ := claimsv1.Marshal(f)
			write(t, p, string(data))
		}, debFile, "CVE-2022-37434 on " + zlib, "two verdicts"},
		{"unknown justification", edit(debFile, `"fix-installed"`, `"binary-stripped"`), debFile, "CVE-2022-37434 on " + zlib, `"binary-stripped" is not listed under fp`},
		{"justification under the wrong verdict", edit(debFile, `"justification": "fix-newer"`, `"justification": "fix-installed"`), debFile, "CVE-2023-4911 on " + libc, `"fix-installed" is not listed under tp`},
		{"rule justification not under its verdict", edit(claimsv1.VocabularyFile, "verdict: tp, justification: no-fix", "verdict: tp, justification: fix-installed"), claimsv1.VocabularyFile, "", `rule debian/affected-unfixed: justification "fix-installed" is not listed under tp`},
		{"rule with an unknown ceiling", edit(claimsv1.VocabularyFile, "ceiling: medium, decision: P-4, basis: Debian", "ceiling: certain, decision: P-4, basis: Debian"), claimsv1.VocabularyFile, "", `ceiling "certain"`},
		{"unknown fact source", edit(debFile, `"debian-security-tracker"`, `"suse-oval"`), debFile, "CVE-2022-37434 on " + zlib, `"suse-oval"`},
		{"package in image.json", edit(NoPackagePath(debDir), `"vulnerability":`, `"package": "pkg:deb/debian/libc6", "vulnerability":`), NoPackagePath(debDir), "CVE-2023-4911 on pkg:deb/debian/libc6", "package must be absent"},
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
			write(t, filepath.Join(dir, "images/centos/labels.json"), `{"schema": "1.0.0", "labels": []}`)
		}, "images/centos/labels.json", "", "not a place in the corpus layout"},
		{"label file where it was before matches/", func(t *testing.T, dir string) {
			old := filepath.Join(dir, filepath.FromSlash(debDir), "deb.json")
			if err := os.Rename(filepath.Join(dir, filepath.FromSlash(debFile)), old); err != nil {
				t.Fatal(err)
			}
		}, debDir + "/deb.json", "", "move it to " + debFile},
		{"labels without their SBOM", func(t *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, debDir, ImageSBOMFile)) }, debDir, "", "no sbom.syft.json"},
		{"path and subject disagree", edit(debFile, "docker.io/anchore/yardstick-fixture-deb@", "docker.io/bitnami/yardstick-fixture-deb@"), debFile, "", "subject.image docker.io/bitnami/yardstick-fixture-deb@" + debDigest + " is not docker.io/anchore/yardstick-fixture-deb"},
		{"index digest without platform", func(t *testing.T, dir string) {
			// the SBOM's manifest is another digest than the directory's: the directory's is an index
			edit(debDir+"/"+ImageSBOMFile, `"manifestDigest":"`+debDigest, `"manifestDigest":"sha256:`+strings.Repeat("0", 64))(t, dir)
		}, debFile, "", "subject.platform must say which platform"},
		{"a schema v2 file", edit(debFile, `"schema": "1.0.0"`, `"schema": "2.0.0"`), debFile, "", "reads v1"},
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

	// a label kind this yardstick does not read is listed and skipped, never a problem
	t.Run("unknown label kind", func(t *testing.T) {
		dir := corpus(t)
		write(t, filepath.Join(dir, filepath.FromSlash(debDir), "packages", "deb.json"), "not a label file")
		write(t, filepath.Join(dir, "global", "packages", "deb.json"), "not a label file")
		if problems, err := ValidateCorpus(dir); err != nil || len(problems) != 0 {
			t.Errorf("expected an unknown label kind skipped, got %v %v", problems, err)
		}
		listed, err := UnknownKinds(dir)
		if err != nil || len(listed) != 2 || listed[0].File != "global/packages" || listed[1].File != debDir+"/packages" {
			t.Errorf("expected both packages/ directories listed, got %v %v", listed, err)
		}
	})

	// a subject nested under another subject's directory reads as an unknown kind there, and its
	// labels are still checked
	t.Run("nested subject under a subject", func(t *testing.T) {
		dir := corpus(t)
		nested := debDir + "/x/" + DigestDir(debDigest)
		write(t, filepath.Join(dir, filepath.FromSlash(TypeFile(nested, "deb"))), `{"schema": "1.0.0", "labels": [{"vulnerability": "CVE-2024-1"}]}`)
		problems, err := ValidateCorpus(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range problems {
			if p.File == TypeFile(nested, "deb") {
				return
			}
		}
		t.Errorf("expected the nested subject's label file checked, got %v", problems)
	})

	// an id in an advisory namespace is valid
	t.Run("advisory id", func(t *testing.T) {
		dir := corpus(t)
		edit(debFile, `"CVE-2023-4911"`, `"ALAS2-2023-1234"`)(t, dir)
		if problems, err := ValidateCorpus(dir); err != nil || len(problems) != 0 {
			t.Errorf("expected a label on an advisory id valid, got %v %v", problems, err)
		}
	})
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
	_, err := (Writer{Dir: dir, Vocab: vocab}).Write([]Placed{{File: TypeFile(debDir, "deb"), Subject: debImage, Label: tp(libc, "CVE-2024-11")}})
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

func TestWriteSchema(t *testing.T) {
	dir := t.TempDir()
	if _, wrote, err := WriteSchema(dir); err != nil || !wrote {
		t.Fatalf("expected the schema written, got %v %v", wrote, err)
	}
	if _, wrote, err := WriteSchema(dir); err != nil || wrote {
		t.Fatalf("expected an identical schema left alone, got %v %v", wrote, err)
	}
	write(t, filepath.Join(dir, claimsv1.SchemaFile), `{}`)
	if _, _, err := WriteSchema(dir); err == nil || !strings.Contains(err.Error(), "never edited") {
		t.Errorf("expected a different published schema refused, got %v", err)
	}
}
