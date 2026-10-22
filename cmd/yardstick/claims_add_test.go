package main

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

// seen-in-filled-from-the-run, writes-to-last-local-source and labels-written-to-subject-files,
// through the CLI
func TestClaimsAdd(t *testing.T) {
	w := newWorkspace(t)
	noTar := w.grype("no-tar", "CVE-2005-2541 tar")
	whole := w.grype("whole")
	w.label(libc, "CVE-2026-5450")
	w.gate("deb", noTar, whole, "", "  - name: noNewFalseNegatives\n")
	// a document subject filtered to its python packages, so the SBOM scanned is not the SBOM
	// the document's labels are addressed by
	oracle := filepath.Join(w.dir, "oracle.syft.json")
	writeFile(t, oracle, gunzip(t, fixture.Path("vml", "sbom", "docker.io+oraclelinux@sha256-a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495.syft.json.gz")))
	ol := stubTool(t, w.tools, "oracle-grype", "#!/bin/sh\ncat \""+fixture.Path("vml", "grype-oraclelinux.json")+"\"\n")
	writeFile(t, filepath.Join(w.dir, "gates", "oracle.yaml"), `schema: v1
claims: [../claims]
candidate: {grype: `+ol+`, db: "dir:`+w.tools+`"}
subjects: [{ref: "sbom:../oracle.syft.json", name: python-only, packages: {keepTypes: [python]}}]
checks: [{name: unlabeledPercentAtMost, params: {max: 100}}]
`)
	if err := os.MkdirAll(filepath.Join(w.dir, "local"), 0o755); err != nil {
		t.Fatal(err)
	}
	// the local source is one of the gate's claims sources from the scan on
	if _, stderr, code := yardstick(t, w.dir, "gates/deb.yaml", "gates/oracle.yaml", "--claims", "local"); code != 1 {
		t.Fatalf("expected the dropped tar match undecided, failing under undecided: fail, got %d: %s", code, stderr)
	}

	add := func(args ...string) (string, string, int) {
		return yardstick(t, w.dir, append([]string{"claims", "add", "--gate", "gates/deb.yaml", "--claims", "local", "--author", "Alex Goodman"}, args...)...)
	}
	// an fp without a justification is refused, naming the field and the allowed values
	_, stderr, code := add("--subject", "deb", "--package", tar, "--vulnerability", "CVE-2005-2541", "--verdict", "fp")
	if code != 2 || !strings.Contains(stderr, "fp needs a justification") || !strings.Contains(stderr, "fix-installed") {
		t.Fatalf("expected the fp refused naming its justifications, got %d: %s", code, stderr)
	}
	stdout, stderr, code := add("--subject", "deb", "--package", tar, "--vulnerability", "CVE-2005-2541", "--verdict", "tp")
	if code != 0 {
		t.Fatalf("expected the label written, got %d: %s %s", code, stdout, stderr)
	}

	// it lands in the last source, the subject's deb.json, with seenIn from the scan
	r, _ := ref.Parse(debImage)
	f := labelFile(t, filepath.Join(w.dir, "local", corpus.ImageDir(r), "deb.json"))
	t.Chdir(w.dir)
	rec, err := runrecord.Load(runrecord.DefaultName, "deb")
	if err != nil {
		t.Fatal(err)
	}
	// only the reference reported the tar match, so seenIn names the reference's grype
	seen := f.Labels[0].SeenIn
	if seen == nil || seen.SBOM != rec.Subjects[0].UnfilteredDigest || seen.Tool(claimsv1.ToolSyft) != "1.54.1" || seen.Tool(claimsv1.ToolGrype) != whole {
		t.Errorf("expected seenIn from the scan, with the reference's grype, got %+v", seen)
	}
	// a match both setups report names the candidate's
	if _, stderr, code := add("--subject", "deb", "--package", libc, "--vulnerability", "CVE-2026-5450", "--verdict", "tp"); code != 0 {
		t.Fatalf("expected the label written, got %d: %s", code, stderr)
	}
	both, err := claimsv1.Parse("deb.json", []byte(read(t, filepath.Join(w.dir, "local", corpus.ImageDir(r), "deb.json"))))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range both.Labels {
		if l.Vulnerability == "CVE-2026-5450" && l.SeenIn.Tool(claimsv1.ToolGrype) != noTar {
			t.Errorf("expected seenIn with the candidate's grype for a match both report, got %+v", l.SeenIn)
		}
	}
	if strings.Contains(read(t, filepath.Join(w.dir, "claims", corpus.ImageDir(r), "deb.json")), "CVE-2005-2541") {
		t.Error("the label was written into the gate's own claims source instead of the last one")
	}

	// on the filtered subject, seenIn.sbom is the unfiltered document's digest, which addresses
	// the document's files
	if _, stderr, code := yardstick(t, w.dir, "claims", "add", "--gate", "gates/oracle.yaml", "--claims", "local", "--author", "Alex Goodman",
		"--subject", "python-only", "--package", "pkg:pypi/pyopenssl", "--vulnerability", "CVE-2018-1000807", "--verdict", "tp"); code != 0 {
		t.Fatalf("expected the label written, got %d: %s", code, stderr)
	}
	olRec, err := runrecord.Load(runrecord.DefaultName, "oracle")
	if err != nil {
		t.Fatal(err)
	}
	sub := olRec.Subjects[0]
	f = labelFile(t, filepath.Join(w.dir, "local", corpus.DocumentDir(sub.UnfilteredDigest), "python.json"))
	if f.Labels[0].SeenIn.SBOM != sub.UnfilteredDigest || sub.Digest == sub.UnfilteredDigest || f.Subject.SBOM != sub.UnfilteredDigest {
		t.Errorf("expected seenIn.sbom and the subject to be the unfiltered digest %s (scanned %s), got %+v %+v", sub.UnfilteredDigest, sub.Digest, f.Labels[0].SeenIn, f.Subject)
	}

	// a label with no package lands in image.json
	if _, stderr, code := add("--subject", "deb", "--vulnerability", "CVE-2023-4911", "--verdict", "tp"); code != 0 {
		t.Fatalf("expected an image-level label written, got %d: %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(w.dir, "local", corpus.ImageDir(r), corpus.NoPackageFile)); err != nil {
		t.Errorf("expected image.json: %v", err)
	}

	// scored with the new label, the dropped tar match is a new false negative
	stdout, _, code = yardstick(t, w.dir, "score", "gates/deb.yaml", "--claims", "local", "-o", "check")
	if code != 1 || !strings.Contains(stdout, "FAIL noNewFalseNegatives") || !strings.Contains(stdout, "1 tp, dropped by the candidate\n      CVE-2005-2541 ") {
		t.Errorf("expected the labeled tar match to fail the gate, got %d: %s", code, stdout)
	}
}

func labelFile(t *testing.T, p string) *claimsv1.File {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("expected a label file at %s: %v", p, err)
	}
	f, err := claimsv1.Parse(p, data)
	if err != nil || len(f.Labels) != 1 {
		t.Fatalf("expected one label in %s, got %v %v", p, f, err)
	}
	return f
}

func gunzip(t *testing.T, p string) string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func read(t *testing.T, p string) string {
	t.Helper()
	data, _ := os.ReadFile(p)
	return string(data)
}

// claims add writes nothing through a symlinked subject directory in the last source
func TestClaimsAddStaysInsideTheSource(t *testing.T) {
	w := newWorkspace(t)
	whole := w.grype("whole")
	w.label(libc, "CVE-2026-5450")
	w.gate("deb", whole, whole, "", "  - name: noNewFalseNegatives\n")
	if err := os.MkdirAll(filepath.Join(w.dir, "local"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := yardstick(t, w.dir, "gates/deb.yaml", "--claims", "local"); code != 0 {
		t.Fatalf("expected the gate to pass, got %d: %s", code, stderr)
	}
	// the subject's directory in the source becomes a link out of it after the scan; reads
	// through it are refused as well
	r, _ := ref.Parse(debImage)
	outside := t.TempDir()
	link := filepath.Join(w.dir, "local", filepath.FromSlash(corpus.ImageDir(r)))
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := yardstick(t, w.dir, "claims", "add", "--gate", "gates/deb.yaml", "--claims", "local", "--author", "Alex Goodman",
		"--subject", "deb", "--package", tar, "--vulnerability", "CVE-2005-2541", "--verdict", "tp")
	if code != 2 {
		t.Errorf("expected the write through a symlink refused, got %d: %s", code, stderr)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("claims add wrote outside the claims source: %v", entries)
	}
}

// export reads the corpus through os.Root, so a label file symlinked from outside it is refused
// rather than exported
func TestClaimsExportStaysInsideTheCorpus(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "outside", claimsv1.VocabularyFile), importVocabulary)
	if _, stderr, code := yardstick(t, dir, "claims", "import", fixture.Path("vex", "vendor.openvex.json"), "--to", "outside", "--author", "Will Murphy"); code != 0 {
		t.Fatalf("import: %d %s", code, stderr)
	}
	if err := os.MkdirAll(filepath.Join(dir, "corpus", "global"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "outside", "global", "rpm.json"), filepath.Join(dir, "corpus", "global", "rpm.json")); err != nil {
		t.Fatal(err)
	}
	if stdout, _, code := yardstick(t, dir, "claims", "export", "--vex", "corpus"); code == 0 || strings.Contains(stdout, "CVE-2024-0727") {
		t.Errorf("expected the symlinked label file refused, got %d %s", code, stdout)
	}
}

const importVocabulary = `justifications:
  fp: {fix-installed: Installed version has the fix, vulnerable_code_not_present: Vulnerable code is not in this package}
  tp: {fix-newer: Fix is in a newer version than installed}
  unclear: {not-assessed: Nobody has assessed this version}
fact-sources: [openvex]
vulnerability-namespaces: [CVE]
`

// importing over a label someone already made says so, since the vendor's statement replaces it
func TestClaimsImportWarnsOnReplace(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "claims", claimsv1.VocabularyFile), importVocabulary)
	doc := fixture.Path("vex", "vendor.openvex.json")
	imp := func(author string) string {
		t.Helper()
		stdout, stderr, code := yardstick(t, dir, "claims", "import", doc, "--to", "claims", "--author", author)
		if code != 0 {
			t.Fatalf("import by %s: %d %s", author, code, stderr)
		}
		return stdout
	}
	if out := imp("Will Murphy"); strings.Contains(out, "replaced") {
		t.Errorf("expected nothing replaced on the first import, got %s", out)
	}
	if out := imp("Alex Goodman"); !strings.Contains(out, "replaced Will Murphy's fp label on CVE-2023-45853") {
		t.Errorf("expected the second import to name what it replaced, got %s", out)
	}
}
