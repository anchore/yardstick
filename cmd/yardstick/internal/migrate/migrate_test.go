package migrate

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// the corpus's own data: categories people write, not tool output
const vocabYAML = `justifications:
  fp:
    fix-installed: Installed version has the fix
    not-recorded: Migrated from vulnerability-match-labels, which recorded no reason
  tp:
    no-fix: Vulnerable code present, no fix for this version
  unclear:
    not-assessed: Nobody has assessed this version
    not-recorded: Migrated from vulnerability-match-labels, which recorded no reason
    labelers-disagree: Labelers of vulnerability-match-labels gave this match different verdicts
fact-sources: [nvd]
advisory-ids: ["ALAS*", ELSA, ALSA, RLSA, RHSA, AVG, FEDORA, BIT]
vulnerability-namespaces: [CVE, GHSA]
`

// every fixture SBOM was built by syft 1.14.0 with its default config
const catalogYAML = "syft: syft@v1.14.0\n"

// oraclelinux carries the advisory labels: single-CVE and multi-CVE ELSAs
var oracle = mustRef("oci:docker.io/oraclelinux@sha256:a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495")

func mustRef(s string) ref.Ref {
	r, err := ref.Parse(s)
	if err != nil {
		panic(err)
	}
	return r
}

// newCorpus is an empty corpus holding the fixture images' published SBOMs, as a corpus does
// before migration.
func newCorpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, labels.VocabularyFile), vocabYAML)
	write(t, filepath.Join(dir, labels.CatalogFile), catalogYAML)
	entries, err := os.ReadDir(fixture.Path("vml", "sbom"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		image := strings.ReplaceAll(strings.Replace(strings.TrimSuffix(e.Name(), ".syft.json.gz"), "@sha256-", "@sha256:", 1), "+", "/")
		r := mustRef("oci:" + image)
		f, err := os.Open(fixture.Path("vml", "sbom", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(zr)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(dir, labels.ImageDir(r), labels.ImageSBOMFile), string(data))
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

// fixtureLookup answers from what grype's DB said about the fixture's advisory ids, and records
// what it was asked.
func fixtureLookup(t *testing.T, asked *[]string) Lookup {
	t.Helper()
	data, err := os.ReadFile(fixture.Path("vml", "grype-db-search.json"))
	if err != nil {
		t.Fatal(err)
	}
	all, err := ParseGrypeSearch(data)
	if err != nil {
		t.Fatal(err)
	}
	return func(_ context.Context, ids []string) (map[string][]string, error) {
		*asked = append(*asked, ids...)
		out := map[string][]string{}
		for _, id := range ids {
			if a, ok := all[id]; ok {
				out[id] = a
			}
		}
		return out, nil
	}
}

func migrate(t *testing.T, vmlDir, corpus string) *Result {
	t.Helper()
	var asked []string
	res, err := Run(context.Background(), vmlDir, corpus, fixtureLookup(t, &asked))
	if err != nil {
		t.Fatal(err)
	}
	if err := (labels.Writer{Dir: corpus, Vocab: mustVocab(t, corpus)}).Write(res.Placed); err != nil {
		t.Fatal(err)
	}
	return res
}

func mustVocab(t *testing.T, corpus string) *labels.Vocabulary {
	v, err := labels.FindVocabulary(os.DirFS(corpus))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// tree is every file of a directory with the sha256 of its bytes.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		sum := sha256.Sum256(data)
		out[p] = hex.EncodeToString(sum[:])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func labelsIn(t *testing.T, corpus string, r ref.Ref, typ string) map[labels.Key]labels.Label {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(corpus, labels.TypeFile(labels.ImageDir(r), typ)))
	if err != nil {
		t.Fatal(err)
	}
	f, err := labels.Parse(typ, data)
	if err != nil {
		t.Fatal(err)
	}
	out := map[labels.Key]labels.Label{}
	for _, l := range f.Labels {
		out[l.Key()] = l
	}
	return out
}

func label(t *testing.T, got map[labels.Key]labels.Label, purl, vuln string) labels.Label {
	t.Helper()
	l, ok := got[labels.Key{Package: purl, Vulnerability: vuln}]
	if !ok {
		t.Fatalf("no label %s on %s", vuln, purl)
	}
	return l
}

func TestMigrate(t *testing.T) {
	corpus := newCorpus(t)
	res := migrate(t, fixture.Path("vml", "labels"), corpus)

	// every input label is reported, and the counts add up to them
	counts := res.Counts()
	want := map[Outcome]int{Migrated: 249, Carried: 12, FannedOut: 1, NoPackage: 1, NoSBOM: 1}
	total := 0
	for o, n := range counts {
		total += n
		if want[o] != n {
			t.Errorf("%s: %d input labels, expected %d", o, n, want[o])
		}
	}
	if total != 264 || len(res.Entries) != 264 {
		t.Errorf("%d input labels reported, expected all 264", total)
	}

	// the second run changes no byte
	before := tree(t, corpus)
	migrate(t, fixture.Path("vml", "labels"), corpus)
	after := tree(t, corpus)
	if len(before) != len(after) {
		t.Errorf("second run changed the file set: %d files, then %d", len(before), len(after))
	}
	for p, sum := range before {
		if after[p] != sum {
			t.Errorf("second run changed %s", p)
		}
	}

	problems, err := labels.ValidateCorpus(corpus)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("validate: %s", p)
	}

	rpm := labelsIn(t, corpus, oracle, "rpm")
	// ELSA-2022-9246 names only CVE-2022-0778: the verdict moves to the CVE
	if l := label(t, rpm, "pkg:rpm/ol/openssl@1.0.1e-58.0.1.el6_10", "CVE-2022-0778"); l.Verdict != labels.TP || l.SeenIn == nil || l.SeenIn.Grype != "grype@v0.51.0" {
		t.Errorf("single-CVE advisory: expected tp on CVE-2022-0778 seen in grype@v0.51.0, got %+v", l)
	}
	// the epoch the old label's version carried stays in the purl
	label(t, rpm, "pkg:rpm/ol/dhclient@4.1.1-63.P1.0.1.el6_10?epoch=12", "CVE-2021-25217")
	// ELSA-2022-9359 names three CVEs: unclear on each, the tp carried to none
	for _, cve := range []string{"CVE-2022-25235", "CVE-2022-25236", "CVE-2022-25315"} {
		l := label(t, rpm, "pkg:rpm/ol/expat@2.0.1-13.el6_8", cve)
		if l.Verdict != labels.Unclear || l.Justification != NotAssessed {
			t.Errorf("multi-CVE advisory on %s: expected unclear not-assessed, got %s %s", cve, l.Verdict, l.Justification)
		}
	}
	for k := range rpm {
		if strings.HasPrefix(k.Vulnerability, "ELSA") {
			t.Errorf("an advisory id was written: %s", k)
		}
	}
	// pyOpenSSL is pyopenssl in this SBOM's python package
	// a label that named no tool says nothing about what it was seen in
	if l := label(t, labelsIn(t, corpus, oracle, "python"), "pkg:pypi/pyopenssl@0.13.1", "CVE-2018-1000807"); l.SeenIn != nil {
		t.Errorf("no tool: expected no seenIn, got %+v", l.SeenIn)
	}

	// two labelers disagree on one match: one unclear label naming both
	disagree := label(t, labelsIn(t, corpus, mustRef("oci:docker.io/anchore/test_images@sha256:7536ee345532f674ec9e448e3768db4e546c48220ba2b6ec9bc9cfbfb3b7b74a"), "go-module"),
		"pkg:golang/github.com/opencontainers/image-spec@v1.0.1", "GHSA-77vh-xpmg-72qh")
	if disagree.Verdict != labels.Unclear || disagree.Justification != LabelersDisagree || disagree.Author != "wagoodman, westonsteimel" {
		t.Errorf("contradiction: expected one unclear labelers-disagree by both, got %+v", disagree)
	}
	if disagree.SeenIn == nil || disagree.SeenIn.Grype != "grype@v0.61.1" {
		t.Errorf("contradiction: expected seenIn from the later call's grype, got %+v", disagree.SeenIn)
	}
	if disagree.FirstIssued != "2022-09-15T00:46:56Z" || disagree.LastUpdated != "2023-05-10T11:38:00Z" {
		t.Errorf("contradiction: expected the earlier and later call's times, got %s and %s", disagree.FirstIssued, disagree.LastUpdated)
	}

	// ?? and FP record no reason
	wolfi := labelsIn(t, corpus, mustRef("oci:cgr.dev/chainguard/wolfi-base@sha256:be3834598c3c4b76ace6a866edcbbe1fa18086f9ee238b57769e4d230cd7d507"), "apk")
	if l := label(t, wolfi, "pkg:apk/wolfi/glibc@2.36-r0", "CVE-2010-4756"); l.Verdict != labels.Unclear || l.Justification != NotRecorded {
		t.Errorf("??: expected unclear not-recorded, got %s %s", l.Verdict, l.Justification)
	}

	// labels with no package type are reported, not written
	cloudbees := filepath.Join(corpus, labels.ImageDir(mustRef("oci:docker.io/cloudbees/cloudbees-core-mm@sha256:4c564f473d38f23da1caa48c4ef53b958ef03d279232007ad3319b1f38584bdb")))
	if _, err := os.Stat(cloudbees); !os.IsNotExist(err) {
		t.Errorf("labels with no package type were written under %s", cloudbees)
	}
	report := t.TempDir()
	if err := res.WriteReport(report); err != nil {
		t.Fatal(err)
	}
	var unknown []Entry
	data, _ := os.ReadFile(filepath.Join(report, UnknownFile))
	if err := json.Unmarshal(data, &unknown); err != nil {
		t.Fatal(err)
	}
	reasons := map[Outcome]string{}
	for _, e := range unknown {
		reasons[e.Outcome] = e.Reason
	}
	if len(unknown) != 2 || !strings.Contains(reasons[NoPackage], "fullentry_fields") || !strings.Contains(reasons[NoSBOM], "sbom.syft.json") {
		t.Errorf("unknown.json: expected the no-package and no-SBOM labels with their reasons, got %+v", unknown)
	}
	var all []Entry
	data, _ = os.ReadFile(filepath.Join(report, ReportFile))
	if err := json.Unmarshal(data, &all); err != nil || len(all) != 264 {
		t.Errorf("report.json: expected all 264 input labels, got %d (%v)", len(all), err)
	}
	for _, e := range all {
		if e.Outcome.Converted() && len(e.Became) == 0 {
			t.Errorf("report.json: %s was converted and names no output", e.ID)
		}
	}
}

// vml writes labels in the old format into a labels directory, one file per label: people's
// calls, not tool output.
func vml(t *testing.T, image string, ls ...string) string {
	t.Helper()
	dir := t.TempDir()
	for i, l := range ls {
		write(t, filepath.Join(dir, "img", fmt.Sprintf("%02d.json", i)), strings.ReplaceAll(l, "IMAGE", image))
	}
	return dir
}

func TestMigrateRules(t *testing.T) {
	corpus := newCorpus(t)
	res := migrate(t, vml(t, oracle.Image(),
		// a direct call and a multi-CVE advisory's call on one key: the direct one wins
		`{"ID": "a", "image": {"exact": "IMAGE"}, "label": "FP", "package": {"name": "expat", "version": "2.0.1-13.el6_8"}, "timestamp": "2023-01-02T00:00:00+00:00", "user": "alice", "vulnerability_id": "CVE-2022-25235"}`,
		`{"ID": "b", "image": {"exact": "IMAGE"}, "label": "TP", "package": {"name": "expat", "version": "2.0.1-13.el6_8"}, "timestamp": "2023-01-01T00:00:00+00:00", "user": "bob", "vulnerability_id": "ELSA-2022-9359"}`,
		// two people agreeing: one label by both, spanning both times
		`{"ID": "c", "image": {"exact": "IMAGE"}, "label": "TP", "package": {"name": "zlib", "version": "1.2.3-29.el6"}, "timestamp": "2022-05-01 10:00:00", "user": "bob", "vulnerability_id": "CVE-2018-25032"}`,
		`{"ID": "c", "image": {"exact": "IMAGE"}, "label": "TP", "package": {"name": "zlib", "version": "1.2.3-29.el6"}, "timestamp": "2022-06-01", "user": "alice", "vulnerability_id": "CVE-2018-25032"}`,
		// an advisory grype's DB no longer has
		`{"ID": "d", "image": {"exact": "IMAGE"}, "label": "TP", "package": {"name": "openssl", "version": "1.0.1e-58.0.1.el6_10"}, "timestamp": "2022-05-01", "user": "bob", "vulnerability_id": "ALAS-2021-1608"}`,
	), corpus)

	rpm := labelsIn(t, corpus, oracle, "rpm")
	if l := label(t, rpm, "pkg:rpm/ol/expat@2.0.1-13.el6_8", "CVE-2022-25235"); l.Verdict != labels.FP || l.Justification != NotRecorded || l.Author != "alice" {
		t.Errorf("direct over fanned out: expected alice's fp, got %+v", l)
	}
	if l := label(t, rpm, "pkg:rpm/ol/expat@2.0.1-13.el6_8", "CVE-2022-25236"); l.Verdict != labels.Unclear || l.Author != "bob" {
		t.Errorf("the advisory's other CVEs: expected bob's unclear, got %+v", l)
	}
	l := label(t, rpm, "pkg:rpm/ol/zlib@1.2.3-29.el6", "CVE-2018-25032")
	if l.Verdict != labels.TP || l.Author != "alice, bob" || l.FirstIssued != "2022-05-01T10:00:00Z" || l.LastUpdated != "2022-06-01T00:00:00Z" {
		t.Errorf("agreeing labels: expected one tp by both from the first call to the last, got %+v", l)
	}
	if len(rpm) != 4 {
		t.Errorf("expected 4 labels, got %d", len(rpm))
	}
	if got := res.Entries[4]; got.Outcome != NoCVE || !strings.Contains(got.Reason, "ALAS-2021-1608") {
		t.Errorf("unknown advisory: expected %s naming it, got %+v", NoCVE, got)
	}
}
