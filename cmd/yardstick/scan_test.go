package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/testkit"
)

func stubTool(t *testing.T, dir, name, script string) string {
	t.Helper()
	return testkit.StubTool(t, dir, name, script)
}

const debImage = testkit.DebImage

// collect-builds-an-sbom-from-a-catalog, the refusals; the build itself runs the real syft in
// TestCollectIntoACorpus (-tags integration)
func TestCollectRefuses(t *testing.T) {
	corpusDir := filepath.Join(t.TempDir(), "corpus")
	writeFile(t, filepath.Join(corpusDir, corpus.CatalogFile), "syft: syft@v1.54.1\n")
	outside := filepath.Join(filepath.Dir(corpusDir), "outside.yaml")
	writeFile(t, outside, "search:\n  scope: all-layers\n")
	if err := os.Symlink(outside, filepath.Join(corpusDir, "linked.yaml")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, catalog string
		args          []string
		want          string
	}{
		{"a tag without a digest", "", []string{"oci:docker.io/library/ubuntu:22.04"}, "pinned by digest"},
		{"an unpinned syft", "syft: syft@latest\n", nil, "syft must be pinned"},
		// a corpus catalog is data: no binary by path, no variables beyond syft's own
		{"syft by path", "syft: ./bin/syft\n", nil, "not a path to a binary"},
		{"a loader variable", "syft: syft@v1.54.1\nenv: {LD_PRELOAD: /tmp/x.so}\n", nil, "only SYFT_* variables, got LD_PRELOAD"},
		// nor a config outside the corpus
		{"config outside the corpus", "syft: syft@v1.54.1\nconfig: ../outside.yaml\n", nil, `config "../outside.yaml" must be a path inside the corpus`},
		{"config by absolute path", "syft: syft@v1.54.1\nconfig: " + outside + "\n", nil, "must be a path inside the corpus"},
		{"config by a symlink out of the corpus", "syft: syft@v1.54.1\nconfig: linked.yaml\n", nil, "config: "},
		// what only the --gate form reads
		{"--rebuild-sboms without --gate", "syft: syft@v1.54.1\n", []string{"--rebuild-sboms"}, "--claims and --rebuild-sboms apply only with --gate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"collect", "sboms"}, tc.args...)
			if tc.catalog != "" {
				writeFile(t, filepath.Join(corpusDir, "c.yaml"), tc.catalog)
				args = append(args, debImage, "--catalog", "c.yaml")
			}
			_, stderr, code := yardstick(t, corpusDir, args...)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Errorf("expected exit 2 saying %q, got %d: %s", tc.want, code, stderr)
			}
		})
	}
}

// stubGrype stands in for a setup's grype: it prints the fixture grype output for the deb image.
const stubGrype = `#!/bin/sh
cat "{{OUT}}"
`

// a gate over the deb image, its SBOM in the claims directory, scanned by two stub grypes on a DB
// directory
func scanGate(t *testing.T, dir string) {
	t.Helper()
	tools := t.TempDir()
	candidate := stubTool(t, tools, "candidate-grype", strings.Replace(stubGrype, "{{OUT}}", fixture.Grype("v0.120.1", "deb"), 1))
	reference := stubTool(t, tools, "reference-grype", strings.Replace(stubGrype, "{{OUT}}", fixture.Grype("v0.119.0", "deb"), 1))
	r, _ := ref.Parse(debImage)
	sbom, _ := os.ReadFile(fixture.SBOM("deb", "syft"))
	writeFile(t, filepath.Join(dir, "claims", corpus.ImageDir(r), corpus.ImageSBOMFile), string(sbom))
	writeFile(t, filepath.Join(dir, "claims", claimsv1.VocabularyFile), "justifications: {fp: {fix-installed: x}}\nfact-sources: [sbom]\nadvisory-ids: [ELSA]\nvulnerability-namespaces: [CVE, GHSA]\n")
	writeFile(t, filepath.Join(dir, "gates/deb.yaml"), `schema: v1
claims: [../claims]
candidate: {grype: `+candidate+`, db: "dir:`+t.TempDir()+`"}
reference: {grype: `+reference+`, db: "dir:`+t.TempDir()+`"}
subjects: [{ref: "`+debImage+`", name: deb}]
checks:
  - name: noNewFalseNegatives
  - name: unlabeledChangesAtMost
    params: {max: 0}
`)
}

// the scan half of gate-and-score-commands: every gate loads before any scan, and a run keeps one
// set of scans per gate in the working directory, never in a claims source
func TestRunScansGates(t *testing.T) {
	dir := t.TempDir()
	scanGate(t, dir)

	// a second gate that does not load stops the run before anything is scanned
	writeFile(t, filepath.Join(dir, "gates/bad.yaml"), strings.Replace(validGate, "noNewFalseNegatives", "noRegressions", 1))
	_, stderr, code := yardstick(t, dir, "gates/deb.yaml", "gates/bad.yaml")
	if code != 2 || !strings.Contains(stderr, "noRegressions") {
		t.Fatalf("expected exit 2 naming the bad gate, got %d: %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, ".yardstick")); !os.IsNotExist(err) {
		t.Fatalf("expected no scan before every gate loads, got %v", err)
	}

	_, stderr, _ = yardstick(t, dir, "gates/deb.yaml")
	data, err := os.ReadFile(filepath.Join(dir, ".yardstick", "runs", "default", "deb", "yardstick-run.json"))
	if err != nil {
		t.Fatalf("expected the gate's run record, got %v: %s", err, stderr)
	}
	var rec struct {
		Gate   struct{ Name string }
		Setups map[string]struct {
			Grype struct{ Bin string }
			DB    struct{ Dir string }
		}
		Subjects []struct {
			Name  string
			From  string
			Scans map[string]string
		}
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Gate.Name != "deb" || len(rec.Subjects) != 1 || rec.Subjects[0].From != "source" || len(rec.Subjects[0].Scans) != 2 {
		t.Errorf("expected one subject from the claims source scanned by both setups, got %s", data)
	}
	// the skills run each side's grype against its DB, so the record names both paths
	for name, p := range rec.Setups {
		if p.Grype.Bin == "" || p.DB.Dir == "" {
			t.Errorf("expected setup %s to name its grype binary and DB dir, got %+v", name, p)
		}
	}
	if len(rec.Setups) != 2 {
		t.Errorf("expected two setups, got %s", data)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "claims")); len(entries) != 2 {
		t.Errorf("expected nothing written into the claims source, got %v", entries)
	}
}

// a run opens a remote claims source once, shared by the scan and the scoring
func TestRunOpensRemoteSourceOnce(t *testing.T) {
	dir := t.TempDir()
	scanGate(t, dir)

	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	root := filepath.Join(dir, "claims")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(zipped.Bytes())
	digest := "sha256:" + hex.EncodeToString(sum[:])

	var mu sync.Mutex
	requests := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests[r.URL.Path]++
		mu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/claims/matches/latest-"):
			_ = json.NewEncoder(w).Encode(map[string]string{"digest": digest})
		case r.URL.Path == "/claims/matches/snapshots/"+strings.TrimPrefix(digest, "sha256:")+".zip":
			_, _ = w.Write(zipped.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("YARDSTICK_CLAIMS_URL", srv.URL)
	// one cache for the run and the pull after it
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())

	gate := filepath.Join(dir, "gates/deb.yaml")
	data, err := os.ReadFile(gate)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, gate, strings.Replace(string(data), "[../claims]", "[github.com/anchore/delta-prototype@main]", 1))

	_, stderr, _ := yardstick(t, dir, "-v", "gates/deb.yaml")
	if _, err := os.Stat(filepath.Join(dir, ".yardstick", "runs", "default", "deb", "yardstick-run.json")); err != nil {
		t.Fatalf("expected the run to scan, got %v: %s", err, stderr)
	}
	// pull reads the pointer again and finds the snapshot already cached
	stdout, pullErr, code := yardstick(t, dir, "claims", "pull", "github.com/anchore/claims@main")
	if want := "✔ cached claims\n  ├ github.com/anchore/claims@main\n  └ " + digest; code != 0 || strings.TrimSpace(stdout) != want {
		t.Errorf("expected pull to name the snapshot, got %d %q: %s", code, stdout, pullErr)
	}
	mu.Lock()
	defer mu.Unlock()
	if n := requests["/claims/matches/snapshots/"+strings.TrimPrefix(digest, "sha256:")+".zip"]; n != 1 {
		t.Errorf("expected the snapshot fetched once, got %d requests: %v", n, requests)
	}
	if n := len(requests); n != 2 {
		t.Errorf("expected one pointer read and one snapshot read, got %v", requests)
	}
	if strings.Contains(stderr, "using cached claims snapshot") || strings.Count(stderr, "opening remote claims source") != 1 {
		t.Errorf("expected the source opened once, got\n%s", stderr)
	}
}

// runs-are-named: each run name keeps its own scans under .yardstick/runs/<name>/, picked by
// --name or YARDSTICK_NAME with the flag winning, and Python yardstick's entries beside runs/ are
// never touched
func TestNamedRunsStayApart(t *testing.T) {
	w := newWorkspace(t)
	w.label(tar, "CVE-2005-2541")
	reference := w.grype("reference")
	// the candidate stub prints whatever cand.json holds, so one gate file gives different scans
	// per run; every yardstick call gets an empty cache, so nothing is reused across runs
	candidate := w.grype("cand")
	w.gate("deb", candidate, reference, "", "  - name: noNewFalseNegatives\n")
	if err := os.MkdirAll(filepath.Join(w.dir, "local"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Python yardstick's store: tools/, result/ and a labels symlink
	store := filepath.Join(w.dir, ".yardstick")
	writeFile(t, filepath.Join(store, "tools", "grype", "v0.1.0", "grype"), "python's grype")
	writeFile(t, filepath.Join(store, "result", "store", "x.json"), "{}")
	if err := os.Symlink("../claims", filepath.Join(store, "labels")); err != nil {
		t.Fatal(err)
	}
	python := tree(t, store)

	// a name that is not one segment fails every command before anything is written
	for _, name := range []string{"../x", "a/b", "Result"} {
		for _, args := range [][]string{
			{"gates/deb.yaml"},
			{"score", "gates/deb.yaml"},
			{"claims", "add", "--gate", "gates/deb.yaml", "--claims", "local", "--subject", "deb", "--vulnerability", "CVE-1", "--verdict", "tp"},
		} {
			_, stderr, code := yardstick(t, w.dir, append(args, "--name", name)...)
			if code != 2 || !strings.Contains(stderr, "[a-z0-9][a-z0-9._-]*") {
				t.Errorf("%v --name %s: expected exit 2 naming the allowed form, got %d: %s", args, name, code, stderr)
			}
		}
	}
	if got := tree(t, store); !maps.Equal(got, python) {
		t.Fatalf("a refused name wrote under .yardstick: %v", got)
	}

	run := func(name string, args ...string) {
		t.Helper()
		if _, stderr, code := yardstick(t, w.dir, append([]string{"gates/deb.yaml"}, args...)...); code == 2 {
			t.Fatalf("run %v: %s", args, stderr)
		}
		if _, err := os.Stat(filepath.Join(store, "runs", name, "deb", "yardstick-run.json")); err != nil {
			t.Fatalf("run %v: expected the record under runs/%s: %v", args, name, err)
		}
	}
	run("default")
	// run a's candidate drops the labeled tar match, the others' do not
	w.grype("cand", "CVE-2005-2541 tar")
	run("a", "--name", "a")
	w.grype("cand")
	t.Run("env", func(t *testing.T) {
		t.Setenv("YARDSTICK_NAME", "b")
		run("b")
		run("pr", "--name", "pr")
	})

	// score reads only the named run's scans
	stdout, _, code := yardstick(t, w.dir, "score", "gates/deb.yaml", "--name", "a", "-o", "check")
	if code != 1 || !strings.Contains(stdout, "FAIL noNewFalseNegatives") {
		t.Errorf("expected run a's dropped tp to fail the gate, got %d: %s", code, stdout)
	}
	if stdout, _, code := yardstick(t, w.dir, "score", "gates/deb.yaml", "--name", "b", "-o", "check"); code != 0 {
		t.Errorf("expected run b to pass, got %d: %s", code, stdout)
	}
	if _, stderr, code := yardstick(t, w.dir, "score", "gates/deb.yaml", "--name", "nightly"); code != 2 || !strings.Contains(stderr, "runs/nightly/deb; run yardstick gates/deb.yaml --name nightly first") {
		t.Errorf("expected a run never made named with the command that makes it, got %d: %s", code, stderr)
	}

	// so does claims add: in run a only the reference reported tar, so seenIn names its grype
	if _, stderr, code := yardstick(t, w.dir, "claims", "add", "--gate", "gates/deb.yaml", "--claims", "local", "--author", "e2e", "--name", "a",
		"--subject", "deb", "--package", tar, "--vulnerability", "CVE-2005-2541", "--verdict", "tp"); code != 0 {
		t.Fatalf("expected the label written, got %d: %s", code, stderr)
	}
	r, _ := ref.Parse(debImage)
	if seen := labelFile(t, filepath.Join(w.dir, "local", filepath.FromSlash(corpus.TypeFile(corpus.ImageDir(r), "deb")))).Labels[0].SeenIn; seen.Tool(claimsv1.ToolGrype) != reference {
		t.Errorf("expected seenIn from run a's reference grype, got %+v", seen)
	}

	// each name holds only its gate, no partial or old set is left beside it, and Python's
	// entries are as they were, the symlink included
	names, _ := os.ReadDir(filepath.Join(store, "runs"))
	var got []string
	for _, n := range names {
		gates, _ := os.ReadDir(filepath.Join(store, "runs", n.Name()))
		if len(gates) != 1 || gates[0].Name() != "deb" {
			t.Errorf("expected runs/%s to hold only deb, got %v", n.Name(), gates)
		}
		got = append(got, n.Name())
	}
	if !slices.Equal(got, []string{"a", "b", "default", "pr"}) {
		t.Errorf("expected runs default, a, b and pr, got %v", got)
	}
	top, _ := os.ReadDir(store)
	if len(top) != 4 {
		t.Errorf("expected only runs/ added beside Python's entries, got %v", top)
	}
	after := tree(t, store)
	for p, sum := range python {
		if after[p] != sum {
			t.Errorf("%s changed", p)
		}
	}
}

// tree is every file under dir with the sha256 of its bytes, symlinks unfollowed.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := os.ReadFile(p)
			if d.Type()&fs.ModeSymlink != 0 {
				target, _ := os.Readlink(p)
				data = []byte("-> " + target)
			}
			sum := sha256.Sum256(data)
			out[p] = hex.EncodeToString(sum[:])
		}
		return err
	})
	return out
}
