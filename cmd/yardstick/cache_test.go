package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// stubImportingGrype imports a DB the way grype does, deleting the DB it is about to replace and
// then taking a while, and scans only when the DB it is pinned to is whole.
const stubImportingGrype = `#!/bin/sh
if [ "$1" = "-c" ]; then shift 2; fi
if [ "$1 $2" = "db import" ]; then
  touch "{{SIGNAL}}"
  rm -rf "$GRYPE_DB_CACHE_DIR/6"
  sleep 0.5
  mkdir -p "$GRYPE_DB_CACHE_DIR/6" && echo db > "$GRYPE_DB_CACHE_DIR/6/vulnerability.db"
  sleep 0.5
  exit 0
fi
if [ ! -s "$GRYPE_DB_CACHE_DIR/6/vulnerability.db" ]; then echo "failed to load vulnerability db: no DB at $GRYPE_DB_CACHE_DIR" >&2; exit 1; fi
cat "{{OUT}}"
`

// a gate over the deb image whose setups import a DB archive, in its own project directory; the
// stubs touch signal when an import starts
func importingGate(t *testing.T, dir, archive, signal string) {
	t.Helper()
	tools := t.TempDir()
	stub := strings.Replace(stubImportingGrype, "{{SIGNAL}}", signal, 1)
	candidate := stubTool(t, tools, "candidate-grype", strings.Replace(stub, "{{OUT}}", fixture.Grype("v0.120.1", "deb"), 1))
	reference := stubTool(t, tools, "reference-grype", strings.Replace(stub, "{{OUT}}", fixture.Grype("v0.119.0", "deb"), 1))
	r, _ := ref.Parse(debImage)
	sbom, _ := os.ReadFile(fixture.SBOM("deb", "syft"))
	writeFile(t, filepath.Join(dir, "claims", corpus.ImageDir(r), corpus.ImageSBOMFile), string(sbom))
	writeFile(t, filepath.Join(dir, "claims", claimsv1.VocabularyFile), "justifications: {fp: {fix-installed: x}}\nfact-sources: [sbom]\nadvisory-ids: [ELSA]\nvulnerability-namespaces: [CVE, GHSA]\n")
	writeFile(t, filepath.Join(dir, "gates/deb.yaml"), `schema: v1
claims: [../claims]
candidate: {grype: `+candidate+`, db: "`+archive+`"}
reference: {grype: `+reference+`, db: "`+archive+`"}
subjects: [{ref: "`+debImage+`", name: deb}]
checks:
  - name: noNewFalseNegatives
`)
}

// cache-writes-are-atomic, two runs of one gate at once: the runs share a cache, and the second
// starts once the first is half way through importing, so it would delete the DB the first has
// just imported if both imported into one directory
func TestTwoRunsOfOneGateAtOnce(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	archive := filepath.Join(t.TempDir(), "vulnerability.db.tar.zst")
	writeFile(t, archive, "a DB archive's bytes")

	type result struct {
		stdout, stderr string
		err            error
	}
	results := make([]result, 2)
	signal := filepath.Join(t.TempDir(), "importing")
	var wg sync.WaitGroup
	for i := range results {
		dir := t.TempDir()
		importingGate(t, dir, archive, signal)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i > 0 {
				for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
					if _, err := os.Stat(signal); err == nil {
						break
					}
				}
				time.Sleep(600 * time.Millisecond)
			}
			cmd := exec.Command(bin, "gates/deb.yaml", "-o", "check")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "YARDSTICK_CACHE_DIR="+cacheDir)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			results[i] = result{err: cmd.Run()}
			results[i].stdout, results[i].stderr = stdout.String(), stderr.String()
		}()
	}
	wg.Wait()
	// both setups report the same matches, so the gate passes; what matters is that both runs
	// scanned and say the same
	verdicts := make([]string, len(results))
	for i, r := range results {
		if r.err != nil || strings.Contains(r.stderr, "vulnerability db") {
			t.Fatalf("run %d: expected a verdict, got %v\n%s\n%s", i, r.err, r.stdout, r.stderr)
		}
		_, verdicts[i], _ = strings.Cut(r.stdout, "PASS gate deb")
	}
	if verdicts[0] == "" || verdicts[0] != verdicts[1] {
		t.Errorf("expected one verdict from both runs, got:\n%s\nand:\n%s", verdicts[0], verdicts[1])
	}
	entries, err := os.ReadDir(filepath.Join(cacheDir, "grype-db"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || strings.HasPrefix(entries[0].Name(), ".") {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected one copy of the DB and no leftover import, got %v", names)
	}
}
