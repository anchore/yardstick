//go:build integration

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// contributable-with-docker-and-git's first step: in a corpus checkout, collect sboms builds an
// image's SBOM with the syft catalog.yaml pins and writes it into the image's directory
func TestCollectIntoACorpus(t *testing.T) {
	corpus := t.TempDir()
	// the config inside the corpus is the one syft is handed
	writeFile(t, filepath.Join(corpus, claimsv1.CatalogFile), "syft: syft@v1.54.1\nconfig: syft.yaml\nplatform: linux/amd64\n")
	writeFile(t, filepath.Join(corpus, "syft.yaml"), "scope: all-layers\n")
	writeFile(t, filepath.Join(corpus, claimsv1.VocabularyFile), "justifications: {fp: {fix-installed: Installed version has the fix}}\nfact-sources: [nvd]\nadvisory-ids: [ALSA]\nvulnerability-namespaces: [CVE]\n")
	const alpine = "oci:docker.io/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
	stdout, stderr, code := yardstick(t, corpus, "collect", "sboms", alpine)
	if code != 0 {
		t.Fatalf("collect sboms failed %d: %s %s", code, stdout, stderr)
	}
	r, _ := ref.Parse(alpine)
	data, err := os.ReadFile(filepath.Join(corpus, claimsv1.ImageDir(r), claimsv1.ImageSBOMFile))
	if err != nil || !strings.Contains(string(data), `"version":"1.54.1"`) || !strings.Contains(string(data), `"scope":"all-layers"`) {
		t.Errorf("expected the image's sbom.syft.json built by syft 1.54.1, got %v", err)
	}
	if _, stderr, code := yardstick(t, corpus, "claims", "validate", "."); code != 0 {
		t.Errorf("expected the corpus valid with the SBOM collect sboms wrote, got %d: %s", code, stderr)
	}
}
