//go:build integration

package collect

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

// collect-builds-an-sbom-from-a-catalog with the real syft the catalog pins, from the registry
func TestCollectWithSyft(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	// alpine 3.20's index, so the catalog's platform picks the manifest cataloged
	image, err := ref.Parse("oci:docker.io/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc")
	if err != nil {
		t.Fatal(err)
	}
	cat := &subject.Catalog{Catalog: gatefile.Catalog{Syft: "syft@v1.54.1", Platform: "linux/amd64"}}
	out, err := (&SBOMs{Tools: install.NewResolver(), Run: execute.Runner{}}).Build(context.Background(), image, cat.Platform, cat)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Artifacts  []struct{ Type string } `json:"artifacts"`
		Descriptor struct{ Name, Version string }
		Source     struct {
			Metadata struct {
				UserInput    string `json:"userInput"`
				Architecture string `json:"architecture"`
			} `json:"metadata"`
		} `json:"source"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Descriptor.Name != "syft" || doc.Descriptor.Version != "1.54.1" || doc.Source.Metadata.Architecture != "amd64" || len(doc.Artifacts) == 0 || doc.Artifacts[0].Type != "apk" {
		t.Errorf("expected syft 1.54.1's catalog of alpine's amd64 manifest, got %+v", doc)
	}
}
