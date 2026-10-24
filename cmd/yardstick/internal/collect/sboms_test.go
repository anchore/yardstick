package collect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

// stubSyft stands in for syft: it logs its arguments and the one declared variable, and prints the
// fixture deb SBOM, which syft built.
const stubSyft = `#!/bin/sh
echo "$* parallelism=$SYFT_PARALLELISM" >> "$CALLS"
cat "$SBOM"
`

func TestCollect(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	dir := t.TempDir()
	syft := filepath.Join(dir, "syft")
	write(t, syft, []byte(stubSyft))
	if err := os.Chmod(syft, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls")
	t.Setenv("CALLS", calls)
	t.Setenv("SBOM", fixture.SBOM("deb", "syft"))
	image, err := ref.Parse("oci:docker.io/anchore/yardstick-fixture-deb@sha256:617d48dd2601779266746a9a382bfb9f3fee2744fba698733b320366f41718b0")
	if err != nil {
		t.Fatal(err)
	}
	cat := &subject.Catalog{Catalog: gatefile.Catalog{Syft: syft, Config: filepath.Join(dir, "syft.yaml"), Platform: "linux/arm64", Env: map[string]string{"SYFT_PARALLELISM": "2"}}}
	out, err := (&SBOMs{Tools: install.NewResolver(), Run: execute.Runner{}}).Build(context.Background(), image, cat.Platform, cat)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(fixture.SBOM("deb", "syft"))
	if string(out) != string(want) {
		t.Error("expected syft's syft-json as written")
	}
	logged, _ := os.ReadFile(calls)
	for _, part := range []string{image.Image(), "-o syft-json", "--platform linux/arm64", "-c " + cat.Config, "parallelism=2"} {
		if !strings.Contains(string(logged), part) {
			t.Errorf("expected syft run with %q, got %s", part, logged)
		}
	}
}

// grype-runs-with-its-db-pinned: a catalog with no config still gives syft an explicit, empty one
func TestCollectWithoutAConfigPassesAnEmptyOne(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	dir := t.TempDir()
	syft := filepath.Join(dir, "syft")
	write(t, syft, []byte(stubSyft))
	if err := os.Chmod(syft, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls")
	t.Setenv("CALLS", calls)
	t.Setenv("SBOM", fixture.SBOM("deb", "syft"))
	image, err := ref.Parse("oci:docker.io/anchore/yardstick-fixture-deb@sha256:617d48dd2601779266746a9a382bfb9f3fee2744fba698733b320366f41718b0")
	if err != nil {
		t.Fatal(err)
	}
	cat := &subject.Catalog{Catalog: gatefile.Catalog{Syft: syft}}
	if _, err := (&SBOMs{Tools: install.NewResolver(), Run: execute.Runner{}}).Build(context.Background(), image, "", cat); err != nil {
		t.Fatal(err)
	}
	logged, _ := os.ReadFile(calls)
	_, after, ok := strings.Cut(string(logged), "-c ")
	cfg, _, _ := strings.Cut(after, " ")
	if !ok || !strings.HasPrefix(cfg, cache.Dir()) {
		t.Fatalf("expected an explicit -c under the cache, got %s", logged)
	}
	if data, err := os.ReadFile(cfg); err != nil || len(data) != 0 {
		t.Errorf("expected %s to be an empty file, got %q, %v", cfg, data, err)
	}
}
