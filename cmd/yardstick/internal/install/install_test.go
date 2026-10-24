package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anchore/binny"
)

// fakeTool stands in for a GitHub release: it counts resolutions of latest and installs, and
// installs a small file whose content names its version.
type fakeTool struct {
	name     string
	latest   string
	resolves *int
	installs *int
}

func (f fakeTool) Name() string { return f.name }

func (f fakeTool) ResolveVersion(_ context.Context, intent binny.VersionIntent) (string, error) {
	if intent.Want == "latest" {
		*f.resolves++
		return f.latest, nil
	}
	return intent.Want, nil
}

func (f fakeTool) UpdateVersion(ctx context.Context, intent binny.VersionIntent) (string, error) {
	return f.ResolveVersion(ctx, intent)
}

func (f fakeTool) InstallTo(_ context.Context, version, dir string) (string, error) {
	*f.installs++
	p := filepath.Join(dir, f.name)
	return p, os.WriteFile(p, []byte("#!/bin/sh\necho "+f.name+" "+version+"\n"), 0o755)
}

func fakeResolver(latest string, resolves, installs *int) *Resolver {
	r := NewResolver()
	r.newTool = func(name string) (binny.Tool, error) {
		return fakeTool{name: name, latest: latest, resolves: resolves, installs: installs}, nil
	}
	return r
}

func TestParseSpec(t *testing.T) {
	s, err := ParseSpec("grype", "grype@v0.120.1")
	if err != nil || s != (Spec{Name: "grype", Version: "v0.120.1"}) {
		t.Errorf("expected grype v0.120.1, got %+v %v", s, err)
	}
	s, err = ParseSpec("grype", "./bin/grype")
	if err != nil || !filepath.IsAbs(s.Path) {
		t.Errorf("expected a path made absolute, got %+v %v", s, err)
	}
	for _, bad := range []string{"syft@v1.0.0", "grype", "grype@"} {
		if _, err := ParseSpec("grype", bad); err == nil {
			t.Errorf("expected %q refused", bad)
		}
	}
}

// tools-and-dbs-are-cached-by-identity, the tool half
func TestInstall(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	ctx := context.Background()
	var resolves, installs int

	// two setups on grype@latest resolve to one version in one invocation
	r := fakeResolver("v0.120.1", &resolves, &installs)
	cand, err := r.Install(ctx, Spec{Name: "grype", Version: "latest"})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := r.Install(ctx, Spec{Name: "grype", Version: "latest"})
	if err != nil {
		t.Fatal(err)
	}
	if resolves != 1 || installs != 1 {
		t.Errorf("expected latest resolved and installed once, got %d resolutions and %d installs", resolves, installs)
	}
	if cand.Spec.Version != "v0.120.1" || cand != ref {
		t.Errorf("expected both to be v0.120.1, got %+v and %+v", cand, ref)
	}
	if len(cand.SHA256) != 64 || !strings.Contains(cand.Bin, filepath.Join("tools", "grype", "v0.120.1")) {
		t.Errorf("expected a digest and a binary in the version's store, got %+v", cand)
	}

	// a second invocation downloads nothing
	installs = 0
	age(t, filepath.Dir(cand.Bin))
	again, err := fakeResolver("v0.120.1", &resolves, &installs).Install(ctx, Spec{Name: "grype", Version: "v0.120.1"})
	if err != nil {
		t.Fatal(err)
	}
	if installs != 0 || again != cand {
		t.Errorf("expected the cached install, got %d installs and %+v", installs, again)
	}
	touched(t, filepath.Dir(cand.Bin))

	// two versions of one tool coexist
	older, err := r.Install(ctx, Spec{Name: "grype", Version: "v0.119.0"})
	if err != nil {
		t.Fatal(err)
	}
	if older.Bin == cand.Bin || older.SHA256 == cand.SHA256 {
		t.Errorf("expected v0.119.0 beside v0.120.1, got %+v", older)
	}
	if _, err := os.Stat(cand.Bin); err != nil {
		t.Errorf("expected v0.120.1 to still be installed: %v", err)
	}
}

func TestInstallRefusesARewrittenBinary(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	var resolves, installs int
	r := fakeResolver("v0.120.1", &resolves, &installs)
	got, err := r.Install(context.Background(), Spec{Name: "grype", Version: "v0.120.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(got.Bin, []byte("something else"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = r.Install(context.Background(), Spec{Name: "grype", Version: "v0.120.1"})
	if err == nil || !strings.Contains(err.Error(), "grype@v0.120.1") || !strings.Contains(err.Error(), "no longer matches") {
		t.Errorf("expected the rewritten binary refused naming the tool and version, got %v", err)
	}
}

func TestInstallUsesAPathInPlace(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	bin := filepath.Join(t.TempDir(), "grype")
	if err := os.WriteFile(bin, []byte("a local build"), 0o755); err != nil {
		t.Fatal(err)
	}
	var resolves, installs int
	got, err := fakeResolver("", &resolves, &installs).Install(context.Background(), Spec{Name: "grype", Path: bin})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("a local build"))
	if got.Bin != bin || got.SHA256 != hex.EncodeToString(sum[:]) || installs != 0 {
		t.Errorf("expected the binary used in place with its digest, got %+v after %d installs", got, installs)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("YARDSTICK_CACHE_DIR"), "tools")); err == nil {
		t.Error("expected nothing copied into the cache")
	}
}

// age sets a cache entry's modification time to 20 days ago, and touched says whether a later use
// moved it to now: cache-entries-record-last-use.
func age(t *testing.T, path string) {
	t.Helper()
	old := time.Now().Add(-20 * 24 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func touched(t *testing.T, path string) {
	t.Helper()
	if info, err := os.Stat(path); err != nil || time.Since(info.ModTime()) > time.Minute {
		t.Errorf("expected %s used by this run, got modification time %v, %v", path, info.ModTime(), err)
	}
}
