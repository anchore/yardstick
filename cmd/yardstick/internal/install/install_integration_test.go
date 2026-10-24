//go:build integration

package install

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// a real release, from GitHub, through binny
func TestInstallFromGitHub(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	r := NewResolver()
	got, err := r.Install(context.Background(), Spec{Name: "grype", Version: "v0.120.1"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(got.Bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "0.120.1") {
		t.Errorf("expected grype 0.120.1, got:\n%s", out)
	}
	latest, err := r.Resolve(context.Background(), Spec{Name: "grype", Version: "latest"})
	if err != nil || latest.Version == "latest" || latest.Version == "" {
		t.Errorf("expected latest resolved to a version, got %+v %v", latest, err)
	}
}
