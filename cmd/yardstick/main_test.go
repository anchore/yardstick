package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/testkit"
)

// bin is the yardstick binary the end to end tests run, built once.
var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "yardstick-e2e-")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "yardstick")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// yardstick runs the binary in dir, returning stdout, stderr and the exit code.
func yardstick(t *testing.T, dir string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	// a test that set its own cache directory keeps it
	if os.Getenv("YARDSTICK_CACHE_DIR") == "" {
		cmd.Env = append(cmd.Env, "YARDSTICK_CACHE_DIR="+filepath.Join(t.TempDir(), "cache"))
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return stdout.String(), stderr.String(), 0
	case errors.As(err, &exit):
		return stdout.String(), stderr.String(), exit.ExitCode()
	}
	t.Fatal(err)
	return "", "", -1
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	testkit.WriteFile(t, path, content)
}

func TestNoArgumentsPrintsHelpAndFails(t *testing.T) {
	stdout, _, code := yardstick(t, t.TempDir())
	if code == 0 || !strings.Contains(stdout, "Usage:") {
		t.Errorf("expected help and a non-zero exit, got %d:\n%s", code, stdout)
	}
}

func TestMistypedSubcommand(t *testing.T) {
	_, stderr, code := yardstick(t, t.TempDir(), "socre", "gates/vulhub.yaml")
	if code != 2 || !strings.Contains(stderr, `"socre" is not a gate file or a command`) {
		t.Errorf("expected exit 2 naming socre, got %d: %s", code, stderr)
	}
}

const digest = "sha256:f0f8e8ee94f8b5d9364f21ceffd50b7db7e19b1938271295eff8229b3cf56db2"

// a gate that would scan six images from a published source if it were run
const validGate = `schema: v1
claims: [github.com/anchore/delta-prototype@main]
candidate: {grype: grype@v0.120.1, db: latest}
reference: {grype: grype@latest, db: latest}
subjects:
  - oci:docker.io/anchore/test_images:a@` + digest + `
  - oci:docker.io/anchore/test_images:b@` + digest + `
  - oci:docker.io/anchore/test_images:c@` + digest + `
  - oci:docker.io/anchore/test_images:d@` + digest + `
  - oci:docker.io/anchore/test_images:e@` + digest + `
  - oci:docker.io/anchore/test_images:f@` + digest + `
checks:
  - name: noNewFalseNegatives
  - name: unjudgedChangesAtMost
    params: {max: 0}
`

func TestConfigValidate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "gates/deb.yaml"), validGate)
	writeFile(t, filepath.Join(dir, "gates/vulhub.yaml"), strings.Replace(validGate, "reference: {grype: grype@latest, db: latest}\n", "", 1)+"")

	// no tool on PATH and no network: config validate must need neither
	t.Setenv("PATH", "")
	writeFile(t, filepath.Join(dir, "gates/presence.yaml"), `schema: v1
claims: [github.com/anchore/delta-prototype@main]
candidate: {grype: grype@latest, db: latest}
subjects: [oci:docker.io/vulhub/struts2:2.3.12@`+digest+`]
checks: [{name: expectationsMetAtLeast, params: {min: 1}}]
`)
	stdout, stderr, code := yardstick(t, dir, "config", "validate", "gates/deb.yaml", "gates/presence.yaml")
	if code != 0 || stderr != "" || !strings.HasSuffix(stdout, "✔ all 2 gate files valid\n") {
		t.Errorf("expected valid files to exit 0 ending on one verdict line, got %d:\n%s%s", code, stdout, stderr)
	}

	// every file is checked: the unknown check in one and the reference-reading checks of the
	// other are both reported
	writeFile(t, filepath.Join(dir, "gates/deb.yaml"), strings.Replace(validGate, "noNewFalseNegatives", "noRegressions", 1))
	stdout, stderr, code = yardstick(t, dir, "config", "validate", "gates/deb.yaml", "gates/vulhub.yaml")
	if code != 2 || !strings.Contains(stdout, "✘ gates/deb.yaml     unknown check \"noRegressions\"") ||
		!strings.Contains(stdout, "✘ gates/vulhub.yaml  check noNewFalseNegatives reads the reference setup") ||
		!strings.Contains(stderr, "2 of 2 gate files are invalid") {
		t.Errorf("expected exit 2 naming both files' errors, got %d:\n%s%s", code, stdout, stderr)
	}

	// config alone is its help
	stdout, _, code = yardstick(t, dir, "config")
	if code != 0 || !strings.Contains(stdout, "validate") {
		t.Errorf("expected config to print its help, got %d:\n%s", code, stdout)
	}
}

// 0.16's validate ran the gate; there is no alias, so it reaches the root as a positional
func TestOldValidateSpelling(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "gates/deb.yaml"), strings.Replace(validGate, "noNewFalseNegatives", "noRegressions", 1))
	for _, args := range [][]string{{"validate"}, {"validate", "gates/deb.yaml"}} {
		_, stderr, code := yardstick(t, dir, args...)
		// a loaded gate would report its unknown check
		if code != 2 || !strings.Contains(stderr, `"validate" is not a gate file or a command`) || strings.Contains(stderr, "noRegressions") {
			t.Errorf("%v: expected exit 2 naming validate and no gate loaded, got %d: %s", args, code, stderr)
		}
	}
}
