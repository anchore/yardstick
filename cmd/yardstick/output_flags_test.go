package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
)

// every value --details and -o take is named in the help of the root command and of score
func TestOutputFlagsHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"score", "--help"}} {
		help, _, _ := yardstick(t, t.TempDir(), args...)
		for _, v := range append(append([]string{}, report.Formats...), report.DetailsLevels...) {
			if !strings.Contains(help, v) {
				t.Errorf("%v: expected the help to name %q:\n%s", args, v, help)
			}
		}
	}
}

// -o is repeatable: one format on stdout and the rest in files, and a bad request is refused
// before anything is scanned
func TestMultipleOutputs(t *testing.T) {
	w := newWorkspace(t)
	whole := w.grype("whole")
	w.gate("deb", whole, whole, "", "  - name: noNewFalseNegatives\n")

	path := filepath.Join(w.dir, "out", "report.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// both setups report the same matches, so the gate passes
	stdout, stderr, code := yardstick(t, w.dir, "gates/deb.yaml", "-o", "check", "-o", "json="+path)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d: %s %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "gate deb") || strings.HasPrefix(strings.TrimSpace(stdout), "{") {
		t.Errorf("expected the check report on stdout, got %s", stdout)
	}
	if got, err := os.ReadFile(path); err != nil || !strings.HasPrefix(string(got), "{") {
		t.Errorf("expected the json report in %s, got %v: %s", path, err, got)
	}

	for _, args := range [][]string{{"-o", "yaml"}, {"-o", "check", "-o", "json"}} {
		_ = os.RemoveAll(filepath.Join(w.dir, ".yardstick"))
		_, stderr, code := yardstick(t, w.dir, append([]string{"gates/deb.yaml"}, args...)...)
		if code != 2 || !strings.Contains(stderr, strings.Join(report.Formats, ", ")) {
			t.Errorf("%v: expected exit 2 naming the formats, got %d: %s", args, code, stderr)
		}
		if _, err := os.Stat(filepath.Join(w.dir, ".yardstick")); !os.IsNotExist(err) {
			t.Errorf("%v: expected no scan, got %v", args, err)
		}
	}
}
