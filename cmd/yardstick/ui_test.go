package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// with stderr redirected nothing is drawn: no escape sequences, and the report alone on stdout
func TestNoUIWithoutATerminal(t *testing.T) {
	dir := t.TempDir()
	scanGate(t, dir)
	stdout, stderr, _ := yardstick(t, dir, "gates/deb.yaml", "-o", "check")
	if strings.Contains(stderr, "\x1b[") || strings.Contains(stdout, "\x1b[") {
		t.Errorf("expected nothing drawn, got stderr %q", stderr)
	}
	if !strings.HasPrefix(stdout, "deb  ") {
		t.Errorf("expected the report on stdout, got %q", stdout)
	}
}

// an interactive run draws its scans on stderr and settles before the report, which is stdout's
// alone. script(1) gives the run a terminal.
func TestUIOnATerminal(t *testing.T) {
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("no script(1) to give the run a terminal")
	}
	dir := t.TempDir()
	scanGate(t, dir)
	report := filepath.Join(dir, "report.txt")
	run := "stty cols 80 rows 30; " + bin + " gates/deb.yaml -o check > " + report
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("script", "-q", "/dev/null", "sh", "-c", run)
	} else {
		cmd = exec.Command("script", "-qec", run, "/dev/null")
	}
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "YARDSTICK_CACHE_DIR="+filepath.Join(t.TempDir(), "cache"), "NO_TTY=")
	drawn, _ := cmd.CombinedOutput()

	if !strings.Contains(string(drawn), "scanned 2 in") {
		t.Errorf("expected the run drawn on the terminal and settled to its summary, got %q", drawn)
	}
	out, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "deb  ") || strings.Contains(string(out), "\x1b[") {
		t.Errorf("expected only the report on stdout, got %q", out)
	}
}
