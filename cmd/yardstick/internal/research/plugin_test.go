package research

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginAvailability(t *testing.T) {
	installed := func(version string, enabled bool) []installedPlugin {
		return []installedPlugin{{ID: "other@x", Version: "1.0.0", Enabled: true}, {ID: "yardstick@delta-prototype", Version: version, Enabled: enabled}}
	}
	for _, tc := range []struct {
		name      string
		plugins   []installedPlugin
		version   string
		available bool
		command   string
	}{
		{"missing", installed("", true)[:1], "0.17.0", false, InstallCommand},
		{"same version", installed("0.17.0", true), "v0.17.0", true, ""},
		{"dev build takes any", installed("0.16.0", true), "[not provided]", true, ""},
		{"older", installed("0.16.0", true), "0.17.0", false, "claude plugin marketplace update delta-prototype && claude plugin update yardstick@delta-prototype"},
		{"disabled", installed("0.17.0", false), "0.17.0", false, "claude plugin enable yardstick@delta-prototype"},
		{"branch build of the release", installed("0.17.0", true), "v0.17.0-address-turnup-feedback", true, ""},
		{"snapshot of the release", installed("0.17.0", true), "v0.17.0+dirty", true, ""},
		{"branch build of another release", installed("0.16.0", true), "v0.17.0-my-branch", false, "claude plugin marketplace update delta-prototype && claude plugin update yardstick@delta-prototype"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pluginAvailability(tc.plugins, tc.version)
			if got.Available != tc.available || got.Command != tc.command || (!got.Available && got.Reason == "") ||
				(got.Available && strings.Contains(tc.version, "-") && !strings.Contains(got.Reason, "installed yardstick plugin")) {
				t.Errorf("got %+v", got)
			}
		})
	}
}

func TestCheckPluginWithoutClaude(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if got := CheckPlugin(t.Context(), "0.17.0"); got.Available || !strings.Contains(got.Reason, "not on PATH") {
		t.Errorf("expected research unavailable without claude, got %+v", got)
	}
}

func TestCheckPluginDir(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	plugin := func(name, version string) string {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".claude-plugin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".claude-plugin", "plugin.json"), []byte(`{"name":"`+name+`","version":"`+version+`"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	dir := plugin("yardstick", "0.17.0")
	if got := CheckPluginDir(dir, "v0.17.0-my-branch"); !got.Available || !strings.Contains(got.Reason, dir) {
		t.Errorf("expected a branch build to run the directory's plugin, saying so, got %+v", got)
	}
	if got := CheckPluginDir(dir, "v0.18.0"); got.Available || got.Command != "" {
		t.Errorf("expected another release refused with nothing to run, got %+v", got)
	}
	if got := CheckPluginDir(plugin("other", "0.17.0"), "v0.17.0"); got.Available {
		t.Errorf("expected a non-yardstick plugin refused, got %+v", got)
	}
	if got := CheckPluginDir(t.TempDir(), "v0.17.0"); got.Available {
		t.Errorf("expected a directory without a manifest refused, got %+v", got)
	}
}

// the default command loads the plugin from YARDSTICK_PLUGIN_DIR only when it's set, as one argument
func TestDefaultCommandPluginDir(t *testing.T) {
	_, rest, _ := strings.Cut(DefaultCommand, "${YARDSTICK_PLUGIN_DIR")
	arg := "${YARDSTICK_PLUGIN_DIR" + rest[:strings.Index(rest, "} ")+1]
	for dir, want := range map[string]string{"": "", "/a b/plugin": "--plugin-dir|/a b/plugin|"} {
		cmd := exec.Command("sh", "-c", `printf '%s|' `+arg)
		cmd.Env = []string{"YARDSTICK_PLUGIN_DIR=" + dir}
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimPrefix(string(out), "|"); got != want {
			t.Errorf("YARDSTICK_PLUGIN_DIR=%q: expected %q, got %q", dir, want, got)
		}
	}
}
