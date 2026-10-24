package research

import (
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pluginAvailability(tc.plugins, tc.version)
			if got.Available != tc.available || got.Command != tc.command || (!got.Available && got.Reason == "") {
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
