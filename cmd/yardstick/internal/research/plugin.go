package research

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// InstallCommand installs the plugin the default command needs.
const InstallCommand = "claude plugin install yardstick --marketplace anchore/yardstick"

// Availability says whether research can run here and, when it cannot, why and what to run.
type Availability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Command   string `json:"command,omitempty"` // for a person to copy; yardstick never runs it
}

type installedPlugin struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Enabled bool   `json:"enabled"`
}

// CheckPlugin looks for the yardstick plugin in `claude plugin list --json` and compares its
// version to this binary's. A binary built without a version accepts any installed one.
func CheckPlugin(ctx context.Context, version string) Availability {
	bin, err := exec.LookPath("claude")
	if err != nil {
		return Availability{Reason: "claude is not on PATH; research runs the yardstick plugin's research-vuln skill in Claude Code"}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "plugin", "list", "--json").Output()
	if err != nil {
		return Availability{Reason: fmt.Sprintf("unable to list Claude Code plugins: %v", err)}
	}
	var plugins []installedPlugin
	if err := json.Unmarshal(out, &plugins); err != nil {
		return Availability{Reason: fmt.Sprintf("unable to read claude plugin list --json: %v", err)}
	}
	return pluginAvailability(plugins, version)
}

func pluginAvailability(plugins []installedPlugin, version string) Availability {
	for _, p := range plugins {
		name, marketplace, _ := strings.Cut(p.ID, "@")
		if name != "yardstick" {
			continue
		}
		want := strings.TrimPrefix(version, "v")
		switch {
		case !p.Enabled:
			return Availability{Reason: "the yardstick plugin (" + p.ID + ") is installed but disabled", Command: "claude plugin enable " + p.ID}
		case want != "" && want != "[not provided]" && strings.TrimPrefix(p.Version, "v") != want:
			return Availability{
				Reason:  fmt.Sprintf("the yardstick plugin is version %s, but this yardstick is %s", p.Version, version),
				Command: fmt.Sprintf("claude plugin marketplace update %s && claude plugin update %s", marketplace, p.ID),
			}
		}
		return Availability{Available: true}
	}
	return Availability{Reason: "the yardstick plugin is not installed in Claude Code", Command: InstallCommand}
}
