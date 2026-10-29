package research

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// InstallCommand installs the plugin the default command needs, from this repository's marketplace.
const InstallCommand = "claude plugin marketplace add anchore/yardstick && claude plugin install yardstick@yardstick"

// Availability says whether research can run here and, when it cannot, why and what to run.
type Availability struct {
	Available bool `json:"available"`
	// Reason says why research can't run, or, when it can, what to know about it (e.g. that a
	// branch build runs the installed plugin)
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"` // for a person to copy; yardstick never runs it
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
		want, have := strings.TrimPrefix(version, "v"), strings.TrimPrefix(p.Version, "v")
		switch {
		case !p.Enabled:
			return Availability{Reason: "the yardstick plugin (" + p.ID + ") is installed but disabled", Command: "claude plugin enable " + p.ID}
		case want == "" || want == "[not provided]" || have == want:
		case baseVersion(have) == baseVersion(want) && want != baseVersion(want):
			// a branch or snapshot build of the plugin's release (v0.17.0-my-branch): its plugin is
			// the branch's own and is versioned as the release, since a plugin version is plain
			// semver; refusing it left no way to try a branch's research
			return Availability{Available: true, Reason: fmt.Sprintf("this yardstick is %s, a build of %s; research runs the installed yardstick plugin %s, which may not be this build's", version, baseVersion(want), p.Version)}
		default:
			return Availability{
				Reason:  fmt.Sprintf("the yardstick plugin is version %s, but this yardstick is %s", p.Version, version),
				Command: fmt.Sprintf("claude plugin marketplace update %s && claude plugin update %s", marketplace, p.ID),
			}
		}
		return Availability{Available: true}
	}
	return Availability{Reason: "the yardstick plugin is not installed in Claude Code", Command: InstallCommand}
}

// baseVersion is a version without its pre-release or build suffix: 0.17.0 for 0.17.0-my-branch.
func baseVersion(v string) string {
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		return v[:i]
	}
	return v
}
