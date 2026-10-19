// Package execute runs grype and syft with an environment yardstick builds: the caller's GRYPE_*
// and SYFT_* variables removed, the pins that hold a DB still, then the setup's declared env. The
// gate file is the whole setup, so a stray variable in a shell can't change a result.
package execute

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// pins are set for every run: never update or age out a DB, never check for a newer release, and
// keep ANSI escapes out of the stderr that goes into errors.
var pins = []string{
	"GRYPE_CHECK_FOR_APP_UPDATE=false",
	"GRYPE_DB_AUTO_UPDATE=false",
	"GRYPE_DB_VALIDATE_AGE=false",
	"SYFT_CHECK_FOR_APP_UPDATE=false",
	"NO_COLOR=1",
}

// Cmd is one tool run.
type Cmd struct {
	Bin  string
	Args []string
	// DBDir is the grype DB the run is pinned to (GRYPE_DB_CACHE_DIR); empty for syft.
	DBDir string
	// Env is the setup's or catalog's declared env, applied last.
	Env map[string]string
}

// EmptyConfig is the config file a tool is given when its setup or catalog declares none. An
// explicit -c makes grype and syft read only that file, so a config in the user's home or XDG
// config directory never applies. It sits in the tools' working directory, which is not a cache
// entry.
func EmptyConfig() (string, error) {
	path := cache.Dir("workdir", "empty-config.yaml")
	if err := cache.WriteFile(path, nil); err != nil {
		return "", fmt.Errorf("unable to create an empty tool config: %w", err)
	}
	return path, nil
}

// Runner runs tools. The zero value scrubs the caller's tool variables.
type Runner struct {
	// InheritEnv keeps the caller's GRYPE_* and SYFT_* variables (--inherit-env), under the pins.
	InheritEnv bool
}

// Run execs the tool from an empty directory yardstick owns, so a .grype.yaml or .syft.yaml
// wherever yardstick runs from is never read, and returns stdout and stderr apart: grype's JSON
// is stdout alone. A failure carries the last 30 lines of stderr.
func (r Runner) Run(ctx context.Context, c Cmd) (stdout, stderr []byte, err error) {
	dir := cache.Dir("workdir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("unable to create a working directory for tools: %w", err)
	}
	log.Debugf("exec: %s %s", c.Bin, strings.Join(c.Args, " "))
	if len(c.Env) > 0 || c.DBDir != "" {
		log.Debugf("exec env: declared keys %v, db dir %q, inherit caller env %v", sortedKeys(c.Env), c.DBDir, r.InheritEnv)
	}
	defer log.Timed("exec %s %s", filepath.Base(c.Bin), firstArg(c.Args))()
	cmd := exec.CommandContext(ctx, c.Bin, c.Args...) //nolint:gosec // G204: grype and syft, as the gate file names them, by design
	cmd.Env = r.environ(os.Environ(), c)
	cmd.Dir = dir
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	logResult(cmd, errOut.Bytes())
	if err != nil {
		return nil, errOut.Bytes(), fmt.Errorf("%s %s: %w\n%s", c.Bin, strings.Join(c.Args, " "), err, lastLines(withoutDebug(errOut.String()), stderrLines))
	}
	return out.Bytes(), errOut.Bytes(), nil
}

// environ is the child's environment: the caller's minus tool variables (unless inherited),
// then the pins, the DB, and the declared env. exec keeps the last value of a repeated key.
func (r Runner) environ(caller []string, c Cmd) []string {
	var env []string
	for _, kv := range caller {
		if r.InheritEnv || !isToolVar(kv) {
			env = append(env, kv)
		}
	}
	env = append(env, pins...)
	if c.DBDir != "" {
		env = append(env, "GRYPE_DB_CACHE_DIR="+c.DBDir)
	}
	for _, k := range sortedKeys(c.Env) {
		env = append(env, k+"="+c.Env[k])
	}
	return env
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// traceStderrBytes caps the stderr logged at trace, keeping the tail where failures show up.
const traceStderrBytes = 4096

// logResult traces the child's exit code and its stderr, when there is any.
func logResult(cmd *exec.Cmd, stderr []byte) {
	log.Tracef("exec exit code: %d", cmd.ProcessState.ExitCode())
	s := strings.TrimSpace(string(stderr))
	if s == "" {
		return
	}
	if len(s) > traceStderrBytes {
		s = "... (truncated)\n" + s[len(s)-traceStderrBytes:]
	}
	log.Tracef("exec stderr:\n%s", s)
}

func isToolVar(kv string) bool {
	return strings.HasPrefix(kv, "GRYPE_") || strings.HasPrefix(kv, "SYFT_")
}

// Inherited is the caller's GRYPE_* and SYFT_* variables, which --inherit-env passes on: the run
// records them and warns naming each.
func Inherited() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		if isToolVar(kv) {
			k, v, _ := strings.Cut(kv, "=")
			out[k] = v
		}
	}
	return out
}

// SecretEnv is the GRYPE_* variables left out of a scan's key under --inherit-env, because they
// carry credentials and a credential cannot change what grype reports for an SBOM it is handed.
// It was derived from grype v0.120.1's own option definitions: the three `secret`-typed fields of
// the registry auth options in cmd/grype/cli/options/registry.go, the other environment
// variables that file reads for registry auth (the only os.Getenv calls in grype's CLI), and the
// one option that takes a URL grype may fetch with. Revisit it when yardstick moves to a grype
// that adds credential options.
var SecretEnv = []string{
	"GRYPE_REGISTRY_AUTH_USERNAME",  // a `secret` field
	"GRYPE_REGISTRY_AUTH_PASSWORD",  // a `secret` field
	"GRYPE_REGISTRY_AUTH_TOKEN",     // a `secret` field
	"GRYPE_REGISTRY_AUTH_AUTHORITY", // names the private registry the credentials above belong to
	"GRYPE_REGISTRY_AUTH_TLS_CERT",  // path to a registry client certificate
	"GRYPE_REGISTRY_AUTH_TLS_KEY",   // path to the registry client key
	"GRYPE_DB_UPDATE_URL",           // a URL that can carry userinfo, and is never fetched while the DB is pinned
}

// InheritedDigest is a sha256 over the caller's inherited GRYPE_* names and values, sorted by
// name, without those in SecretEnv. It is empty when the runner scrubs the environment or nothing
// remains. SYFT_* variables are left out: they cannot change what grype reports. The values are
// hashed and never logged or stored.
func (r Runner) InheritedDigest() string {
	if !r.InheritEnv {
		return ""
	}
	vars := Inherited()
	var names []string
	for k := range vars {
		if strings.HasPrefix(k, "GRYPE_") && !slices.Contains(SecretEnv, k) {
			names = append(names, k)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	h := sha256.New()
	for _, k := range names {
		h.Write([]byte(k + "\x00" + vars[k] + "\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// stderrLines is how much of a failed tool's stderr goes into the error: enough for syft's
// per-provider list of why it couldn't resolve an image, without pages of warnings before it.
const stderrLines = 30

// lastLines is the last n lines of s.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = append([]string{fmt.Sprintf("... (%d earlier lines of stderr omitted)", len(lines)-n)}, lines[len(lines)-n:]...)
	}
	return strings.Join(lines, "\n")
}

// debugLine is the start of an anchore tool's debug or trace log line, e.g. "[0000] DEBUG ...".
var debugLine = regexp.MustCompile(`^\[\d+\]\s+(DEBUG|TRACE)\b`)

// withoutDebug drops debug and trace lines from a tool's stderr, with their continuation lines
// (e.g. the config dump), so an error made from it shows the errors, not a verbose log's tail.
func withoutDebug(stderr string) string {
	var keep []string
	skipping := false
	for _, line := range strings.Split(stderr, "\n") {
		switch {
		case debugLine.MatchString(line):
			skipping = true
		case strings.HasPrefix(line, "["):
			skipping = false
		}
		if !skipping {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}
