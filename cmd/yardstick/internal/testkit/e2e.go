package testkit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/score"
)

// E2EGates are the gates of the label UI's end to end workspace, in the order they are scanned.
var E2EGates = []string{"deb-java", "deb-npm"}

// E2EPath is a path under testdata/e2e/: the gate files, the claims they read (labels and the
// vocabulary; the SBOMs come from the fixture package), the lists of what each stub grype drops,
// and the agent material recorded at seed time.
func E2EPath(elem ...string) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to locate the testkit package")
	}
	return filepath.Join(append([]string{filepath.Dir(file), "testdata", "e2e"}, elem...)...)
}

// E2E builds the end to end workspace under dir and scans its gates with the yardstick binary bin.
// The working directory must already be dir, since yardstick keeps its runs and the agent records
// under it. Exit 1 from a scan is a failed gate, which is what the gates start as.
func E2E(t TB, dir, tools, bin string) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.CopyFS(filepath.Join(dir, "gates"), os.DirFS(E2EPath("gates"))))
	must(os.CopyFS(filepath.Join(dir, "claims"), os.DirFS(E2EPath("claims"))))
	for _, image := range []string{"deb", "java", "npm"} {
		r := e2eImage(image)
		sbom, err := os.ReadFile(fixture.SBOM(image, "syft"))
		must(err)
		WriteFile(t, filepath.Join(dir, "claims", claimsv1.ImageDir(r), claimsv1.ImageSBOMFile), string(sbom))
	}
	must(writeStubs(t, filepath.Join(dir, "tools")))

	env := append(os.Environ(), "YARDSTICK_CACHE_DIR="+filepath.Join(tools, "cache"))
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir, cmd.Env = dir, env
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
			t.Fatal(fmt.Sprintf("yardstick %s: %v\n%s", strings.Join(args, " "), err, out))
		}
	}
	for _, g := range E2EGates {
		run("gates/"+g+".yaml", "-q")
	}
	for _, g := range E2EGates {
		must(recordAgent(g, dir, env, bin))
	}
}

// e2eImage is a fixture image as the gates refer to it: by its manifest digest, as syft recorded it.
func e2eImage(name string) ref.Ref {
	var sbom struct {
		Source struct {
			Metadata struct {
				ManifestDigest string `json:"manifestDigest"`
			} `json:"metadata"`
		} `json:"source"`
	}
	data, err := os.ReadFile(fixture.SBOM(name, "syft"))
	if err == nil {
		err = json.Unmarshal(data, &sbom)
	}
	if err != nil {
		panic(err)
	}
	r, err := ref.Parse("oci:docker.io/anchore/yardstick-fixture-" + name + "@" + sbom.Source.Metadata.ManifestDigest)
	if err != nil {
		panic(err)
	}
	return r
}

// writeStubs writes a stub grype for each setup in setups.yaml: it prints the fixture output of
// the image its SBOM is of, without the matches the setup drops.
func writeStubs(t TB, tools string) error {
	data, err := os.ReadFile(E2EPath("setups.yaml"))
	if err != nil {
		return err
	}
	var setups map[string]map[string][]string
	if err := yaml.Unmarshal(data, &setups); err != nil {
		return err
	}
	for name, drops := range setups {
		for _, image := range fixture.Images {
			out, err := dropped(image, drops[image])
			if err != nil {
				return err
			}
			WriteFile(t, filepath.Join(tools, "out", name+"-"+image+".json"), string(out))
		}
		// grype is called with: -c <config> sbom:<path> -o json
		StubTool(t, tools, name, `#!/bin/sh
case "$3" in sbom:*) ;; *) exit 1 ;; esac
image=$(grep -o 'yardstick-fixture-[a-z]*' "${3#sbom:}" | head -1)
cat "$(dirname "$0")/out/`+name+`-${image#yardstick-fixture-}.json"
`)
	}
	return nil
}

// dropped is the fixture grype output for an image without the "<vulnerability> <package>" matches.
func dropped(image string, drop []string) ([]byte, error) {
	data, err := os.ReadFile(fixture.Grype("v0.120.1", image))
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var kept []any
	for _, m := range doc["matches"].([]any) {
		mm := m.(map[string]any)
		key := mm["vulnerability"].(map[string]any)["id"].(string) + " " + mm["artifact"].(map[string]any)["name"].(string)
		if !slices.Contains(drop, key) {
			kept = append(kept, m)
		}
	}
	doc["matches"] = kept
	return json.Marshal(doc)
}

// recordAgent records a gate's checked-in agent material through the yardstick CLI, as the skills
// do. The files name rows as "<subject> <vulnerability> <package name> [<location>]", since row ids
// are derived from the scan; they are resolved here.
func recordAgent(gate, dir string, env []string, bin string) error {
	rec, err := runrecord.Load(runrecord.DefaultName, gate)
	if err != nil {
		return err
	}
	rows, err := score.Rows(runrecord.DefaultName, rec, nil)
	if err != nil {
		return err
	}
	ids := map[string]string{}
	for id, r := range rows {
		short := r.Subject.Name + " " + r.Match.Vulnerability + " " + r.Match.Package.Name
		// one package in two places (java's two jars) is told apart by its location
		ids[short+" "+r.Match.Location] = id
		if _, taken := ids[short]; taken {
			id = ""
		}
		ids[short] = id
	}
	for _, kind := range []string{"proposals", "causes", "explanations"} {
		in, err := os.ReadFile(E2EPath("agent", gate, kind+".jsonl"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		var out bytes.Buffer
		for _, line := range bytes.Split(bytes.TrimSpace(in), []byte("\n")) {
			var v any
			if err := json.Unmarshal(line, &v); err != nil {
				return fmt.Errorf("%s/%s: %w", gate, kind, err)
			}
			if err := resolveRows(v, ids); err != nil {
				return fmt.Errorf("%s/%s: %w", gate, kind, err)
			}
			b, _ := json.Marshal(v)
			out.Write(append(b, '\n'))
		}
		args := append([]string{"claims", "agent"}, map[string][]string{
			"proposals":    {"propose"},
			"causes":       {"propose-cause"},
			"explanations": {"explain", "propose"},
		}[kind]...)
		cmd := exec.Command(bin, append(args, "--gate", gate)...) //nolint:gosec // the yardstick under test
		cmd.Dir, cmd.Env, cmd.Stdin = dir, env, &out
		if b, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("yardstick %s: %w\n%s", strings.Join(args, " "), err, b)
		}
	}
	return nil
}

// resolveRows replaces row selectors, in any "row" or "rows" field, with row ids.
func resolveRows(v any, ids map[string]string) error {
	pick := func(sel any) (string, error) {
		id := ids[fmt.Sprint(sel)]
		if id == "" {
			return "", fmt.Errorf("no row, or more than one, for %q in the scan: add the package's location", sel)
		}
		return id, nil
	}
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			switch k {
			case "row":
				id, err := pick(x)
				if err != nil {
					return err
				}
				v[k] = id
			case "rows":
				if err := pickEach(x.([]any), pick); err != nil {
					return err
				}
			default:
				if err := resolveRows(x, ids); err != nil {
					return err
				}
			}
		}
	case []any:
		for _, x := range v {
			if err := resolveRows(x, ids); err != nil {
				return err
			}
		}
	}
	return nil
}

// pickEach replaces each selector in list with its row id.
func pickEach(list []any, pick func(any) (string, error)) error {
	for i := range list {
		id, err := pick(list[i])
		if err != nil {
			return err
		}
		list[i] = id
	}
	return nil
}
