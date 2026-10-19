// build bundles the label UI into labelserver/assets/dist/, which the yardstick binary embeds. Run
// it from the repo root (make generate does): go run ./cmd/yardstick/internal/labelserver/web/build
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/evanw/esbuild/pkg/api"

	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver/web/buildopts"
)

const webDir = "cmd/yardstick/internal/labelserver/web"

// allowed are the licenses a bundled npm package may carry, as its package.json spells them
var allowed = []string{"MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD"}

func main() {
	if err := build(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build() error {
	web, err := filepath.Abs(webDir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(web, "package.json")); err != nil {
		return fmt.Errorf("run from the repo root: %w", err)
	}
	opts := buildopts.Options(web)
	opts.Write = false // written below, once the licenses check out
	res := api.Build(opts)
	if len(res.Errors) > 0 {
		return fmt.Errorf("esbuild: %d errors", len(res.Errors))
	}
	if err := checkLicenses(res.Metafile, web); err != nil {
		return err
	}

	if err := os.RemoveAll(opts.Outdir); err != nil {
		return err
	}
	var legal bytes.Buffer
	for _, f := range res.OutputFiles {
		if strings.HasSuffix(f.Path, ".LEGAL.txt") {
			legal.Write(f.Contents)
			continue
		}
		if err := write(f.Path, f.Contents); err != nil {
			return err
		}
	}
	if legal.Len() > 0 {
		return write(filepath.Join(opts.Outdir, "LICENSES.txt"), legal.Bytes())
	}
	return nil
}

func write(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644) //nolint:gosec // built assets, read by anyone
}

// checkLicenses fails on any npm package in the bundle whose license is not allowed. metafile is
// esbuild's, whose inputs are relative to web, the directory holding node_modules.
func checkLicenses(metafile, web string) error {
	var meta struct {
		Inputs map[string]json.RawMessage `json:"inputs"`
	}
	if err := json.Unmarshal([]byte(metafile), &meta); err != nil {
		return fmt.Errorf("esbuild metafile: %w", err)
	}
	pkgs := map[string]bool{}
	for in := range meta.Inputs {
		if pkg := packageDir(in); pkg != "" {
			pkgs[pkg] = true
		}
	}
	var errs []error
	for _, pkg := range slices.Sorted(maps.Keys(pkgs)) {
		b, err := os.ReadFile(filepath.Join(web, pkg, "package.json"))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var pj struct {
			License any `json:"license"`
		}
		if err := json.Unmarshal(b, &pj); err != nil {
			errs = append(errs, fmt.Errorf("%s/package.json: %w", pkg, err))
			continue
		}
		if l, _ := pj.License.(string); !slices.Contains(allowed, l) {
			errs = append(errs, fmt.Errorf("%s ships in the label UI under license %v, which is not one of %s", pkg, pj.License, strings.Join(allowed, ", ")))
		}
	}
	return errors.Join(errs...)
}

// packageDir is the node_modules/<pkg> (or node_modules/@scope/pkg) directory an input path is in,
// the innermost when packages nest, or "" for an input outside node_modules.
func packageDir(in string) string {
	in = filepath.ToSlash(in)
	i := strings.LastIndex(in, "node_modules/")
	if i < 0 {
		return ""
	}
	rest := strings.Split(in[i+len("node_modules/"):], "/")
	n := 1
	if strings.HasPrefix(rest[0], "@") {
		n = 2
	}
	if len(rest) <= n {
		return ""
	}
	return in[:i] + "node_modules/" + strings.Join(rest[:n], "/")
}
