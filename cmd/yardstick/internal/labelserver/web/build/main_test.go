package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckLicenses(t *testing.T) {
	web := t.TempDir()
	for pkg, license := range map[string]string{
		"ok":                     `"MIT"`,
		"@scope/ok":              `"ISC"`,
		"ok/node_modules/nested": `"BSD-3-Clause"`,
		"copyleft":               `"GPL-3.0-only"`,
		"legacy":                 `{"type": "MIT"}`,
	} {
		dir := filepath.Join(web, "node_modules", filepath.FromSlash(pkg))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"license": `+license+`}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	meta := func(inputs ...string) string {
		return `{"inputs": {"src/app/main.ts": {}, "` + strings.Join(inputs, `": {}, "`) + `": {}}}`
	}

	if err := checkLicenses(meta("node_modules/ok/index.js", "node_modules/@scope/ok/lib/a.js", "node_modules/ok/node_modules/nested/x.js"), web); err != nil {
		t.Errorf("allowed licenses: %v", err)
	}
	err := checkLicenses(meta("node_modules/ok/index.js", "node_modules/copyleft/index.js", "node_modules/legacy/index.js", "node_modules/missing/index.js"), web)
	for _, want := range []string{"node_modules/copyleft ships", "GPL-3.0-only", "node_modules/legacy ships", "missing/package.json"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want an error naming %q, got %v", want, err)
		}
	}
	if err != nil && strings.Contains(err.Error(), "node_modules/ok ") {
		t.Errorf("an allowed package was refused: %v", err)
	}
}
