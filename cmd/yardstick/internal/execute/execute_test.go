package execute

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// env runs /usr/bin/env, a tool that prints the environment it was given, and parses it.
func env(t *testing.T, r Runner, c Cmd) map[string]string {
	t.Helper()
	c.Bin = "/usr/bin/env"
	out, _, err := r.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, _ := strings.Cut(line, "=")
		got[k] = v
	}
	return got
}

// declared-environment, the run side: a variable in the shell never reaches a tool, and a
// declared one does
func TestDeclaredEnvironment(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	t.Setenv("GRYPE_MATCH_JAVA_USING_CPES", "true")
	t.Setenv("SYFT_SCOPE", "all-layers")
	t.Setenv("GRYPE_DB_AUTO_UPDATE", "true")

	ref := env(t, Runner{}, Cmd{DBDir: "/db/ref"})
	if _, ok := ref["GRYPE_MATCH_JAVA_USING_CPES"]; ok {
		t.Error("expected the shell's GRYPE_MATCH_JAVA_USING_CPES scrubbed")
	}
	if _, ok := ref["SYFT_SCOPE"]; ok {
		t.Error("expected the shell's SYFT_SCOPE scrubbed")
	}
	if ref["PATH"] != os.Getenv("PATH") {
		t.Error("expected variables that configure no tool kept")
	}

	cand := env(t, Runner{}, Cmd{DBDir: "/db/cand", Env: map[string]string{"GRYPE_MATCH_JAVA_USING_CPES": "false"}})
	if cand["GRYPE_MATCH_JAVA_USING_CPES"] != "false" {
		t.Errorf("expected the declared value, got %q", cand["GRYPE_MATCH_JAVA_USING_CPES"])
	}

	// --inherit-env keeps the shell's variables, and the pins still win
	inherited := env(t, Runner{InheritEnv: true}, Cmd{DBDir: "/db/ref"})
	if inherited["GRYPE_MATCH_JAVA_USING_CPES"] != "true" || inherited["SYFT_SCOPE"] != "all-layers" {
		t.Errorf("expected the shell's variables with --inherit-env, got %v", inherited)
	}
	if inherited["GRYPE_DB_AUTO_UPDATE"] != "false" {
		t.Errorf("expected the pin over the shell's GRYPE_DB_AUTO_UPDATE, got %q", inherited["GRYPE_DB_AUTO_UPDATE"])
	}
	names := Inherited()
	if names["GRYPE_MATCH_JAVA_USING_CPES"] != "true" || names["SYFT_SCOPE"] != "all-layers" {
		t.Errorf("expected the inherited variables listed for the record and the warning, got %v", names)
	}
}

// grype-runs-with-its-db-pinned: the pins and the DB reach every run, from a directory with no
// config file in it
func TestGrypeRunsWithItsDBPinned(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("YARDSTICK_CACHE_DIR", cacheDir)
	got := env(t, Runner{}, Cmd{DBDir: "/db/pinned"})
	for k, v := range map[string]string{
		"GRYPE_DB_AUTO_UPDATE":       "false",
		"GRYPE_DB_VALIDATE_AGE":      "false",
		"GRYPE_CHECK_FOR_APP_UPDATE": "false",
		"SYFT_CHECK_FOR_APP_UPDATE":  "false",
		"GRYPE_DB_CACHE_DIR":         "/db/pinned",
	} {
		if got[k] != v {
			t.Errorf("expected %s=%s, got %q", k, v, got[k])
		}
	}

	// a stray config where yardstick runs from is never where the tool runs
	t.Chdir(t.TempDir())
	if err := os.WriteFile(".grype.yaml", []byte("by-cve: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := Runner{}.Run(context.Background(), Cmd{Bin: "/bin/ls", Args: []string{"-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), ".grype.yaml") {
		t.Error("expected the tool to run from yardstick's own empty directory")
	}
	pwd, _, err := Runner{}.Run(context.Background(), Cmd{Bin: "/bin/pwd"})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(filepath.Join(cacheDir, "workdir"))
	if got, _ := filepath.EvalSymlinks(strings.TrimSpace(string(pwd))); got != want {
		t.Errorf("expected tools to run in %s, ran in %s", want, got)
	}
}

func TestFailureCarriesTheEndOfStderr(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	script := `for i in $(seq 1 40); do echo "line $i" >&2; done; echo out; exit 3`
	stdout, _, err := Runner{}.Run(context.Background(), Cmd{Bin: "/bin/sh", Args: []string{"-c", script}})
	if err == nil {
		t.Fatal("expected the failure returned")
	}
	if stdout != nil || !strings.Contains(err.Error(), "line 40") || !strings.Contains(err.Error(), "line 11") || strings.Contains(err.Error(), "line 10\n") {
		t.Errorf("expected the last 30 lines of stderr, got %v", err)
	}
	if !strings.Contains(err.Error(), "10 earlier lines of stderr omitted") {
		t.Errorf("expected the omission counted, got %v", err)
	}
}

func TestStdoutAndStderrApart(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	stdout, stderr, err := Runner{}.Run(context.Background(), Cmd{Bin: "/bin/sh", Args: []string{"-c", `echo '{"matches":[]}'; echo "[0000]  INFO a log line" >&2`}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(stdout)) != `{"matches":[]}` || !strings.Contains(string(stderr), "a log line") {
		t.Errorf("expected the document on stdout and the log on stderr, got %q and %q", stdout, stderr)
	}
}

func TestInheritedDigestSkipsSecretsAndSyft(t *testing.T) {
	t.Setenv("GRYPE_MATCH_JAVA_USING_CPES", "false")
	inherit := Runner{InheritEnv: true}
	base := inherit.InheritedDigest()
	if base == "" || (Runner{}).InheritedDigest() != "" {
		t.Fatalf("expected a digest only when inheriting, got %q", base)
	}
	for _, k := range SecretEnv {
		t.Setenv(k, "a credential")
	}
	t.Setenv("SYFT_FILE_METADATA_SELECTION", "all")
	if got := inherit.InheritedDigest(); got != base {
		t.Errorf("expected secrets and SYFT_* left out of the digest")
	}
	t.Setenv("GRYPE_MATCH_JAVA_USING_CPES", "true")
	if got := inherit.InheritedDigest(); got == base {
		t.Errorf("expected a changed value to change the digest")
	}
}

// a failure names the command without the credentials a DB or proxy URL carries
func TestFailureRedactsURLUserinfo(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	_, _, err := Runner{}.Run(context.Background(), Cmd{Bin: "/bin/sh", Args: []string{"-c", "exit 3", "sh", "https://bob:s3cret@mirror.example/db.tar.zst"}})
	if err == nil || strings.Contains(err.Error(), "s3cret") || !strings.Contains(err.Error(), "https://*******@mirror.example/db.tar.zst") {
		t.Errorf("expected the URL's userinfo masked in the error, got %v", err)
	}
}

// a declared env as it is printed or recorded: credentials masked, other values kept
func TestMaskEnv(t *testing.T) {
	got := MaskEnv(map[string]string{
		"GRYPE_REGISTRY_AUTH_PASSWORD": "hunter2",
		"SYFT_REGISTRY_AUTH_0_TOKEN":   "abc123",
		"GRYPE_DB_UPDATE_URL":          "https://example.invalid/listing.json",
		"HTTPS_PROXY":                  "http://bob:s3cret@proxy.example:8080",
		"GRYPE_MATCH_JAVA_USING_CPES":  "false",
	})
	want := map[string]string{
		"GRYPE_REGISTRY_AUTH_PASSWORD": Masked,
		"SYFT_REGISTRY_AUTH_0_TOKEN":   Masked,
		"GRYPE_DB_UPDATE_URL":          Masked,
		"HTTPS_PROXY":                  "http://*******@proxy.example:8080",
		"GRYPE_MATCH_JAVA_USING_CPES":  "false",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: expected %q, got %q", k, v, got[k])
		}
	}
}
