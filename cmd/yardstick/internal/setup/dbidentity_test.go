package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestDirIdentitySources(t *testing.T) {
	put := func(t *testing.T, dir, name, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, "6"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "6", name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte("the DB"))

	dir := t.TempDir()
	if got := dirIdentity(dir); got != "" {
		t.Errorf("expected no identity for a directory holding no DB, got %q", got)
	}
	put(t, dir, "vulnerability.db", "the DB")
	if got := dirIdentity(dir); got != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("expected a hash of the DB file, got %q", got)
	}
	put(t, dir, "import.json", `{"digest": "xxh64:a415f9c467efd212", "client_version": "v6.1.10"}`)
	if got := dirIdentity(dir); got != "xxh64:a415f9c467efd212" {
		t.Errorf("expected grype's import digest to win over a hash, got %q", got)
	}
	put(t, dir, "import.json", `{}`)
	if got := dirIdentity(dir); got != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("expected an import.json with no digest to fall back to the hash, got %q", got)
	}
}
