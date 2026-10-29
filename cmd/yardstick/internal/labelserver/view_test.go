package labelserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
)

// a claims source's .git changes on every fetch, but the view doesn't read it, so it isn't re-scored
func TestStampSkipsDotDirs(t *testing.T) {
	dir := t.TempDir()
	claimsDir := filepath.Join(dir, "claims")
	write := func(p, body string) {
		t.Helper()
		p = filepath.Join(claimsDir, p)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("vocabulary.yaml", "a")
	s := &Server{opts: Options{Store: agentstore.Open(filepath.Join(dir, "agent"))}}
	e := &entry{gate: &gatefile.Gate{Claims: []gatefile.Source{{Locator: claimsDir}}}}
	stamp := func() string {
		t.Helper()
		v, err := s.stampOf(e)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	before := stamp()
	write(".git/FETCH_HEAD", "x")
	if stamp() != before {
		t.Errorf("expected a .git change not to change the stamp")
	}
	write("vocabulary.yaml", "ab")
	if stamp() == before {
		t.Errorf("expected a claims file change to change the stamp")
	}
}
