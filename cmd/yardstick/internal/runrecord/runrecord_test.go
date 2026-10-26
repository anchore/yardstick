package runrecord

import (
	"os"
	"path/filepath"
	"testing"
)

// runs-are-named: the partial and old sets sit under the run name, and nothing is made for a name
// that is not one segment
func TestStartUnderName(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, name := range []string{"../x", "a/b", "Result", "", ".a"} {
		if _, err := Start(name, "deb"); err == nil {
			t.Errorf("expected %q refused", name)
		}
	}
	if _, err := os.Stat(".yardstick"); !os.IsNotExist(err) {
		t.Fatalf("expected nothing made for a refused name, got %v", err)
	}

	for range 2 {
		p, err := Start("pr-1.2_x", "deb")
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(".yardstick", "runs", "pr-1.2_x", ".partial-deb"); p.Dir != want {
			t.Errorf("expected the partial set at %s, got %s", want, p.Dir)
		}
		// the second Replace moves the first set to .old-deb before dropping it
		if err := p.Replace(&Record{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Load("pr-1.2_x", "deb"); err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]string{".yardstick": "runs", RunsDir: "pr-1.2_x", filepath.Join(RunsDir, "pr-1.2_x"): "deb"} {
		if entries, _ := os.ReadDir(dir); len(entries) != 1 || entries[0].Name() != want {
			t.Errorf("expected %s to hold only %s, got %v", dir, want, entries)
		}
	}
}
