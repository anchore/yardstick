package analysis

import (
	"os"
	"strings"
	"testing"
)

// the gate file reference documents every registered check: its heading, its description and each
// of its params, so a check added or reworded here fails until the doc says so too
func TestGateFileDocCoversEveryCheck(t *testing.T) {
	data, err := os.ReadFile("../../../../docs/gate-file.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	for _, name := range Names() {
		_, section, ok := strings.Cut(doc, "\n### `"+name+"`\n")
		if !ok {
			t.Errorf("docs/gate-file.md has no section for %s", name)
			continue
		}
		section, _, _ = strings.Cut(section, "\n#")
		c := Lookup(name)
		if !strings.Contains(strings.ToLower(section), strings.ToLower(c.Description)) {
			t.Errorf("docs/gate-file.md: %s does not say %q", name, c.Description)
		}
		for _, p := range c.Params {
			if !strings.Contains(section, "| `"+p.Name+"` |") || !strings.Contains(section, p.Description) {
				t.Errorf("docs/gate-file.md: %s has no row for param %s saying %q", name, p.Name, p.Description)
			}
		}
	}
}
