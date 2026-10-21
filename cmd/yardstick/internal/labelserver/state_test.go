package labelserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
)

// every check a gate can name has the words a check row shows
func TestCheckWordsCoverRegistry(t *testing.T) {
	for name := range analysis.Registry {
		if w := checkWords[name]; w.summary == "" || w.direction == "" {
			t.Errorf("checkWords has no summary or direction for %s", name)
		}
	}
}

// a check that counts no findings lists none, not null: the check page maps over them
func TestCheckFindingsOfNone(t *testing.T) {
	data, err := json.Marshal(CheckFindings{Findings: (&view{}).checkFindings(analysis.Check{Name: "noNewFalsePositives"}, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"findings":[]`) {
		t.Errorf("expected an empty findings list, got %s", data)
	}
}
