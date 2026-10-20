package labelserver

import (
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
