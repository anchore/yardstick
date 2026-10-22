package labelserver

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

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

// a log's tail starts on a whole line, or failing that a whole rune, never inside one
func TestLogTailKeepsRunesWhole(t *testing.T) {
	log := []byte("first line\n" + strings.Repeat("é", 10) + "\nlast é line\n")
	if got := string(tail(log, 18)); got != "last é line\n" {
		t.Errorf("expected the tail from the last whole line, got %q", got)
	}
	if got := tail([]byte(strings.Repeat("é", 10)), 5); !utf8.Valid(got) || len(got) != 4 {
		t.Errorf("expected two whole runes with no newline to cut at, got %q", got)
	}
}

// subject slugs stay unique however the names collide with numbered ones
func TestSubjectSlugsAreUnique(t *testing.T) {
	used := map[string]bool{}
	var got []string
	for _, name := range []string{"x", "x", "x-2", "x"} {
		got = append(got, uniqueSlug(used, name))
	}
	if strings.Join(got, " ") != "x x-2 x-2-2 x-3" {
		t.Errorf("expected unique slugs, got %v", got)
	}
}
