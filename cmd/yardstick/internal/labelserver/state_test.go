package labelserver

import (
	"encoding/json"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
)

// every check a gate can name has the words a check row shows
func TestCheckWordsCoverRegistry(t *testing.T) {
	for _, name := range analysis.Names() {
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

// the string unions tygo.yaml declares for the UI list exactly the values the Go side sends
func TestWireUnions(t *testing.T) {
	data, err := os.ReadFile("web/tygo.yaml")
	if err != nil {
		t.Fatal(err)
	}
	unions := map[string][]string{}
	for _, m := range regexp.MustCompile(`export type (\w+) = ([^;\n]+);`).FindAllStringSubmatch(string(data), -1) {
		var values []string
		for _, part := range strings.Split(m[2], " | ") {
			if v, ok := strings.CutPrefix(part, `"`); ok {
				values = append(values, strings.TrimSuffix(v, `"`))
			} else {
				values = append(values, unions[part]...)
			}
		}
		slices.Sort(values)
		unions[m[1]] = values
	}
	dirs := map[string]bool{}
	for _, in := range [][2]bool{{true, false}, {false, true}, {true, true}, {false, false}} {
		dirs[direction(&report.Match{InCandidate: in[0], InReference: in[1]})] = true
	}
	for name, want := range map[string][]string{
		"Effect":            {effectDecides, effectCouldMove, effectCounted},
		"QueueEffect":       {effectDecides, effectCouldMove, effectCounted, effectNone},
		"Direction":         slices.Collect(maps.Keys(dirs)),
		"CheckDirection":    {atMost, atLeast},
		"HintGroup":         {groupDecides, groupNeeded, groupNone},
		"HintOrigin":        {OriginLabelUI, OriginResearchJob, OriginSkillRun},
		"MemberState":       {memberPending, memberConflict, memberLabeled, memberAccepted, "missing"},
		"ResearchLevel":     {LevelTriaged, LevelResearched},
		"ResearchGroupName": {researchChange, researchNone},
		"ResearchFrom":      {FromTable, FromFinding},
		"LabelScope":        {scopeSubject, scopeAnywhere},
		"VocabularyList":    {claimsv1.ListDisclosure, claimsv1.ListAdvisory},
		"ReasonKind":        agentstore.ReasonKinds,
	} {
		want = slices.Sorted(slices.Values(want))
		if got := unions[name]; !slices.Equal(got, want) {
			t.Errorf("tygo.yaml's %s is %v, the Go side sends %v", name, got, want)
		}
	}
}
