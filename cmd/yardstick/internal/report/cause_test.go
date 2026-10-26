package report

import (
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
)

func TestCauseLayout(t *testing.T) {
	snapshotLayout(t, "cause")
}

// the same stdlib in two binaries is one change, counted by its two places, and --details rows
// tells the two rows apart by location
func TestCauseTwoBinaries(t *testing.T) {
	dropped := func(pkgID, location string) Match {
		return Match{ID: pkgID + "/CVE-2023-24531", Vulnerability: "CVE-2023-24531", Package: "pkg:golang/stdlib@1.18.4",
			MatchType: "nvd:cpe cpe-match", Matcher: "go-module-matcher", Location: location, InReference: true, Direction: Review}
	}
	g := Gate{Name: "go", Path: "gates/go.yaml", Outcome: analysis.Undecided, Subjects: []Subject{{Name: "img",
		Matches: []Match{dropped("aa", "/usr/local/bin/grype"), dropped("bb", "/usr/local/bin/syft")}}}}
	out := render(t, Summarize([]Gate{g}), Options{Format: "cause", Details: DetailsRows})
	for _, want := range []string{
		"1 go-module-matcher stopped reporting nvd:cpe cpe-match on golang/stdlib\n",
		"    2 matches, 1 CVE, 2 packages, on img\n",
		"      CVE-2023-24531 on stdlib@1.18.4 in 2 places\n",
		"      CVE-2023-24531   stdlib@1.18.4   /usr/local/bin/grype\n",
		"      CVE-2023-24531   stdlib@1.18.4   /usr/local/bin/syft\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in\n%s", want, out)
		}
	}
}
