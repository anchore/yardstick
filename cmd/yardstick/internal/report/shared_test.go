package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
)

func TestRunHeaderLayout(t *testing.T) {
	g, _ := rpmGate(t)
	g.Header.Frozen = []string{"oci:docker.io/anchore/test_images@sha256:7536ee345532f674ec9e448e3768db4e546c48220ba2b6ec9bc9cfbfb3b7b74a"}
	g.Header.InheritedEnv = []string{"GRYPE_DB_AUTO_UPDATE"}
	g.Warnings = []string{"cbl-mariner/base/core@51101e635f56: its label files record linux/arm64, and this run catalogs linux/amd64"}
	one := g
	one.Header.OneSetup, one.Header.Varied, one.Header.Held = true, nil, nil
	for name, g := range map[string]Gate{"two setups": g, "one setup": one} {
		t.Run(name, func(t *testing.T) {
			var plain, colored bytes.Buffer
			writeRunHeader(&plain, g, newStyles(false))
			writeRunHeader(&colored, g, newStyles(true))
			if colored.String() == plain.String() {
				t.Error("expected escape codes with color on")
			}
			snaps.MatchSnapshot(t, plain.String())
		})
	}
}

func TestLayoutHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"oci:docker.io/anchore/test_images@sha256:7536ee345532f674ec9e448e3768db4e546c48220ba2b6ec9bc9cfbfb3b7b74a":           "anchore/test_images@7536ee345532",
		"oci:mcr.microsoft.com/cbl-mariner/base/core@sha256:51101e635f56032d5afd3fb56d66c7b93b34d5a39ddac01695d62b94473cc34e": "cbl-mariner/base/core@51101e635f56",
		"oci:localhost/app@sha256:51101e635f56032d5afd3fb56d66c7b93b34d5a39ddac01695d62b94473cc34e":                           "app@51101e635f56",
		"oci:library/alpine:3.20": "library/alpine:3.20",
		"rpm":                     "rpm",
	} {
		if got := subjectName(in); got != want {
			t.Errorf("subjectName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := span(analysis.Value{Worst: 73, Best: 3}); got != "3..73" {
		t.Errorf("span: got %q", got)
	}
	g := Gate{Checks: []analysis.Check{{State: analysis.Fail}, {State: analysis.Pass}, {State: analysis.Undecided}, {State: analysis.Undecided}}}
	if got := tally(g); got != "1 check fails, 2 undecided, 1 passes" {
		t.Errorf("tally: got %q", got)
	}
	if got := tally(Gate{Checks: g.Checks[2:]}); got != "2 checks undecided" {
		t.Errorf("tally: got %q", got)
	}
	if got := shortPackage("pkg:golang/stdlib@1.18.4?os=linux"); got != "stdlib@1.18.4" {
		t.Errorf("shortPackage: got %q", got)
	}
	rows := rowLines([]Match{
		{Vulnerability: "CVE-2020-29509", Package: "pkg:golang/stdlib@1.16.9", Location: "/usr/local/bin/syft-v0.29.0"},
		{Vulnerability: "CVE-2023-24531", Package: "pkg:golang/stdlib@1.18.4", Location: "/usr/local/bin/grype"},
		{Vulnerability: "CVE-2023-24531", Package: "pkg:golang/stdlib@1.18.4", Location: "/usr/local/bin/syft"},
	}, "      ", newStyles(false))
	want := []string{
		"      CVE-2020-29509   stdlib@1.16.9   /usr/local/bin/syft-v0.29.0",
		"      CVE-2023-24531   stdlib@1.18.4   /usr/local/bin/grype",
		"      CVE-2023-24531   stdlib@1.18.4   /usr/local/bin/syft",
	}
	if strings.Join(rows, "\n") != strings.Join(want, "\n") {
		t.Errorf("rowLines: got\n%s", strings.Join(rows, "\n"))
	}
}

// a value two decimals would round to 0 keeps its first digits: a failing drop never reads as none
func TestNumKeepsSmallValues(t *testing.T) {
	for v, want := range map[float64]string{0: "0", 0.0005: "0.0005", -0.000523456: "-0.000523", 0.004: "0.004", 0.005: "0.01", 0.3333: "0.33", 70: "70"} {
		if got := num(v); got != want {
			t.Errorf("num(%v): expected %s, got %s", v, want, got)
		}
	}
}
