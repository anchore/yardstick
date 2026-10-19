package report

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
)

func TestCheckLayout(t *testing.T) {
	snapshotLayout(t, "check")
}

func TestVerdictFirst(t *testing.T) {
	failing, _ := rpmGate(t)
	out := render(t, Summarize([]Gate{passing(t), failing}), Options{Format: "check"})
	verdicts := out[strings.Index(out, "FAIL gate rpm-cpes"):]
	lines := strings.Split(strings.TrimSpace(verdicts), "\n")
	if lines[0] != "FAIL gate rpm-cpes  1 check fails, 1 undecided, 1 passes" {
		t.Errorf("expected the failing gate's outcome before any detail and before the passing gate, got %q", lines[0])
	}
	// the passing gate prints one line
	if strings.Count(verdicts, "rpm-coverage") != 1 || !strings.Contains(verdicts, "\nPASS gate rpm-coverage  1 check passes\n\nFAILED 1 of 2 gates") {
		t.Errorf("expected the passing gate on one line just before the summary, got\n%s", verdicts)
	}
	// with --quiet a failure and the summary still print
	quiet := render(t, Summarize([]Gate{passing(t), failing}), Options{Format: "check", Quiet: true})
	if !strings.HasPrefix(quiet, "FAIL gate rpm-cpes") || !strings.HasSuffix(quiet, "FAILED 1 of 2 gates\n") || strings.Contains(quiet, "rpm-coverage") {
		t.Errorf("expected only the failing gate and the summary, got\n%s", quiet)
	}
}

// rows-summarized: by default a check's rows print as groups, every count exact, and --details rows
// prints each row once per gate, under the check that printed its group first
func TestRowsSummarized(t *testing.T) {
	g, _ := rpmGate(t)
	var sc analysis.SubjectCheck
	for _, c := range g.Checks {
		if c.Name == analysis.UnjudgedChangesAtMost {
			sc = c.Subjects[0]
		}
	}
	section := func(out string) string {
		out = out[strings.Index(out, "UNDECIDED unjudgedChangesAtMost"):]
		return out[:strings.Index(out, "\n\n")+1]
	}
	out := render(t, Summarize([]Gate{g}), Options{Format: "check"})
	// noNewFalsePositives prints these rows first, so this check only refers back to them
	re := regexp.MustCompile(`(?m)^    (\d+) unlabeled, added  same rows as noNewFalsePositives$`)
	total := 0
	for _, m := range re.FindAllStringSubmatch(section(out), -1) {
		n, _ := strconv.Atoi(m[1])
		total += n
	}
	if total != len(sc.Rows) {
		t.Errorf("expected group counts summing to the %d rows, got %d in\n%s", len(sc.Rows), total, section(out))
	}
	if !strings.Contains(out, "    14 unlabeled, added by the candidate\n      14 CVEs on pkg:rpm/rocky/libssh@0.10.4-18.el9\n") {
		t.Errorf("expected libssh's rows as one group with an exact count, got\n%s", out)
	}
	// every row once, told apart by its location
	rows := render(t, Summarize([]Gate{g}), Options{Format: "check", Details: DetailsRows})
	row := regexp.MustCompile(`(?m)^      (CVE-\S+) +(\S+@\S+) +/var/lib/rpm/rpmdb.sqlite$`)
	seen := map[string]int{}
	for _, m := range row.FindAllStringSubmatch(rows, -1) {
		seen[m[1]+" "+m[2]]++
	}
	for _, id := range sc.Rows {
		m := g.Subjects[0].match(id)
		if n := seen[m.Vulnerability+" "+shortPackage(m.Package)]; n != 1 {
			t.Errorf("expected %s on %s printed once with --details rows, got %d", m.Vulnerability, m.Package, n)
		}
	}
	if section(rows) != section(out) {
		t.Errorf("expected the referring check unchanged by --details rows, got\n%s", section(rows))
	}
}
