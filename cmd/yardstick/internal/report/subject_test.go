package report

import (
	"strings"
	"testing"
)

func TestSubjectLayout(t *testing.T) {
	snapshotLayout(t, "subject")
}

// every row only one setup reports prints once under its subject, even when two checks name it,
// and a subject every check passes on is one line until --details passing
func TestSubjectRowsOnce(t *testing.T) {
	failing, _ := rpmGate(t)
	out := render(t, Summarize([]Gate{failing}), Options{Format: "subject", Details: DetailsRows})
	printed := map[string]int{}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); strings.HasPrefix(l, "      CVE-") && len(f) == 3 {
			printed[f[0]+" "+f[1]]++
		}
	}
	rows := 0
	for _, m := range failing.Subjects[0].Matches {
		if m.InCandidate == m.InReference {
			continue
		}
		rows++
		if n := printed[m.Vulnerability+" "+shortPackage(m.Package)]; n != 1 {
			t.Errorf("expected %s on %s printed once, got %d", m.Vulnerability, m.Package, n)
		}
	}
	if len(printed) != rows || !strings.Contains(out, "\n  35 matches only the candidate reports") {
		t.Errorf("expected the %d rows the candidate added under one heading, printed %d in\n%s", rows, len(printed), out)
	}
	set := fixtureSet(t)
	if def := render(t, set, Options{Format: "subject"}); strings.Contains(def, "PASS  F1") || strings.Contains(def, "1 subject passes") {
		t.Errorf("expected the passing gate on one line by default, got\n%s", def)
	}
	if more := render(t, set, Options{Format: "subject", Details: DetailsPassing}); !strings.Contains(more, "1 subject passes every check\n  PASS  F1 0.00 -> 0.33  rpm\n") {
		t.Errorf("expected --details passing to list the passing subject, got\n%s", more)
	}
}
