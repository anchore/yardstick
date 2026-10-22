//go:build integration

package collect

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
)

// the DB generate.sh scanned the fixtures with
const fixtureDB = "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.10_2026-10-14T00:28:57Z_1791959434.tar.zst"

// each-setup-scans-one-sbom with the real grype releases: each setup's output over
// the fixture SBOM has the matches generate.sh recorded for that version
func TestScanGateWithGrype(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	deb, err := ref.Parse("sbom:" + fixture.SBOM("deb", "syft"))
	if err != nil {
		t.Fatal(err)
	}
	g := &gatefile.Gate{
		Name:      "deb",
		Candidate: &gatefile.Setup{Grype: "grype@v0.120.1", DB: fixtureDB},
		Reference: &gatefile.Setup{Grype: "grype@v0.119.0", DB: fixtureDB},
		Claims:    []gatefile.Source{{Locator: t.TempDir()}},
		Subjects:  []gatefile.Subject{{Ref: deb, Name: "deb"}},
	}
	run := execute.Runner{}
	set, err := claims.OpenSet(g.Claims)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Scans{Run: run, RunName: runrecord.DefaultName, Preparer: setup.NewPreparer(install.NewResolver(), run)}.Gate(context.Background(), g, set)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Setups[gatefile.Candidate].DB.Dir != rec.Setups[gatefile.Reference].DB.Dir {
		t.Errorf("expected one DB imported once for both setups")
	}
	for setupName, version := range map[string]string{gatefile.Candidate: "v0.120.1", gatefile.Reference: "v0.119.0"} {
		got, _ := os.ReadFile(filepath.Join(runrecord.Dir(runrecord.DefaultName, "deb"), rec.Subjects[0].Scans[setupName]))
		want, _ := os.ReadFile(fixture.Grype(version, "deb"))
		if a, b := matchKeys(t, got), matchKeys(t, want); len(a) == 0 || len(a) != len(b) {
			t.Errorf("%s: %d matches, generate.sh recorded %d", setupName, len(a), len(b))
		} else {
			for i := range a {
				if a[i] != b[i] {
					t.Errorf("%s: %s, generate.sh recorded %s", setupName, a[i], b[i])
				}
			}
		}
	}
}

func matchKeys(t *testing.T, data []byte) []string {
	t.Helper()
	doc, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range doc.Matches {
		out = append(out, m.Vulnerability.ID+" "+m.Artifact.ID)
	}
	sort.Strings(out)
	return out
}
