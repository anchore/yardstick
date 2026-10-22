package gatefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// registry is a stand-in for the check registry: one check of each shape loading cares about.
func ptr(v float64) *float64 { return &v }

var registry = map[string]CheckDef{
	"f1NotWorse": {Name: "f1NotWorse", ReadsReference: true, Params: []Param{
		{Name: "tolerance", Min: 0, Default: ptr(0)},
	}},
	"noNewFalseNegatives": {Name: "noNewFalseNegatives", ReadsReference: true, Params: []Param{
		{Name: "max", Integer: true, Default: ptr(0)},
	}},
	"unlabeledChangesAtMost": {Name: "unlabeledChangesAtMost", ReadsReference: true, Params: []Param{
		{Name: "max", Integer: true, Description: "how many may stay unlabeled"},
	}},
	"unlabeledPercentAtMost": {Name: "unlabeledPercentAtMost", Params: []Param{
		{Name: "max", Max: ptr(100)},
	}},
	"expectationsMetAtLeast": {Name: "expectationsMetAtLeast", Params: []Param{
		{Name: "min", Integer: true, Excludes: "minFraction"},
		{Name: "minFraction", Max: ptr(1), Excludes: "min"},
	}},
}

const digest = "sha256:f0f8e8ee94f8b5d9364f21ceffd50b7db7e19b1938271295eff8229b3cf56db2"

const validGate = `schema: v1
description: grype PRs against the quality images
claims:
  - ../claims
candidate: {grype: grype@v0.120.1, db: latest, config: quality.yaml}
reference: {grype: grype@v0.119.0, db: latest, config: quality.yaml}
subjects:
  - oci:docker.io/anchore/test_images@` + digest + `
checks:
  - name: noNewFalseNegatives
  - name: f1NotWorse
    params: {tolerance: 0.01}
`

// gateDir is a directory holding a claims directory, for gate files to point at.
func gateDir(t *testing.T) string {
	t.Helper()
	// the canonical spelling, as loading resolves paths (on macOS, /private/var for /var)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "claims"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func load(t *testing.T, content string, opts ...Options) (*Gate, error) {
	t.Helper()
	o := Options{Checks: registry}
	if len(opts) > 0 {
		o = opts[0]
		o.Checks = registry
	}
	return Load(write(t, gateDir(t), "gates/deb-matching.yaml", content), o)
}

func TestLoadValid(t *testing.T) {
	g, err := load(t, validGate)
	if err != nil {
		t.Fatal(err)
	}
	if g.Name != "deb-matching" {
		t.Errorf("expected the name to default to the file name, got %q", g.Name)
	}
	if g.Undecided != UndecidedFail {
		t.Errorf("expected undecided to default to fail, got %q", g.Undecided)
	}
	if len(g.Checks) != 2 || g.Checks[0].Params["max"] != 0 || g.Checks[1].Params["tolerance"] != 0.01 {
		t.Errorf("expected the checks with defaults filled in, got %+v", g.Checks)
	}
	if len(g.SHA256) != 64 {
		t.Errorf("expected the file's digest, got %q", g.SHA256)
	}
}

func TestLoadVulnerabilities(t *testing.T) {
	g, err := load(t, validGate+"vulnerabilities:\n  maxYear: 2021\n  namespaces: [nvd:cpe, debian:distro:debian:12]\n")
	if err != nil {
		t.Fatal(err)
	}
	if v := g.Vulnerabilities; v == nil || v.MaxYear != 2021 || strings.Join(v.Namespaces, ",") != "nvd:cpe,debian:distro:debian:12" {
		t.Errorf("expected the filter as written, got %+v", v)
	}
	if g, err := load(t, validGate); err != nil || g.Vulnerabilities != nil {
		t.Errorf("expected no filter by default, got %+v (%v)", g, err)
	}
}

// each case changes one thing in a valid gate file and expects loading to fail with a message
func TestLoadRefuses(t *testing.T) {
	without := func(s, cut string) string { return strings.Replace(s, cut, "", 1) }
	swap := func(old, new string) string { return strings.Replace(validGate, old, new, 1) }
	tests := []struct {
		name, gate, want string
	}{
		// gate-file-schema
		{"unknown top-level key", validGate + "hold: db\n", `unknown key "hold"`},
		{"pairing key", validGate + "match: {key: name}\n", `unknown key "match"`},
		{"report key", validGate + "report: {diff: true}\n", `unknown key "report"`},
		{"no schema", without(validGate, "schema: v1\n"), "schema must be v1"},
		{"schema v2", swap("schema: v1", "schema: v2"), "schema must be v1"},
		{"no checks", strings.Split(validGate, "checks:")[0] + "checks: []\n", "at least one check"},
		{"no subjects", swap("subjects:\n  - oci:docker.io/anchore/test_images@"+digest, "subjects: []"), "at least one subject"},
		{"unknown candidate key", swap("config: quality.yaml}", "config: quality.yaml, hold: db}"), `unknown key "candidate.hold"`},
		// setups
		{"no candidate", without(validGate, "candidate: {grype: grype@v0.120.1, db: latest, config: quality.yaml}\n"), "candidate is required"},
		{"candidate without db", swap("candidate: {grype: grype@v0.120.1, db: latest,", "candidate: {grype: grype@v0.120.1,"), "candidate.db is required"},
		{"reference without grype", swap("reference: {grype: grype@v0.119.0,", "reference: {"), "reference.grype is required"},
		{"grype not grype", swap("grype: grype@v0.120.1", "grype: syft@v1.0.0"), "candidate.grype must be"},
		// checks-list
		{"unknown check", swap("noNewFalseNegatives", "noRegressions"), `unknown check "noRegressions"`},
		{"unknown key in a check", swap("  - name: noNewFalseNegatives", "  - name: noNewFalseNegatives\n    param: {max: 1}"), `unknown key "checks[0].param"`},
		{"check listed twice", validGate + "  - name: f1NotWorse\n", "listed twice"},
		{"misspelled param", swap("tolerance: 0.01", "tolerence: 0.01"), `no param "tolerence"`},
		{"param not a number", swap("tolerance: 0.01", "tolerance: high"), "must be a number"},
		{"param below minimum", swap("tolerance: 0.01", "tolerance: -1"), "at least 0"},
		{"fractional count", swap("  - name: noNewFalseNegatives", "  - name: unlabeledChangesAtMost\n    params: {max: 1.5}"), "max must be a whole number"},
		{"required param missing", swap("  - name: noNewFalseNegatives", "  - name: unlabeledChangesAtMost"), "needs max"},
		{"param above maximum", swap("  - name: noNewFalseNegatives", "  - name: unlabeledPercentAtMost\n    params: {max: 120}"), "at most 100"},
		// undecided-policy
		{"bad undecided", validGate + "undecided: maybe\n", "undecided must be fail or pass"},
		// vulnerabilities
		{"unknown vulnerabilities key", validGate + "vulnerabilities:\n  maxYears: 2021\n", `unknown key "vulnerabilities.maxYears" (line 14)`},
		{"maxYear not a year", validGate + "vulnerabilities: {maxYear: 21}\n", "maxYear must be a four-digit year"},
		{"maxYear not a number", validGate + "vulnerabilities: {maxYear: soon}\n", "cannot unmarshal"},
		{"empty namespaces", validGate + "vulnerabilities: {namespaces: []}\n", "namespaces must list at least one"},
		// subjects
		{"tag without digest", swap("test_images@"+digest, "test_images:latest"), "pinned by digest"},
		{"a purl literal", swap("oci:docker.io/anchore/test_images@"+digest, "pkg:deb/debian/libxml2@2.7.8"), "oci:<image>@sha256:<digest> or sbom:<path>"},
		{"filter without name", swap("  - oci:docker.io/anchore/test_images@"+digest, "  - ref: oci:docker.io/anchore/test_images@"+digest+"\n    packages: {keepTypes: [deb]}"), "needs a name"},
		{"empty keepTypes", swap("  - oci:docker.io/anchore/test_images@"+digest, "  - ref: oci:docker.io/anchore/test_images@"+digest+"\n    name: x\n    packages: {keepTypes: []}"), "keepTypes must list"},
		{"unknown keepType", swap("  - oci:docker.io/anchore/test_images@"+digest, "  - ref: oci:docker.io/anchore/test_images@"+digest+"\n    name: x\n    packages: {keepTypes: [deb, go-modules]}"), `packages.keepTypes lists "go-modules", which is not a syft package type`},
		{"path keepType", swap("  - oci:docker.io/anchore/test_images@"+digest, "  - ref: oci:docker.io/anchore/test_images@"+digest+"\n    name: x\n    packages: {keepTypes: [../deb]}"), `lists "../deb"`},
		{"subtract filter", swap("  - oci:docker.io/anchore/test_images@"+digest, "  - ref: oci:docker.io/anchore/test_images@"+digest+"\n    name: x\n    packages: {subtract: ubuntu-base}"), `unknown key "subjects[0].packages.subtract"`},
		{"frozen declared", swap("  - oci:docker.io/anchore/test_images@"+digest, "  - ref: oci:docker.io/anchore/test_images@"+digest+"\n    frozen: true"), `unknown key "subjects[0].frozen"`},
		{"two subjects one name", swap("  - oci:docker.io/anchore/test_images@"+digest, "  - oci:docker.io/anchore/test_images@"+digest+"\n  - oci:docker.io/anchore/test_images@"+digest), "two subjects are named"},
		// catalog
		{"floating syft", validGate + "catalog: {syft: syft@latest}\n", "must be pinned"},
		{"catalog without syft", validGate + "catalog: {platform: linux/amd64}\n", "catalog: syft is required"},
		{"catalog unknown key", validGate + "catalog: {syft: syft@v1.54.1, scope: squashed}\n", `unknown key "catalog.scope"`},
		// claims-sources
		{"missing claims directory", swap("  - ../claims\n", "  - does-not-exist\n"), `"does-not-exist" is neither an existing directory`},
		{"no claims at all", without(validGate, "claims:\n  - ../claims\n"), "at least one claims source"},
		// declared-environment
		{"pinning key in candidate env", swap("config: quality.yaml}", "config: quality.yaml, env: {GRYPE_DB_AUTO_UPDATE: \"true\"}}"), "candidate.env may not set GRYPE_DB_AUTO_UPDATE"},
		{"pinning key in reference env", strings.Replace(validGate, "reference: {grype: grype@v0.119.0, db: latest, config: quality.yaml}", "reference: {grype: grype@v0.119.0, db: latest, env: {GRYPE_DB_VALIDATE_AGE: \"true\"}}", 1), "reference.env may not set GRYPE_DB_VALIDATE_AGE"},
		{"cache dir in env", swap("config: quality.yaml}", "config: quality.yaml, env: {GRYPE_DB_CACHE_DIR: /tmp}}"), "may not set GRYPE_DB_CACHE_DIR"},
		{"syft update check in catalog env", validGate + "catalog: {syft: syft@v1.54.1, env: {SYFT_CHECK_FOR_APP_UPDATE: \"true\"}}\n", "catalog.env may not set SYFT_CHECK_FOR_APP_UPDATE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.gate)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected an error with %q, got %v", tt.want, err)
			}
			// every error names the file it is about
			if !strings.Contains(err.Error(), "deb-matching.yaml") {
				t.Errorf("expected the error to name the gate file, got %v", err)
			}
		})
	}
}

func TestLoadReportsEveryProblem(t *testing.T) {
	_, err := load(t, strings.Replace(validGate, "noNewFalseNegatives", "noRegressions", 1)+"hold: db\n")
	var le *LoadError
	if !errors.As(err, &le) || len(le.Problems) != 1 {
		// an unknown top-level key stops decoding, since the rest of the file can't be trusted
		t.Fatalf("expected the unknown key alone, got %v", err)
	}
	_, err = load(t, strings.Replace(strings.Replace(validGate, "noNewFalseNegatives", "noRegressions", 1), "schema: v1", "schema: v2", 1))
	if !errors.As(err, &le) || len(le.Problems) != 2 {
		t.Fatalf("expected both the check and the schema, got %v", err)
	}
}

func TestReferenceReadingChecksNeedAReference(t *testing.T) {
	noRef := strings.Replace(validGate, "reference: {grype: grype@v0.119.0, db: latest, config: quality.yaml}\n", "", 1)
	_, err := load(t, noRef)
	if err == nil || !strings.Contains(err.Error(), "check noNewFalseNegatives reads the reference setup") ||
		!strings.Contains(err.Error(), "check f1NotWorse reads the reference setup") {
		t.Fatalf("expected each reference-reading check named, got %v", err)
	}

	presence := strings.Split(noRef, "checks:")[0] + "checks:\n  - name: expectationsMetAtLeast\n    params: {min: 76}\n"
	g, err := load(t, presence)
	if err != nil {
		t.Fatal(err)
	}
	if g.HasReference() {
		t.Error("expected a gate with no reference")
	}
}

// min is a count and minFraction a fraction, and a gate sets exactly one: min 1 reads as "at least
// one", never as 100%
func TestAlternativeParams(t *testing.T) {
	gate := func(params string) string {
		return strings.Split(validGate, "checks:")[0] + "checks:\n  - name: expectationsMetAtLeast\n    params: " + params + "\n"
	}
	for params, want := range map[string]map[string]float64{"{min: 1}": {"min": 1}, "{minFraction: 1}": {"minFraction": 1}, "{minFraction: 0.95}": {"minFraction": 0.95}} {
		g, err := load(t, gate(params))
		if err != nil {
			t.Fatalf("%s: %v", params, err)
		}
		if got := g.Checks[0].Params; len(got) != len(want) || got["min"] != want["min"] || got["minFraction"] != want["minFraction"] {
			t.Errorf("%s: expected params %v, got %v", params, want, got)
		}
	}
	for params, want := range map[string]string{
		"{min: 1, minFraction: 0.5}": "takes min or minFraction, not both",
		"{}":                         "needs min or minFraction",
		"{min: 0.5}":                 "min must be a whole number",
		"{minFraction: 1.5}":         "minFraction must be at most 1",
	} {
		if _, err := load(t, gate(params)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: expected %q, got %v", params, want, err)
		}
	}
}

func TestSubjects(t *testing.T) {
	sub := strings.Replace(validGate, "  - oci:docker.io/anchore/test_images@"+digest, `  - oci:docker.io/anchore/test_images:grype-quality@`+digest+`
  - sbom:../subjects/vendor.cdx.json
  - ref: oci:ubuntu:22.04@`+digest+`
    name: petclinic-java
    platform: linux/arm64
    packages: {keepTypes: [jenkins-plugin, java-archive]}
  - ref: oci:ubuntu:22.04@`+digest+`
    name: petclinic-deb
    packages: {keepTypes: [deb]}`, 1) + "catalog: {syft: syft@v1.54.1, platform: linux/amd64}\n"
	g, err := load(t, sub)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Subjects) != 4 {
		t.Fatalf("expected 4 subjects, got %+v", g.Subjects)
	}
	img := g.Subjects[0]
	if img.Name != "oci:docker.io/anchore/test_images:grype-quality@"+digest || img.Ref.Repository != "anchore/test_images" || img.Ref.Digest != digest {
		t.Errorf("expected the image's name to default to its ref, got %+v", img)
	}
	// an-image-address-records-its-platform: the catalog's platform, unless the entry sets one
	if img.Platform != "linux/amd64" || g.Subjects[2].Platform != "linux/arm64" {
		t.Errorf("expected the catalog's platform, then the entry's, got %q and %q", img.Platform, g.Subjects[2].Platform)
	}
	doc := g.Subjects[1]
	if !filepath.IsAbs(doc.Ref.Path) || filepath.Base(filepath.Dir(doc.Ref.Path)) != "subjects" {
		t.Errorf("expected the SBOM path resolved against the gate file, got %q", doc.Ref.Path)
	}
	java := g.Subjects[2]
	if java.Ref.Name() != "docker.io/library/ubuntu" || strings.Join(java.KeepTypes, ",") != "java-archive,jenkins-plugin" {
		t.Errorf("expected a normalized image and sorted types, got %+v", java)
	}
}

// relative-paths: every path in the file resolves against the file's directory, wherever
// yardstick runs from
func TestRelativePaths(t *testing.T) {
	dir := gateDir(t)
	gate := `schema: v1
claims: [../claims]
catalog: {syft: ../bin/syft, config: syft.yaml}
candidate: {grype: ../bin/grype, db: ../dbs/vulnerability.db.tar.zst, config: grype.yaml}
reference: {grype: grype@v0.120.1, db: dir:../dbs/current}
subjects: [sbom:vendor.cdx.json]
checks: [{name: noNewFalseNegatives}]
`
	path := write(t, dir, "gates/grype-pr.yaml", gate)
	t.Chdir(t.TempDir())
	g, err := Load(path, Options{Checks: registry})
	if err != nil {
		t.Fatal(err)
	}
	gates := filepath.Join(dir, "gates")
	want := map[string]string{
		"claims":           filepath.Join(dir, "claims"),
		"catalog.syft":     filepath.Join(dir, "bin/syft"),
		"catalog.config":   filepath.Join(gates, "syft.yaml"),
		"candidate.grype":  filepath.Join(dir, "bin/grype"),
		"candidate.db":     filepath.Join(dir, "dbs/vulnerability.db.tar.zst"),
		"candidate.config": filepath.Join(gates, "grype.yaml"),
		"reference.grype":  "grype@v0.120.1",
		"reference.db":     "dir:" + filepath.Join(dir, "dbs/current"),
		"sbom":             filepath.Join(gates, "vendor.cdx.json"),
	}
	got := map[string]string{
		"claims":           g.Claims[0].Locator,
		"catalog.syft":     g.Catalog.Syft,
		"catalog.config":   g.Catalog.Config,
		"candidate.grype":  g.Candidate.Grype,
		"candidate.db":     g.Candidate.DB,
		"candidate.config": g.Candidate.Config,
		"reference.grype":  g.Reference.Grype,
		"reference.db":     g.Reference.DB,
		"sbom":             g.Subjects[0].Ref.Path,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: expected %s, got %s", k, w, got[k])
		}
	}
}

func TestClaimsSources(t *testing.T) {
	dir := gateDir(t)
	remote := strings.Replace(validGate, "  - ../claims\n", "  - github.com/anchore/delta-prototype@main\n", 1)
	path := write(t, dir, "gates/g.yaml", remote)
	t.Chdir(dir)

	// the CLI's --claims appends after the file's list
	g, err := Load(path, Options{Checks: registry, Claims: []string{"claims"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Claims) != 2 || g.Claims[0].Remote == nil || g.Claims[0].Remote.Ref != "main" || g.Claims[1].Locator != filepath.Join(dir, "claims") {
		t.Errorf("expected the published source then ./claims, got %+v", g.Claims)
	}
	if _, err := Load(path, Options{Checks: registry, Claims: []string{"claims"}, Writes: true}); err != nil {
		t.Errorf("expected a local last source to take writes, got %v", err)
	}

	// a path after the repository names a claims directory in it, at a ref
	srcs, err := Sources(nil, []string{"github.com/anchore/vunnel/tests/quality/claims@main"})
	if err != nil || len(srcs) != 1 || *srcs[0].Remote != (Remote{Repository: "github.com/anchore/vunnel", Path: "tests/quality/claims", Ref: "main"}) {
		t.Errorf("expected a path-qualified reference, got %+v %v", srcs, err)
	}
	for _, bad := range []string{"github.com/anchore/vunnel/../x@main", "github.com/anchore/vunnel/claims/@main", "nope@main",
		"github.com/../x/p@main", "github.com/anchore/..@main", "github.com/anchore/vunnel@..", "github.com/./vunnel@main"} {
		if _, err := Sources(nil, []string{bad}); err == nil || !strings.Contains(err.Error(), bad) {
			t.Errorf("expected %s refused, got %v", bad, err)
		}
	}
	if _, err := Sources(nil, []string{"nope"}); err == nil || !strings.Contains(err.Error(), "github.com/<owner>/<repo>/<path>@<ref>") {
		t.Errorf("expected the refusal to name both reference forms, got %v", err)
	}

	// a remote last source is fine to read, and refused when the invocation writes labels
	if _, err := Load(path, Options{Checks: registry}); err != nil {
		t.Errorf("expected a read-only load against a remote source, got %v", err)
	}
	_, err = Load(path, Options{Checks: registry, Writes: true})
	if err == nil || !strings.Contains(err.Error(), "last claims source must be a local path") {
		t.Errorf("expected a remote last source refused for writes, got %v", err)
	}
}

func TestUniqueNames(t *testing.T) {
	a, err := Load(write(t, gateDir(t), "a/grype-pr.yaml", validGate), Options{Checks: registry})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(write(t, gateDir(t), "b/grype-pr.yaml", validGate), Options{Checks: registry})
	if err != nil {
		t.Fatal(err)
	}
	err = UniqueNames([]*Gate{a, b})
	if err == nil || !strings.Contains(err.Error(), a.Path) || !strings.Contains(err.Error(), b.Path) {
		t.Errorf("expected both paths named, got %v", err)
	}
	b.Name = "other"
	if err := UniqueNames([]*Gate{a, b}); err != nil {
		t.Errorf("expected distinct names to pass, got %v", err)
	}
}

// scans-follow-the-gate-file: the fingerprint covers what is scanned, not how it is judged
func TestFingerprint(t *testing.T) {
	dir := gateDir(t)
	fp := func(content string) string {
		t.Helper()
		g, err := Load(write(t, dir, "gates/g.yaml", content), Options{Checks: registry})
		if err != nil {
			t.Fatal(err)
		}
		return g.Fingerprint()
	}
	base := fp(validGate)
	if fp(validGate) != base {
		t.Fatal("expected the same file to fingerprint the same")
	}
	same := map[string]string{
		"checks":    strings.Replace(validGate, "tolerance: 0.01", "tolerance: 0.05", 1),
		"undecided": validGate + "undecided: pass\n",
		// filtered at scoring time, so the same scans are rescored
		"vulnerabilities": validGate + "vulnerabilities: {maxYear: 2021}\n",
		"description":     strings.Replace(validGate, "quality images", "quality images, again", 1),
		// score checks these per subject, against the SBOM digest the run recorded
		"catalog": validGate + "catalog: {syft: syft@v1.54.1}\n",
		"claims":  strings.Replace(validGate, "  - ../claims\n", "  - github.com/anchore/delta-prototype@main\n", 1),
	}
	for what, content := range same {
		if fp(content) != base {
			t.Errorf("expected a change to %s alone to keep the fingerprint", what)
		}
	}
	changed := map[string]string{
		"candidate": strings.Replace(validGate, "grype@v0.120.1", "grype@v0.120.2", 1),
		"reference": strings.Replace(validGate, "grype@v0.119.0", "grype@v0.118.0", 1),
		"subjects":  strings.Replace(validGate, "  - oci:docker.io/anchore/test_images@"+digest, "  - oci:docker.io/anchore/test_images@"+digest+"\n  - oci:docker.io/library/ubuntu@"+digest, 1),
		"env":       strings.Replace(validGate, "config: quality.yaml}", "config: quality.yaml, env: {GRYPE_MATCH_JAVA_USING_CPES: \"false\"}}", 1),
	}
	for what, content := range changed {
		if fp(content) == base {
			t.Errorf("expected a change to %s to change the fingerprint", what)
		}
	}
}

// one gate file reached through a symlinked directory, as macOS's /var is /private/var, and with
// --claims relative to either spelling of the working directory, fingerprints the same
func TestFingerprintIgnoresPathSpelling(t *testing.T) {
	dir := gateDir(t)
	path := write(t, dir, "gates/g.yaml", validGate)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	var prints []string
	for _, base := range []string{dir, link} {
		t.Chdir(base)
		g, err := Load(filepath.Join(base, "gates", "g.yaml"), Options{Checks: registry, Claims: []string{"claims"}})
		if err != nil {
			t.Fatal(err)
		}
		prints = append(prints, g.Fingerprint())
		if g.Path != path || g.Claims[1].Locator != filepath.Join(dir, "claims") {
			t.Errorf("expected the canonical paths, got %s and %s", g.Path, g.Claims[1].Locator)
		}
	}
	if prints[0] != prints[1] {
		t.Error("the fingerprint changed with how the path was spelled")
	}
}

// a gate file and the files it names, moved together to another directory, fingerprint the same,
// with none of those files present; pointing a setup or subject at another file changes it
func TestFingerprintIgnoresLocation(t *testing.T) {
	const moved = `schema: v1
claims: [../claims]
candidate: {grype: ../../.tool/grype, db: ../build/vulnerability.db, config: grype.yaml}
reference: {grype: grype@v0.119.0, db: "dir:../reference-db"}
subjects:
  - sbom:../sboms/deb.json
checks:
  - name: noNewFalseNegatives
`
	fp := func(dir, content string) string {
		t.Helper()
		g, err := Load(write(t, dir, "gates/g.yaml", content), Options{Checks: registry})
		if err != nil {
			t.Fatal(err)
		}
		return g.Fingerprint()
	}
	a, b := gateDir(t), gateDir(t)
	base := fp(a, moved)
	if fp(b, moved) != base {
		t.Error("expected the same gate in another directory to keep the fingerprint")
	}
	for what, content := range map[string]string{
		"grype path":   strings.Replace(moved, "../../.tool/grype", "../.tool/grype", 1),
		"db path":      strings.Replace(moved, "../build/vulnerability.db", "../build/other.db", 1),
		"dir: db path": strings.Replace(moved, "dir:../reference-db", "dir:../other-db", 1),
		"config path":  strings.Replace(moved, "config: grype.yaml", "config: other.yaml", 1),
		"sbom subject": strings.Replace(moved, "../sboms/deb.json", "../sboms/rpm.json", 1),
	} {
		if fp(b, content) == base {
			t.Errorf("expected another %s to change the fingerprint", what)
		}
	}
}

// app-config: read from the working directory only, one of two names, claims its only key, and
// the Python yardstick's config named as such
func TestLoadAppConfig(t *testing.T) {
	dir := gateDir(t)
	if app, err := LoadAppConfig(dir); app != nil || err != nil {
		t.Fatalf("expected no app config and no error, got %v, %v", app, err)
	}

	// relative sources resolve against the config file's directory, and a missing one is left for
	// the first write to create
	write(t, dir, "config/yardstick.yaml", "claims: [./claims]\n")
	app, err := LoadAppConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Load(write(t, dir, "gates/g.yaml", strings.Replace(validGate, "claims:\n  - ../claims\n", "", 1)), Options{Checks: registry, App: app})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Claims) != 1 || g.Claims[0].Locator != filepath.Join(dir, "config", "claims") || !g.Claims[0].Create {
		t.Errorf("expected config/claims from the app config, to be created, got %+v", g.Claims)
	}
	if _, err := os.Stat(filepath.Join(dir, "config", "claims")); !os.IsNotExist(err) {
		t.Errorf("expected loading a gate to create no directory, got %v", err)
	}
	// one outside the config's directory is not created, and fails as any missing directory does
	write(t, dir, "config/yardstick.yaml", "claims: [../outside]\n")
	app2, err := LoadAppConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(write(t, dir, "gates/g2.yaml", strings.Replace(validGate, "claims:\n  - ../claims\n", "", 1)), Options{Checks: registry, App: app2}); err == nil || !strings.Contains(err.Error(), "neither an existing directory") {
		t.Errorf("expected a missing directory outside the config's refused, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "outside")); err == nil {
		t.Error("expected no directory created outside the config's directory")
	}
	// nor one reached through a symlink that leaves it
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "config", "link")); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "config/yardstick.yaml", "claims: [./link/claims]\n")
	app3, err := LoadAppConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(write(t, dir, "gates/g3.yaml", strings.Replace(validGate, "claims:\n  - ../claims\n", "", 1)), Options{Checks: registry, App: app3}); err == nil {
		t.Error("expected a missing directory behind a symlink refused")
	}
	if _, err := os.Stat(filepath.Join(outside, "claims")); err == nil {
		t.Error("expected no directory created through the symlink")
	}
	write(t, dir, "config/yardstick.yaml", "claims: [./claims]\n")
	if err := os.MkdirAll(filepath.Join(dir, "config", "claims"), 0o755); err != nil {
		t.Fatal(err)
	}

	// a gate's own claims: replaces the app config's, and --claims appends after it
	t.Chdir(dir)
	g, err = Load(write(t, dir, "gates/own.yaml", validGate), Options{Checks: registry, App: app, Claims: []string{"config/claims"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Claims) != 2 || g.Claims[0].Locator != filepath.Join(dir, "claims") || g.Claims[1].Locator != filepath.Join(dir, "config", "claims") {
		t.Errorf("expected the gate's claims then --claims, got %+v", g.Claims)
	}

	// no source anywhere
	if _, err := Load(write(t, dir, "gates/none.yaml", strings.Replace(validGate, "claims:\n  - ../claims\n", "", 1)), Options{Checks: registry}); err == nil || !strings.Contains(err.Error(), "at least one claims source") {
		t.Errorf("expected a gate with no claims source refused, got %v", err)
	}

	write(t, dir, ".yardstick.yaml", "claims: [./claims]\n")
	if _, err := LoadAppConfig(dir); err == nil || !strings.Contains(err.Error(), ".yardstick.yaml") || !strings.Contains(err.Error(), filepath.Join("config", "yardstick.yaml")) {
		t.Errorf("expected both files named, got %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "config", "yardstick.yaml")); err != nil {
		t.Fatal(err)
	}

	write(t, dir, ".yardstick.yaml", "x-ref:\n  images: &images [docker.io/anchore/test_images@sha256:aa]\nresult-sets:\n  pr_vs_latest_via_sbom: {}\n")
	if _, err := LoadAppConfig(dir); err == nil || !strings.Contains(err.Error(), "Python yardstick configuration") {
		t.Errorf("expected the Python config named, got %v", err)
	}
	write(t, dir, ".yardstick.yaml", "claims: [./claims]\ndb: latest\n")
	if _, err := LoadAppConfig(dir); err == nil || !strings.Contains(err.Error(), `"db"`) {
		t.Errorf("expected the unknown key named, got %v", err)
	}

	// a config in a parent directory is not read
	child := filepath.Join(dir, "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if app, err := LoadAppConfig(child); app != nil || err != nil {
		t.Errorf("expected the parent's config ignored, got %v, %v", app, err)
	}
}
