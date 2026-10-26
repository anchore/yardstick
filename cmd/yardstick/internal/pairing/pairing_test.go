package pairing

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

var advisories = []string{"ALAS*", "ALSA", "ELSA", "RLSA", "RHSA"}

func isAdvisory(id string) bool {
	v := claimsv1.Vocabulary{AdvisoryIDs: advisories}
	return v.IsAdvisory(id)
}

const oracleSBOM = "docker.io+oraclelinux@sha256-a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495.syft.json.gz"

// scan is grype's output for a fixture.
func scan(t *testing.T, path string) *models.Document {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// decoded as collect.Decode does, which imports this package
	var doc models.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return &doc
}

// sbomPath is a fixture SBOM as a plain file.
func sbomPath(t *testing.T, image string) string {
	t.Helper()
	if image != "oracle" {
		return fixture.SBOM(image, "syft")
	}
	f, err := os.Open(fixture.Path("vml", "sbom", oracleSBOM))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "oracle.syft.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// packagesOf resolves an SBOM document subject, filtered when keep is given.
func packagesOf(t *testing.T, path string, keep ...string) []Package {
	t.Helper()
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	r, err := ref.Parse("sbom:" + path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := (&subject.Resolver{}).Resolve(context.Background(), gatefile.Subject{Ref: r, Name: "s", KeepTypes: keep})
	if err != nil {
		t.Fatal(err)
	}
	var out []Package
	for _, p := range res.Packages {
		out = append(out, p)
	}
	return out
}

// label is a person's call, as a claims source holds it.
func label(pkg, vuln string, v claimsv1.Verdict) claims.Label {
	l := claims.Label{Label: claimsv1.Label{Package: pkg, Vulnerability: vuln, Verdict: v}, File: "deb.json"}
	l.Held = []claims.SourceVerdict{{Source: "corpus", Verdict: v}}
	return l
}

func global(l claims.Label) claims.Label {
	l.Global = true
	return l
}

// pair pairs labels against one image's fixture scans, the same output as both setups unless
// a candidate is given.
func pair(t *testing.T, image string, candidate *models.Document, ls ...claims.Label) *Result {
	t.Helper()
	reference := scan(t, fixture.Grype("v0.120.1", image))
	if candidate == nil {
		candidate = scan(t, fixture.Grype("v0.120.1", image))
	}
	return pairScans(t, sbomPath(t, image), candidate, reference, ls...)
}

func pairScans(t *testing.T, sbom string, candidate, reference *models.Document, ls ...claims.Label) *Result {
	t.Helper()
	a := NewAliases(isAdvisory)
	a.AddScan(candidate)
	a.AddScan(reference)
	a.AddLabels(ls)
	return Pair(a, Subject{Name: "s", Packages: packagesOf(t, sbom), Labels: ls,
		Scans: map[string]*models.Document{gatefile.Candidate: candidate, gatefile.Reference: reference}})
}

func find(t *testing.T, r *Result, vuln, pkg string) *Match {
	t.Helper()
	for _, m := range r.Matches {
		if m.Vulnerability == vuln && m.Package.Name == pkg {
			return m
		}
	}
	t.Fatalf("no match %s on %s", vuln, pkg)
	return nil
}

func bound(t *testing.T, r *Result, vuln string) *Bound {
	t.Helper()
	for _, b := range r.Labels {
		if b.Vulnerability == vuln {
			return b
		}
	}
	t.Fatalf("label on %s is not bound", vuln)
	return nil
}

const log4j = "pkg:maven/org.apache.logging.log4j/log4j-core"

func TestAliasGroups(t *testing.T) {
	t.Run("one DB drops a CVE to GHSA link", func(t *testing.T) {
		candidate := scan(t, fixture.Grype("v0.120.1", "java"))
		for i := range candidate.Matches {
			if candidate.Matches[i].Vulnerability.ID == "GHSA-jfh8-c2jp-5v3q" {
				candidate.Matches[i].RelatedVulnerabilities = nil
			}
		}
		r := pair(t, "java", candidate, label(log4j, "CVE-2021-44228", claimsv1.TP))
		b := bound(t, r, "CVE-2021-44228")
		if !b.PairedIn(gatefile.Candidate) || !b.PairedIn(gatefile.Reference) || len(b.Matches) != 2 {
			t.Errorf("expected the label to pair GHSA-jfh8-c2jp-5v3q in both setups, paired %d matches", len(b.Matches))
		}
		if g := r.aliases.Group("GHSA-jfh8-c2jp-5v3q"); g != r.aliases.Group("CVE-2021-44228") {
			t.Errorf("expected one group, got %s", g)
		}
	})
	t.Run("reading a group changes nothing", func(t *testing.T) {
		// two relations that leave GHSA-3 two steps from its root
		a := NewAliases(nil)
		a.add("GHSA-2", "GHSA-3")
		a.add("CVE-1", "GHSA-2")
		before := maps.Clone(a.parent)
		if a.Group("GHSA-3") != "CVE-1" || !maps.Equal(before, a.parent) {
			t.Errorf("expected GHSA-3 in CVE-1's group and the alias set left as it was, got %v", a.parent)
		}
	})
	t.Run("an id neither setup reported", func(t *testing.T) {
		r := pair(t, "java", nil, label(log4j, "CVE-2020-9999", claimsv1.TP))
		if b := bound(t, r, "CVE-2020-9999"); len(b.Matches) != 0 || r.aliases.Group("CVE-2020-9999") != "CVE-2020-9999" {
			t.Errorf("expected a group of its own pairing nothing, paired %d", len(b.Matches))
		}
	})
	t.Run("an advisory relates several CVEs", func(t *testing.T) {
		ol := scan(t, fixture.Path("vml", "grype-oraclelinux.json"))
		a := NewAliases(isAdvisory)
		a.AddScan(ol)
		if a.Group("CVE-2022-25235") == a.Group("CVE-2022-25236") || a.Group("ELSA-2022-9359") != "" {
			t.Errorf("expected the advisory's CVEs in groups of their own and the advisory in none")
		}
	})
}

func TestLabelPairsOnStatedFields(t *testing.T) {
	for _, tc := range []struct {
		name, image, pkg, vuln string
		pairs                  []string // package names of the matches it pairs
	}{
		{"no version", "deb", "pkg:deb/debian/ncurses-base?distro=debian-12", "CVE-2023-50495", []string{"ncurses-base"}},
		{"versioned", "deb", "pkg:deb/debian/ncurses-base@6.4-4?distro=debian-12", "CVE-2023-50495", []string{"ncurses-base"}},
		{"a stated qualifier differs", "deb", "pkg:deb/debian/ncurses-base@6.4-4?distro=debian-11", "CVE-2023-50495", nil},
		{"no package", "deb", "", "CVE-2023-50495", []string{"libtinfo6", "ncurses-base", "ncurses-bin"}},
		{"version without the epoch grype reports", "rpm", "pkg:rpm/rocky/openssl-libs@3.5.5-2.el9_8", "CVE-2026-45447", nil},
		{"epoch as a qualifier", "rpm", "pkg:rpm/rocky/openssl-libs@3.5.5-2.el9_8?epoch=1", "CVE-2026-45447", []string{"openssl-libs"}},
		{"epoch in the version", "rpm", "pkg:rpm/rocky/openssl-libs@1:3.5.5-2.el9_8", "CVE-2026-45447", []string{"openssl-libs"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := pair(t, tc.image, nil, label(tc.pkg, tc.vuln, claimsv1.TP))
			var got []string
			for _, m := range bound(t, r, tc.vuln).Matches {
				got = append(got, m.Package.Name)
			}
			if strings.Join(got, ",") != strings.Join(tc.pairs, ",") {
				t.Errorf("expected it to pair %v, paired %v", tc.pairs, got)
			}
		})
	}
}

func TestOneLabelSeveralMatches(t *testing.T) {
	// log4j-core in two jars is two packages, and one versionless label pairs both
	r := pair(t, "java", nil, label(log4j, "CVE-2021-44228", claimsv1.TP))
	b := bound(t, r, "CVE-2021-44228")
	if len(b.Matches) != 2 || b.Matches[0].PackageID == b.Matches[1].PackageID {
		t.Fatalf("expected the label to pair the match in both jars, paired %d", len(b.Matches))
	}
	for _, m := range b.Matches {
		if m.Verdict != claimsv1.TP {
			t.Errorf("expected each match to take tp, got %q", m.Verdict)
		}
	}
}

func TestMostSpecificLabelWins(t *testing.T) {
	const ncurses = "pkg:deb/debian/ncurses-base@6.4-4"
	for _, tc := range []struct {
		name   string
		labels []claims.Label
		want   claimsv1.Verdict
	}{
		{"subject over global", []claims.Label{global(label(ncurses, "CVE-2023-50495", claimsv1.FP)), label(ncurses, "CVE-2023-50495", claimsv1.TP)}, claimsv1.TP},
		{"versioned over versionless", []claims.Label{label("pkg:deb/debian/ncurses-base", "CVE-2023-50495", claimsv1.TP), label(ncurses, "CVE-2023-50495", claimsv1.FP)}, claimsv1.FP},
		{"only unclear", []claims.Label{label(ncurses, "CVE-2023-50495", claimsv1.Unclear)}, ""},
		// claims.Set gives the label the last source's verdict and keeps every source's in Held
		{"the last of two sources that disagree", []claims.Label{func() claims.Label {
			l := label(ncurses, "CVE-2023-50495", claimsv1.TP)
			l.Verdict = claimsv1.FP
			l.Held = append(l.Held, claims.SourceVerdict{Source: "local", Verdict: claimsv1.FP})
			return l
		}()}, claimsv1.FP},
		{"equally specific labels disagree", []claims.Label{label("pkg:deb/debian/ncurses-base@6.4-4", "CVE-2023-50495", claimsv1.TP), label("pkg:deb/debian/ncurses-base?arch=all", "CVE-2023-50495", claimsv1.FP)}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := pair(t, "deb", nil, tc.labels...)
			if m := find(t, r, "CVE-2023-50495", "ncurses-base"); m.Verdict != tc.want {
				t.Errorf("expected %q, got %q", tc.want, m.Verdict)
			}
		})
	}
}

func TestAdvisoryKeyedMatches(t *testing.T) {
	ol := func() *models.Document { return scan(t, fixture.Path("vml", "grype-oraclelinux.json")) }
	sbom := sbomPath(t, "oracle")

	r := pairScans(t, sbom, ol(), ol(), label("pkg:rpm/ol/openssl", "CVE-2022-0778", claimsv1.TP))
	if m := find(t, r, "ELSA-2022-9246", "openssl"); m.Verdict != claimsv1.TP || len(m.Addresses) != 1 {
		t.Errorf("expected the one-CVE advisory to pair its CVE, got %q over %v", m.Verdict, m.Addresses)
	}
	for _, w := range r.Warnings {
		if strings.Contains(w, "ELSA-2022-9246") {
			t.Errorf("a one-CVE advisory warned: %s", w)
		}
	}

	r = pairScans(t, sbom, ol(), ol(),
		label("pkg:rpm/ol/expat", "CVE-2022-25235", claimsv1.TP),
		label("pkg:rpm/ol/expat", "CVE-2022-25236", claimsv1.TP))
	m := find(t, r, "ELSA-2022-9359", "expat")
	if len(m.Paired) != 2 || m.Verdict != claimsv1.TP {
		t.Errorf("expected the three-CVE advisory to pair both labels, paired %d", len(m.Paired))
	}
	warned := false
	for _, w := range r.Warnings {
		warned = warned || (strings.Contains(w, "ELSA-2022-9359") && strings.Contains(w, "3 CVEs") && strings.Contains(w, "CVE-2022-25315"))
	}
	if !warned {
		t.Errorf("expected a warning naming the match and its 3 CVEs, got %v", r.Warnings)
	}
}

// a label on an advisory pairs the match grype reported under
// exactly that id, never a CVE-keyed match, and decides that match over labels on its CVEs
func TestAdvisoryLabels(t *testing.T) {
	ol := func() *models.Document { return scan(t, fixture.Path("vml", "grype-oraclelinux.json")) }
	sbom := sbomPath(t, "oracle")
	const expat = "pkg:rpm/ol/expat"

	t.Run("pairs only its own advisory", func(t *testing.T) {
		r := pairScans(t, sbom, ol(), ol(), label(expat, "ELSA-2022-9359", claimsv1.FP))
		b := bound(t, r, "ELSA-2022-9359")
		if len(b.Matches) != 1 || b.Matches[0].Vulnerability != "ELSA-2022-9359" || !b.PairedIn(gatefile.Candidate) || !b.PairedIn(gatefile.Reference) {
			t.Fatalf("expected the label to pair ELSA-2022-9359 on expat in both setups, paired %d", len(b.Matches))
		}
		if m := find(t, r, "ELSA-2022-9359", "expat"); m.Verdict != claimsv1.FP {
			t.Errorf("expected fp, got %q", m.Verdict)
		}
		// ELSA-2022-9962 is another advisory on the same package
		if m := find(t, r, "ELSA-2022-9962", "expat"); len(m.Paired) != 0 {
			t.Errorf("expected another advisory unpaired, paired %d", len(m.Paired))
		}
		if g := r.aliases.Group("ELSA-2022-9359"); g != "" {
			t.Errorf("expected the advisory in no alias group, got %s", g)
		}
	})
	t.Run("never pairs a CVE-keyed match", func(t *testing.T) {
		candidate := ol()
		for i, m := range candidate.Matches {
			if m.Vulnerability.ID == "ELSA-2022-9359" && m.Artifact.Name == "expat" {
				candidate.Matches[i].Vulnerability.ID = "CVE-2022-25235"
				candidate.Matches[i].RelatedVulnerabilities = nil
			}
		}
		r := pairScans(t, sbom, candidate, ol(), label(expat, "ELSA-2022-9359", claimsv1.FP), label(expat, "CVE-2022-25235", claimsv1.TP))
		cve := find(t, r, "CVE-2022-25235", "expat")
		if len(cve.Paired) != 1 || cve.Label.Vulnerability != "CVE-2022-25235" || cve.Verdict != claimsv1.TP {
			t.Errorf("expected only the CVE label on the CVE-keyed match, paired %d", len(cve.Paired))
		}
		if b := bound(t, r, "ELSA-2022-9359"); b.PairedIn(gatefile.Candidate) || !b.PairedIn(gatefile.Reference) {
			t.Errorf("expected the advisory label to pair only the reference's advisory-keyed match")
		}
	})
	t.Run("pairs the CVE --by-cve reports it as when aliased", func(t *testing.T) {
		candidate := ol()
		for i, m := range candidate.Matches {
			if m.Vulnerability.ID == "ELSA-2022-9359" && m.Artifact.Name == "expat" {
				candidate.Matches[i].Vulnerability.ID = "CVE-2022-25235"
				candidate.Matches[i].RelatedVulnerabilities = []models.VulnerabilityMetadata{{ID: "ELSA-2022-9359"}}
			}
		}
		aliased := label(expat, "ELSA-2022-9359", claimsv1.FP)
		aliased.Aliases = []string{"CVE-2022-25235"}
		r := pairScans(t, sbom, candidate, ol(), aliased)
		if b := bound(t, r, "ELSA-2022-9359"); !b.PairedIn(gatefile.Candidate) || !b.PairedIn(gatefile.Reference) {
			t.Errorf("expected the aliased label to pair the candidate's CVE-keyed match and the reference's advisory")
		}
		if m := find(t, r, "CVE-2022-25235", "expat"); m.Verdict != claimsv1.FP {
			t.Errorf("expected the CVE-keyed match to take the advisory's fp, got %q", m.Verdict)
		}
		// an alias pairs only what is reported under exactly it, never another advisory naming it
		if m := find(t, r, "ELSA-2022-9962", "expat"); len(m.Paired) != 0 {
			t.Errorf("expected another advisory unpaired, paired %d", len(m.Paired))
		}
	})
	t.Run("decides over labels on its CVEs", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			labels []claims.Label
			want   claimsv1.Verdict
		}{
			{"advisory fp, CVE tp", []claims.Label{label(expat, "ELSA-2022-9359", claimsv1.FP), label(expat, "CVE-2022-25235", claimsv1.TP)}, claimsv1.FP},
			// subject over global holds among labels on the advisory, but not across the two kinds
			{"global advisory over a subject CVE label", []claims.Label{global(label(expat, "ELSA-2022-9359", claimsv1.TP)), label(expat+"@2.0.1-13.el6_8", "CVE-2022-25235", claimsv1.FP)}, claimsv1.TP},
			{"advisory unclear", []claims.Label{label(expat, "ELSA-2022-9359", claimsv1.Unclear), label(expat, "CVE-2022-25235", claimsv1.TP)}, ""},
			{"CVE labels alone still decide", []claims.Label{label(expat, "CVE-2022-25235", claimsv1.TP)}, claimsv1.TP},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := pairScans(t, sbom, ol(), ol(), tc.labels...)
				m := find(t, r, "ELSA-2022-9359", "expat")
				if m.Verdict != tc.want || len(m.Paired) != len(tc.labels) {
					t.Errorf("expected %q with every label paired, got %q with %d paired", tc.want, m.Verdict, len(m.Paired))
				}
			})
		}
	})
}

func TestMatchIdentity(t *testing.T) {
	t.Run("the setups report different ids of one group", func(t *testing.T) {
		candidate := scan(t, fixture.Grype("v0.120.1", "java"))
		for i := range candidate.Matches {
			if candidate.Matches[i].Vulnerability.ID == "GHSA-jfh8-c2jp-5v3q" {
				candidate.Matches[i].Vulnerability.ID = "CVE-2021-44228"
			}
		}
		r := pair(t, "java", candidate)
		for _, m := range r.Matches {
			if !m.In(gatefile.Candidate) || !m.In(gatefile.Reference) {
				t.Errorf("%s on %s is in one setup only", m.Vulnerability, m.PackageID)
			}
		}
	})
	t.Run("only the fix version differs", func(t *testing.T) {
		candidate := scan(t, fixture.Grype("v0.120.1", "deb"))
		for i := range candidate.Matches {
			candidate.Matches[i].Vulnerability.Fix.Versions = []string{"99.0"}
			candidate.Matches[i].Vulnerability.Fix.State = "fixed"
		}
		r := pair(t, "deb", candidate)
		for _, m := range r.Matches {
			if !m.In(gatefile.Candidate) || !m.In(gatefile.Reference) {
				t.Errorf("%s on %s is in one setup only", m.Vulnerability, m.PackageID)
			}
		}
	})
}

func TestFilteredSubjectBindsItsPackages(t *testing.T) {
	sbom := sbomPath(t, "oracle")
	ol := scan(t, fixture.Path("vml", "grype-oraclelinux.json"))
	ls := []claims.Label{
		label("pkg:rpm/ol/expat", "CVE-2022-40674", claimsv1.TP),
		label("", "CVE-2022-0778", claimsv1.TP),
		label("pkg:pypi/pyopenssl", "CVE-2018-1000807", claimsv1.TP),
	}
	a := NewAliases(isAdvisory)
	a.AddScan(ol)
	a.AddLabels(ls)
	r := Pair(a, Subject{Name: "python-only", Packages: packagesOf(t, sbom, "python"), Filtered: true, Labels: ls,
		Scans: map[string]*models.Document{gatefile.Candidate: ol}})
	if len(r.Labels) != 1 || r.Labels[0].Vulnerability != "CVE-2018-1000807" {
		t.Errorf("expected only the python label bound, got %d", len(r.Labels))
	}
	if len(r.Skipped) != 1 || !strings.Contains(r.Skipped[0], "python-only") || !strings.Contains(r.Skipped[0], "image-level") {
		t.Errorf("expected the skipped image-level label reported, got %v", r.Skipped)
	}

	// a global label applies only where its package is
	r = pair(t, "deb", nil, global(label("pkg:deb/debian/libxml2@2.7.8.dfsg-2+squeeze1", "CVE-2016-1839", claimsv1.TP)))
	if len(r.Labels) != 0 {
		t.Errorf("a global label on a package the subject lacks was bound")
	}
}

// syft reports Go's standard library at go1.16.9 and its purl at 1.16.9; a label naming the purl
// pairs it
func TestVersionsCompareAsPurls(t *testing.T) {
	stdlib := purl.Package("pkg:golang/stdlib@1.16.9", "go1.16.9")
	if f, _ := purl.Label("pkg:golang/stdlib@1.16.9"); !f.Matches(stdlib) {
		t.Error("expected a label on the purl's version to pair")
	}
	rpm := purl.Package("pkg:rpm/rocky/openssl-libs@3.5.5-2.el9_8?arch=aarch64&epoch=1", "1:3.5.5-2.el9_8")
	if f, _ := purl.Label("pkg:rpm/rocky/openssl-libs@3.5.5-2.el9_8"); f.Matches(rpm) {
		t.Error("expected a label without the epoch not to pair")
	}
}

func TestIDYear(t *testing.T) {
	for id, want := range map[string]int{
		"CVE-2023-1234": 2023, "cve-2021-44228": 2021, "ALAS-2022-1234": 2022, "ELSA-2022-9359": 2022,
		"ALASRUBY3.0-2023-003": 2023, "ALASSELINUX-NG-2023-001": 2023,
		"CVE-1989-0001": 0, "CVE-20231-1": 0, "GHSA-jfh8-c2jp-5v3q": 0, "RHSA-2023:1234": 0, "CVE-2023": 0,
	} {
		if got := idYear(id); got != want {
			t.Errorf("%s: expected %d, got %d", id, want, got)
		}
	}
}

// an advisory label is kept by its alias's year, so it stays with the CVE match it pairs under --by-cve
func TestAliasYear(t *testing.T) {
	r := &Result{aliases: NewAliases(isAdvisory), filter: &gatefile.Vulnerabilities{MaxYear: 2021}, years: map[string]int{}}
	l := label("pkg:rpm/ol/openssl", "ELSA-2022-9137", claimsv1.TP)
	if r.keepsLabel(l) {
		t.Errorf("expected a 2022 advisory with no alias dropped by maxYear 2021")
	}
	l.Aliases = []string{"CVE-2021-3711"}
	if !r.keepsLabel(l) {
		t.Errorf("expected a 2022 advisory aliased to a 2021 CVE kept by maxYear 2021")
	}
}

func TestVulnerabilitiesFilter(t *testing.T) {
	java := func() *models.Document { return scan(t, fixture.Grype("v0.120.1", "java")) }
	filtered := func(f *gatefile.Vulnerabilities, candidate *models.Document, ls ...claims.Label) *Result {
		a := NewAliases(isAdvisory)
		reference := java()
		a.AddScan(candidate)
		a.AddScan(reference)
		a.AddLabels(ls)
		return Pair(a, Subject{Name: "s", Packages: packagesOf(t, sbomPath(t, "java")), Labels: ls,
			Scans: map[string]*models.Document{gatefile.Candidate: candidate, gatefile.Reference: reference}, Vulnerabilities: f})
	}
	vulns := func(r *Result) []string {
		var out []string
		for _, m := range r.Matches {
			out = append(out, m.Vulnerability)
		}
		return slices.Compact(slices.Sorted(slices.Values(out)))
	}

	t.Run("maxYear reads the related CVE of a GHSA", func(t *testing.T) {
		r := filtered(&gatefile.Vulnerabilities{MaxYear: 2024}, java(),
			label(log4j, "GHSA-jfh8-c2jp-5v3q", claimsv1.TP), // CVE-2021-44228
			label(log4j, "GHSA-3pxv-7cmr-fjr4", claimsv1.TP), // CVE-2026-34480
			label(log4j, "GHSA-aaaa-bbbb-cccc", claimsv1.TP), // no year and pairs nothing: kept
			label(log4j, "CVE-2026-0001", claimsv1.TP))
		if got := strings.Join(vulns(r), ","); got != "GHSA-7rjr-3q55-vv33,GHSA-8489-44mv-ggj8,GHSA-jfh8-c2jp-5v3q,GHSA-p6xc-xr62-6r2g" {
			t.Errorf("expected the four 2021 vulnerabilities, got %s", got)
		}
		var labels []string
		for _, b := range r.Labels {
			labels = append(labels, b.Vulnerability)
		}
		if got := strings.Join(labels, ","); got != "GHSA-jfh8-c2jp-5v3q,GHSA-aaaa-bbbb-cccc" {
			t.Errorf("expected the 2021 label and the one with no year, got %s", got)
		}
	})
	t.Run("namespaces drop matches, not labels, and keep row indexes", func(t *testing.T) {
		candidate := java()
		candidate.Matches[0].Vulnerability.Namespace = "nvd:cpe"
		candidate.Matches[1].Vulnerability.Namespace = "nvd:cpe"
		r := filtered(&gatefile.Vulnerabilities{Namespaces: []string{"github:language:java"}}, candidate, label(log4j, "GHSA-jfh8-c2jp-5v3q", claimsv1.TP))
		if b := bound(t, r, "GHSA-jfh8-c2jp-5v3q"); b.PairedIn(gatefile.Candidate) || !b.PairedIn(gatefile.Reference) {
			t.Errorf("expected the label to pair only the reference's matches")
		}
		if m := find(t, r, "GHSA-7rjr-3q55-vv33", "log4j-core"); m.Rows[gatefile.Candidate][0] < 2 {
			t.Errorf("expected the candidate's row index into its scan, got %v", m.Rows[gatefile.Candidate])
		}
		if r := filtered(&gatefile.Vulnerabilities{Namespaces: []string{"nvd:cpe"}}, java()); len(r.Matches) != 0 {
			t.Errorf("expected no matches outside the namespace, got %d", len(r.Matches))
		}
	})
}
