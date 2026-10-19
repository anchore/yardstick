package pairing

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

var advisories = []string{"ALAS*", "ALSA", "ELSA", "RLSA", "RHSA"}

func isAdvisory(id string) bool {
	v := labels.Vocabulary{AdvisoryIDs: advisories}
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
func label(pkg, vuln string, v labels.Verdict) claims.Label {
	l := claims.Label{Label: labels.Label{Package: pkg, Vulnerability: vuln, Verdict: v}, File: "deb.json"}
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
		Scans: map[string]*models.Document{Candidate: candidate, Reference: reference}})
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
		r := pair(t, "java", candidate, label(log4j, "CVE-2021-44228", labels.TP))
		b := bound(t, r, "CVE-2021-44228")
		if !b.PairedIn(Candidate) || !b.PairedIn(Reference) || len(b.Matches) != 2 {
			t.Errorf("expected the label to pair GHSA-jfh8-c2jp-5v3q in both setups, paired %d matches", len(b.Matches))
		}
		if g := r.aliases.Group("GHSA-jfh8-c2jp-5v3q"); g != r.aliases.Group("CVE-2021-44228") {
			t.Errorf("expected one group, got %s", g)
		}
	})
	t.Run("an id neither setup reported", func(t *testing.T) {
		r := pair(t, "java", nil, label(log4j, "CVE-2020-9999", labels.TP))
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
			r := pair(t, tc.image, nil, label(tc.pkg, tc.vuln, labels.TP))
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
	r := pair(t, "java", nil, label(log4j, "CVE-2021-44228", labels.TP))
	b := bound(t, r, "CVE-2021-44228")
	if len(b.Matches) != 2 || b.Matches[0].PackageID == b.Matches[1].PackageID {
		t.Fatalf("expected the label to pair the match in both jars, paired %d", len(b.Matches))
	}
	for _, m := range b.Matches {
		if m.Verdict != labels.TP {
			t.Errorf("expected each match to take tp, got %q", m.Verdict)
		}
	}
}

func TestMostSpecificLabelWins(t *testing.T) {
	const ncurses = "pkg:deb/debian/ncurses-base@6.4-4"
	for _, tc := range []struct {
		name   string
		labels []claims.Label
		want   labels.Verdict
	}{
		{"subject over global", []claims.Label{global(label(ncurses, "CVE-2023-50495", labels.FP)), label(ncurses, "CVE-2023-50495", labels.TP)}, labels.TP},
		{"versioned over versionless", []claims.Label{label("pkg:deb/debian/ncurses-base", "CVE-2023-50495", labels.TP), label(ncurses, "CVE-2023-50495", labels.FP)}, labels.FP},
		{"only unclear", []claims.Label{label(ncurses, "CVE-2023-50495", labels.Unclear)}, ""},
		{"two sources disagree", []claims.Label{func() claims.Label {
			l := label(ncurses, "CVE-2023-50495", labels.TP)
			l.Held = append(l.Held, claims.SourceVerdict{Source: "local", Verdict: labels.FP})
			return l
		}()}, ""},
		{"equally specific labels disagree", []claims.Label{label("pkg:deb/debian/ncurses-base@6.4-4", "CVE-2023-50495", labels.TP), label("pkg:deb/debian/ncurses-base?arch=all", "CVE-2023-50495", labels.FP)}, ""},
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

	r := pairScans(t, sbom, ol(), ol(), label("pkg:rpm/ol/openssl", "CVE-2022-0778", labels.TP))
	if m := find(t, r, "ELSA-2022-9246", "openssl"); m.Verdict != labels.TP || len(m.Addresses) != 1 {
		t.Errorf("expected the one-CVE advisory to pair its CVE, got %q over %v", m.Verdict, m.Addresses)
	}
	for _, w := range r.Warnings {
		if strings.Contains(w, "ELSA-2022-9246") {
			t.Errorf("a one-CVE advisory warned: %s", w)
		}
	}

	r = pairScans(t, sbom, ol(), ol(),
		label("pkg:rpm/ol/expat", "CVE-2022-25235", labels.TP),
		label("pkg:rpm/ol/expat", "CVE-2022-25236", labels.TP))
	m := find(t, r, "ELSA-2022-9359", "expat")
	if len(m.Paired) != 2 || m.Verdict != labels.TP {
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
			if !m.In(Candidate) || !m.In(Reference) {
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
			if !m.In(Candidate) || !m.In(Reference) {
				t.Errorf("%s on %s is in one setup only", m.Vulnerability, m.PackageID)
			}
		}
	})
}

func TestFilteredSubjectBindsItsPackages(t *testing.T) {
	sbom := sbomPath(t, "oracle")
	ol := scan(t, fixture.Path("vml", "grype-oraclelinux.json"))
	ls := []claims.Label{
		label("pkg:rpm/ol/expat", "CVE-2022-40674", labels.TP),
		label("", "CVE-2022-0778", labels.TP),
		label("pkg:pypi/pyopenssl", "CVE-2018-1000807", labels.TP),
	}
	a := NewAliases(isAdvisory)
	a.AddScan(ol)
	a.AddLabels(ls)
	r := Pair(a, Subject{Name: "python-only", Packages: packagesOf(t, sbom, "python"), Filtered: true, Labels: ls,
		Scans: map[string]*models.Document{Candidate: ol}})
	if len(r.Labels) != 1 || r.Labels[0].Vulnerability != "CVE-2018-1000807" {
		t.Errorf("expected only the python label bound, got %d", len(r.Labels))
	}
	if len(r.Skipped) != 1 || !strings.Contains(r.Skipped[0], "python-only") || !strings.Contains(r.Skipped[0], "image-level") {
		t.Errorf("expected the skipped image-level label reported, got %v", r.Skipped)
	}

	// a global label applies only where its package is
	r = pair(t, "deb", nil, global(label("pkg:deb/debian/libxml2@2.7.8.dfsg-2+squeeze1", "CVE-2016-1839", labels.TP)))
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
