package labelserver

import (
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/lookup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
)

func TestLinksForUbuntuPackage(t *testing.T) {
	m := &report.Match{Vulnerability: "CVE-1", Aliases: []string{"CVE-1", "GHSA-x"}, SourcePackage: "libx11", Package: "pkg:deb/ubuntu/libx11-6@1.6.9",
		Candidate: &pairing.Detail{Distro: "ubuntu 20.04", DataSource: "https://ubuntu.com/security/CVE-1", Related: []pairing.Related{{ID: "CVE-1", DataSource: "javascript:alert(1)"}}}}
	urls := map[string]bool{}
	for _, l := range Links(m) {
		urls[l.URL] = true
	}
	for _, want := range []string{
		"https://ubuntu.com/security/CVE-1",
		"https://nvd.nist.gov/vuln/detail/CVE-1",
		"https://github.com/advisories/GHSA-x",
		"https://launchpad.net/ubuntu/+source/libx11/+changelog",
		"https://security-tracker.debian.org/tracker/CVE-1",
		"https://metadata.ftp-master.debian.org/changelogs/main/libx/libx11/unstable_changelog",
	} {
		if !urls[want] {
			t.Errorf("missing link %s", want)
		}
	}
	if urls["javascript:alert(1)"] {
		t.Error("non-http links must be dropped")
	}
}

func TestPackageLinksForAnEcosystemPackage(t *testing.T) {
	links := Links(&report.Match{Vulnerability: "GHSA-y", Package: "pkg:maven/org.eclipse.jetty/jetty-server@9.4.1", SourcePackage: "org.eclipse.jetty"})
	urls := map[string]bool{}
	for _, l := range links {
		urls[l.URL] = true
	}
	for _, want := range []string{
		"https://central.sonatype.com/artifact/org.eclipse.jetty/jetty-server/9.4.1",
		"https://deps.dev/maven/org.eclipse.jetty:jetty-server/9.4.1",
	} {
		if !urls[want] {
			t.Errorf("missing link %s in %v", want, links)
		}
	}
	for u := range urls {
		if u == "https://tracker.debian.org/pkg/org.eclipse.jetty" {
			t.Error("an ecosystem package gets no distro links")
		}
	}
}

// a distro package links to its distro's page for the CVE, and to the distro records the other DB
// has for it, where their page follows no pattern (an Amazon advisory)
func TestLinksForADistroPackage(t *testing.T) {
	urls := func(m *report.Match) map[string]bool {
		out := map[string]bool{}
		for _, l := range Links(m) {
			out[l.URL] = true
		}
		return out
	}
	// a CPE match only the reference reported, which the candidate's secureos record says is not affected
	got := urls(&report.Match{Vulnerability: "CVE-2026-4438", SourcePackage: "glibc-2.42", Package: "pkg:apk/secureos/glibc-2.42@2.42-r4?arch=x86_64&distro=secureos-2025.09.09",
		Reference: &pairing.Detail{Namespace: "nvd:cpe", DataSource: "https://nvd.nist.gov/vuln/detail/CVE-2026-4438"},
		CandidateRecords: []lookup.Affected{
			{Vulnerability: "CVE-2026-4438", Namespace: "nvd:cpe", DataSource: "https://nvd.nist.gov/vuln/detail/CVE-2026-4438"},
			{Vulnerability: "CVE-2026-4438", Namespace: "secureos:distro:secureos:rolling", Package: "glibc-2.42", DataSource: "https://security.secureos.io/CVE-2026-4438?record"},
		}})
	// grype v0.100.0 reports no distro for the secureos image: the purl's names it
	if !got["https://security.secureos.io/CVE-2026-4438"] || !got["https://security.secureos.io/CVE-2026-4438?record"] {
		t.Errorf("expected the SecureOS page and the record's, got %v", got)
	}

	for distro, want := range map[string]string{
		"wolfi 20230201": "https://images.chainguard.dev/security/CVE-1",
		"chainguard 1":   "https://images.chainguard.dev/security/CVE-1",
		"alpine 3.18.4":  "https://security.alpinelinux.org/vuln/CVE-1",
		"rhel 9.3":       "https://access.redhat.com/security/cve/CVE-1",
		"sles 15.6":      "https://www.suse.com/security/cve/CVE-1",
	} {
		if got := urls(&report.Match{Vulnerability: "CVE-1", SourcePackage: "x", Package: "pkg:apk/x/x@1", Candidate: &pairing.Detail{Distro: distro}}); !got[want] {
			t.Errorf("%s: expected %s, got %v", distro, want, got)
		}
	}

	got = urls(&report.Match{Vulnerability: "CVE-2022-32221", SourcePackage: "curl", Package: "pkg:rpm/amazon/curl@7.87.0-2.amzn2023.0.1?distro=amzn-2023",
		Reference: &pairing.Detail{Namespace: "nvd:cpe", Distro: "amzn 2023"},
		CandidateRecords: []lookup.Affected{
			{Vulnerability: "ALAS2023-2023-083", Namespace: "amazon:distro:amazonlinux:2023", Package: "curl", DataSource: "https://alas.aws.amazon.com/AL2023/ALAS2023-2023-083.html"},
			{Vulnerability: "ALAS2-2023-1", Namespace: "amazon:distro:amazonlinux:2", Package: "curl", DataSource: "https://alas.aws.amazon.com/AL2/ALAS2-2023-1.html"},
		}})
	if !got["https://alas.aws.amazon.com/AL2023/ALAS2023-2023-083.html"] || got["https://alas.aws.amazon.com/AL2/ALAS2-2023-1.html"] {
		t.Errorf("expected only the Amazon Linux 2023 advisory, got %v", got)
	}
}
