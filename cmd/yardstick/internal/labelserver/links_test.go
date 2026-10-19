package labelserver

import (
	"testing"

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
