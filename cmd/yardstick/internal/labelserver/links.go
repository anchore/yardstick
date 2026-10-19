package labelserver

import (
	"net/url"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
)

// Link is somewhere a person can go to judge a match.
type Link struct {
	Group string `json:"group"`
	Label string `json:"label"`
	URL   string `json:"url"`
}

// Links collects, for a row: the records each DB cited, lookups for every alias, distro trackers
// and changelogs for the source package, and registry pages for an ecosystem package. Ported from
// delta's labelserver/links.go, less the records' reference URLs, which a report row does not keep.
func Links(m *report.Match) []Link {
	out := []Link{}
	seen := map[string]bool{}
	add := func(group, label, u string) {
		if u == "" || seen[u] || (!strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://")) {
			return
		}
		seen[u] = true
		out = append(out, Link{Group: group, Label: label, URL: u})
	}

	var details []*pairing.Detail
	for _, side := range []struct {
		name string
		d    *pairing.Detail
	}{{"candidate", m.Candidate}, {"reference", m.Reference}} {
		if side.d == nil {
			continue
		}
		details = append(details, side.d)
		add("Records the DBs cited", side.d.Namespace+" ("+side.name+")", side.d.DataSource)
		for _, r := range side.d.Related {
			add("Records the DBs cited", r.ID+" · "+r.Namespace, r.DataSource)
		}
	}

	ids := append([]string{m.Vulnerability}, m.Aliases...)
	for _, id := range ids {
		e := url.PathEscape(id)
		switch {
		case strings.HasPrefix(id, "CVE-"):
			add("Lookups", id+" · NVD", "https://nvd.nist.gov/vuln/detail/"+e)
			add("Lookups", id+" · cve.org", "https://www.cve.org/CVERecord?id="+e)
		case strings.HasPrefix(id, "GHSA-"):
			add("Lookups", id+" · GitHub", "https://github.com/advisories/"+e)
		}
		add("Lookups", id+" · OSV", "https://osv.dev/vulnerability/"+e)
	}

	// an ecosystem package's fix ships upstream, not through the image's distro
	coords := purl.Package(m.Package, "")
	if _, ecosystem := depsDevSystems[coords.Type]; !ecosystem {
		for _, l := range distroLinks(m.SourcePackage, firstCVE(ids), distroOf(details)) {
			add("Distro", l.Label, l.URL)
		}
	}
	for _, l := range packageLinks(coords) {
		add("Package", l.Label, l.URL)
	}
	return out
}

// distroLinks are the distro's trackers and changelogs for a source package.
func distroLinks(srcPkg, cve, distro string) []Link {
	var out []Link
	add := func(label, u string) { out = append(out, Link{Label: label, URL: u}) }
	src := url.PathEscape(srcPkg)
	if distro == "ubuntu" {
		if cve != "" {
			add("Ubuntu CVE tracker", "https://ubuntu.com/security/"+cve)
		}
		add("Ubuntu changelog for "+srcPkg, "https://launchpad.net/ubuntu/+source/"+src+"/+changelog")
		add("Ubuntu publishing history for "+srcPkg, "https://launchpad.net/ubuntu/+source/"+src+"/+publishinghistory")
	}
	if distro == "ubuntu" || distro == "debian" {
		// ubuntu inherits most packages (and fixes) from debian, so debian's view is useful for both
		if cve != "" {
			add("Debian security tracker", "https://security-tracker.debian.org/tracker/"+cve)
		}
		add("Debian tracker for "+srcPkg, "https://tracker.debian.org/pkg/"+src)
		add("Debian changelog for "+srcPkg, "https://metadata.ftp-master.debian.org/changelogs/main/"+debianPrefix(srcPkg)+"/"+src+"/unstable_changelog")
	}
	switch distro {
	case "alpine":
		if cve != "" {
			add("Alpine secdb", "https://security.alpinelinux.org/vuln/"+cve)
		}
	case "redhat", "rhel", "centos", "rocky", "almalinux":
		if cve != "" {
			add("Red Hat CVE page", "https://access.redhat.com/security/cve/"+cve)
		}
	}
	return out
}

const (
	purlMaven = "maven"
	purlPyPI  = "pypi"
)

// depsDevSystems maps purl types to the package systems deps.dev knows.
var depsDevSystems = map[string]string{
	purlMaven: "maven",
	purlPyPI:  "pypi",
	"npm":     "npm",
	"golang":  "go",
	"cargo":   "cargo",
	"nuget":   "nuget",
}

// packageLinks are the registry pages for an ecosystem package: what versions exist, when they
// were released, and (on deps.dev) which advisories affect which versions.
func packageLinks(c purl.Fields) []Link {
	if c.Name == "" || c.Version == "" {
		return nil
	}
	var out []Link
	v := url.PathEscape(c.Version)
	switch c.Type {
	case purlMaven:
		if c.Namespace != "" {
			out = append(out, Link{Label: "Maven Central", URL: "https://central.sonatype.com/artifact/" + url.PathEscape(c.Namespace) + "/" + url.PathEscape(c.Name) + "/" + v})
		}
	case purlPyPI:
		out = append(out, Link{Label: "PyPI", URL: "https://pypi.org/project/" + url.PathEscape(c.Name) + "/" + v + "/"})
	}
	if system, ok := depsDevSystems[c.Type]; ok {
		// deps.dev names maven packages group:artifact, and npm scopes and go modules by full path
		name := c.Name
		switch {
		case c.Type == purlMaven && c.Namespace != "":
			name = c.Namespace + ":" + c.Name
		case c.Namespace != "":
			name = c.Namespace + "/" + c.Name
		}
		out = append(out, Link{Label: "deps.dev", URL: "https://deps.dev/" + system + "/" + url.PathEscape(name) + "/" + v})
	}
	return out
}

func distroOf(details []*pairing.Detail) string {
	for _, d := range details {
		if name, _, _ := strings.Cut(d.Distro, " "); name != "" {
			return strings.ToLower(name)
		}
	}
	return ""
}

func firstCVE(ids []string) string {
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			return id
		}
	}
	return ""
}

// debianPrefix is the pool directory debian uses for a source package (lib packages use 4 letters).
func debianPrefix(src string) string {
	if strings.HasPrefix(src, "lib") && len(src) > 3 {
		return src[:4]
	}
	if src == "" {
		return ""
	}
	return src[:1]
}
