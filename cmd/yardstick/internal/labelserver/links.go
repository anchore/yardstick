package labelserver

import (
	"net/url"
	"slices"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/lookup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
)

// Link is somewhere a person can go to judge a match.
type Link struct {
	Group string `json:"group"`
	// Label says where the link goes ("NVD · CVE-1"), and Note, secondary, what it is ("nvd:cpe, cited
	// by reference").
	Label string `json:"label"`
	Note  string `json:"note,omitempty"`
	URL   string `json:"url"`
}

// Links collects, for a row, in the order the Evidence tab shows them: distro trackers and
// changelogs for the source package, and the distro's records; the records each DB cited; lookups
// for every alias; and registry pages for an ecosystem package. Ported from
// delta's labelserver/links.go, less the records' reference URLs, which a report row does not keep.
func Links(m *report.Match) []Link {
	out := []Link{}
	// each group is complete on its own: a lookup stays though a cited record has the same URL
	seen := map[string]bool{}
	put := func(l Link) {
		if l.URL == "" || seen[l.Group+" "+l.URL] || (!strings.HasPrefix(l.URL, "https://") && !strings.HasPrefix(l.URL, "http://")) {
			return
		}
		seen[l.Group+" "+l.URL] = true
		out = append(out, l)
	}
	add := func(group, label, u string) { put(Link{Group: group, Label: label, URL: u}) }
	// record links a DB record's page: the site and the id, then what the record is
	record := func(group, id, note, u string) {
		put(Link{Group: group, Label: siteName(u) + " · " + id, Note: note, URL: u})
	}

	type cited struct {
		name string
		d    *pairing.Detail
	}
	var sides []cited
	var details []*pairing.Detail
	for _, side := range []cited{{"candidate", m.Candidate}, {"reference", m.Reference}} {
		if side.d != nil {
			sides = append(sides, side)
			details = append(details, side.d)
		}
	}
	ids := append([]string{m.Vulnerability}, m.Aliases...)

	// the distro's own pages first: for a distro package they say most about whether it is affected.
	// An ecosystem package's fix ships upstream, not through the image's distro.
	coords := purl.Package(m.Package, "")
	if _, ecosystem := depsDevSystems[coords.Type]; !ecosystem {
		// the scanned distro, else the purl's: a grype that doesn't know the distro reports none
		dist := lookup.PurlOS(m.Package)
		distro := distroOf(details)
		if distro == "" {
			distro = dist.Name
		}
		for _, l := range distroLinks(m.SourcePackage, firstCVE(ids), distro) {
			add("Distro", l.Label, l.URL)
		}
		// the distro's own records of the package, as the other DB has them: the page for a distro
		// distroLinks has no pattern for, or one keyed by its advisory (ALAS, ELSA)
		for _, r := range append(slices.Clone(m.CandidateRecords), m.ReferenceRecords...) {
			if dist.Has(r.Namespace) {
				record("Distro", r.Vulnerability, r.Namespace, r.DataSource)
			}
		}
	}

	for _, side := range sides {
		record("Records the DBs cited", m.Vulnerability, side.d.Namespace+", cited by "+side.name, side.d.DataSource)
		for _, r := range side.d.Related {
			record("Records the DBs cited", r.ID, r.Namespace+", related, cited by "+side.name, r.DataSource)
		}
	}

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
	// each pattern is the one the distro's records in the grype DB cite
	if cve == "" {
		return out
	}
	switch distro {
	case "alpine":
		add("Alpine secdb", "https://security.alpinelinux.org/vuln/"+cve)
	case "redhat", "rhel", "centos", "rocky", "almalinux", "hummingbird":
		add("Red Hat CVE page", "https://access.redhat.com/security/cve/"+cve)
	case "wolfi", "chainguard":
		add("Chainguard security page", "https://images.chainguard.dev/security/"+cve)
	case "secureos":
		add("SecureOS security page", "https://security.secureos.io/"+cve)
	case "sles":
		add("SUSE CVE page", "https://www.suse.com/security/cve/"+cve)
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

// sites names the sites records link to, by host (and path, where a host serves several)
var sites = []struct{ prefix, name string }{
	{"nvd.nist.gov", "NVD"},
	{"github.com/advisories", "GitHub"},
	{"security-tracker.debian.org", "Debian"},
	{"ubuntu.com", "Ubuntu"},
	{"security.alpinelinux.org", "Alpine"},
	{"access.redhat.com", "Red Hat"},
	{"images.chainguard.dev", "Chainguard"},
	{"security.secureos.io", "SecureOS"},
	{"www.suse.com", "SUSE"},
	{"alas.aws.amazon.com", "Amazon Linux"},
	{"linux.oracle.com", "Oracle Linux"},
	{"security.archlinux.org", "Arch Linux"},
	{"bodhi.fedoraproject.org", "Fedora"},
	{"www.cve.org", "cve.org"},
	{"osv.dev", "OSV"},
}

// siteName is the site a URL goes to, by name where known, else its host.
func siteName(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	at := p.Host + p.Path
	for _, s := range sites {
		if strings.HasPrefix(at, s.prefix) {
			return s.name
		}
	}
	return p.Host
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
