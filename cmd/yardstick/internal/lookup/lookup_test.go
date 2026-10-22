package lookup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
)

// trimmed from `grype db search --vuln CVE-2018-20796 --pkg glibc -o json` (grype v0.120.1), as
// delta's test has it
const affectedOutput = `[
 {"vulnerability": {"id": "CVE-2018-20796", "provider": "ubuntu", "status": "active", "refs": [{"url": "https://ubuntu.com/security/CVE-2018-20796"}]},
  "packages": [
   {"os": {"name": "ubuntu", "version": "20.04"}, "package": {"name": "glibc", "ecosystem": "deb"},
    "namespace": "ubuntu:distro:ubuntu:20.04",
    "detail": {"ranges": [{"version": {"type": "dpkg"}, "fix": {"state": "wont-fix"}}]}}
  ]},
 {"vulnerability": {"id": "CVE-2018-20796", "provider": "mariner"},
  "packages": [
   {"package": {"name": "glibc", "ecosystem": "rpm"}, "namespace": "mariner:distro:mariner:1.0",
    "detail": {"ranges": [{"version": {"type": "rpm", "constraint": "< 0:2.28-12.cm1"},
      "fix": {"version": "0:2.28-12.cm1", "state": "fixed", "detail": {"available": {"date": "2020-10-08"}}}}]}}
  ]},
 {"vulnerability": {"id": "CVE-2023-28434"},
  "packages": [
   {"cpe": "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*", "namespace": "nvd:cpe",
    "detail": {"cves": ["CVE-2023-28434"], "ranges": [{"version": {"constraint": "< 2023-03-20t20-16-18z"}, "fix": {"version": "2023-03-20t20-16-18z", "state": "fixed"}}]}}
  ]}
]`

func TestParseAffected(t *testing.T) {
	got, err := parseAffected([]byte(affectedOutput))
	if err != nil {
		t.Fatal(err)
	}
	want := []Affected{
		{Vulnerability: "CVE-2018-20796", Namespace: "ubuntu:distro:ubuntu:20.04", Package: "glibc", Ecosystem: "deb", FixStates: []string{"wont-fix"},
			DataSource: "https://ubuntu.com/security/CVE-2018-20796"},
		{Vulnerability: "CVE-2018-20796", Namespace: "mariner:distro:mariner:1.0", Package: "glibc", Ecosystem: "rpm",
			FixStates: []string{"fixed"}, FixVersions: []string{"0:2.28-12.cm1"}, Constraints: []string{"< 0:2.28-12.cm1"}},
		{Vulnerability: "CVE-2023-28434", Namespace: "nvd:cpe", CPE: "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*",
			FixStates: []string{"fixed"}, FixVersions: []string{"2023-03-20t20-16-18z"}, Constraints: []string{"< 2023-03-20t20-16-18z"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("want %+v\ngot  %+v", want, got)
	}
}

func TestParseStatuses(t *testing.T) {
	data := []byte(`[
		{"id":"GHSA-3mq5-fq9h-gj7j","provider":"github","status":"rejected"},
		{"id":"CVE-1","provider":"debian","status":"active"},
		{"id":"CVE-1","provider":"nvd","status":"rejected"},
		{"id":"CVE-1","provider":"ubuntu","status":""},
		{"id":"CVE-2","provider":"alpine","status":""}
	]`)
	got := map[string]string{"GHSA-3mq5-fq9h-gj7j": NotInDB, "CVE-1": NotInDB, "CVE-2": NotInDB, "CVE-3": NotInDB}
	if err := parseStatuses(data, got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"GHSA-3mq5-fq9h-gj7j": "rejected",
		"CVE-1":               "rejected", // the strongest status across records wins
		"CVE-2":               "active",   // providers without a status
		"CVE-3":               NotInDB,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

// a DB is asked for the status of every one-sided row's ids, and for the records of only the rows
// the other setup reported: by package and source package, or by CPE for a CPE match, and for a
// CPE match on a distro package by its names in its distro too
func TestSearch(t *testing.T) {
	row := func(id, setup, vuln, name, purl string, d *pairing.Detail) Row {
		return Row{ID: id, Match: &pairing.Match{Identity: pairing.Identity{PackageID: id, Group: vuln}, Vulnerability: vuln, Package: pairing.Package{Name: name, PURL: purl},
			Rows: map[string][]int{setup: {0}}, Details: map[string]*pairing.Detail{setup: d}}}
	}
	rows := []Row{
		row("a", pairing.Reference, "CVE-2018-20796", "libc6", "pkg:deb/ubuntu/libc6@2.31?distro=ubuntu-20.04", &pairing.Detail{Upstreams: []string{"glibc"}, MatchTypes: []string{"exact-indirect-match"}}),
		row("b", pairing.Reference, "CVE-2023-28434", "minio", "pkg:golang/github.com/minio/minio@7.0.30", &pairing.Detail{MatchTypes: []string{"cpe-match"}, CPEs: []string{"cpe:2.3:a:minio:minio:7.0.30:*:*:*:*:*:*:*"}}),
		row("c", pairing.Candidate, "CVE-3", "zlib", "", &pairing.Detail{MatchTypes: []string{"exact-direct-match"}}),
		row("d", pairing.Reference, "CVE-2026-4438", "glibc-2.42", "pkg:apk/secureos/glibc-2.42@2.42-r4?arch=x86_64&distro=secureos-2025.09.09",
			&pairing.Detail{MatchTypes: []string{"cpe-match"}, CPEs: []string{"cpe:2.3:a:gnu:glibc:2.42:*:*:*:*:*:*:*"}}),
	}
	var calls []string
	grype := func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		if args[2] == "vuln" {
			return []byte(`[{"id":"CVE-2018-20796","status":"active"}]`), nil
		}
		return []byte(affectedOutput), nil
	}
	f, err := Search(context.Background(), grype, pairing.Candidate, rows)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"db search vuln -o json --limit 0 CVE-2018-20796 CVE-2023-28434 CVE-2026-4438 CVE-3",
		"db search -o json --limit 0 --vuln CVE-2018-20796 --pkg glibc --pkg libc6",
		"db search -o json --limit 0 --vuln CVE-2023-28434 --vuln CVE-2026-4438 --pkg cpe:2.3:a:gnu:glibc:2.42:*:*:*:*:*:*:* --pkg cpe:2.3:a:minio:minio:7.0.30:*:*:*:*:*:*:* --broad-cpe-matching",
		"db search -o json --limit 0 --vuln CVE-2026-4438 --pkg glibc-2.42 --distro secureos:2025.09",
	}
	if !slices.Equal(calls, want) {
		t.Errorf("want calls\n%s\ngot\n%s", strings.Join(want, "\n"), strings.Join(calls, "\n"))
	}
	if f.Statuses["CVE-2018-20796"] != "active" || f.Statuses["CVE-3"] != NotInDB {
		t.Errorf("expected each id's status, NotInDB when the DB has none, got %v", f.Statuses)
	}
	if !f.Looked("a") || !f.Looked("b") || f.Looked("c") || !f.Looked("d") {
		t.Errorf("expected only the reference's rows looked up in the candidate DB, got %+v", f.Queries)
	}
	if len(f.Records) != 3 {
		t.Errorf("expected the records deduplicated across queries, got %+v", f.Records)
	}
}

// a package's distro is its purl's, to the minor release, as grype's --distro takes it, and holds
// the namespaces of the release it falls in or a rolling one
func TestPackageOS(t *testing.T) {
	os := func(purl string) OS { return PackageOS(&pairing.Match{Package: pairing.Package{PURL: purl}}) }
	tests := []struct {
		purl   string
		search string
		has    []string
		hasNot []string
	}{
		{"pkg:apk/secureos/glibc-2.42@2.42-r4?arch=x86_64&distro=secureos-2025.09.09", "secureos:2025.09",
			[]string{"secureos:distro:secureos:rolling"}, []string{"nvd:cpe", "wolfi:distro:wolfi:rolling"}},
		{"pkg:deb/ubuntu/libc6@2.31?distro=ubuntu-20.04", "ubuntu:20.04",
			[]string{"ubuntu:distro:ubuntu:20.04"}, []string{"ubuntu:distro:ubuntu:22.04", "debian:distro:debian:12"}},
		{"pkg:rpm/redhat/glibc@2.34?distro=rhel-9.3", "rhel:9.3", []string{"redhat:distro:redhat:9"}, []string{"redhat:distro:redhat:8"}},
		{"pkg:golang/github.com/minio/minio@7.0.30", "", nil, []string{"nvd:cpe", "wolfi:distro:wolfi:rolling"}},
	}
	for _, tt := range tests {
		o := os(tt.purl)
		if o.Search != tt.search {
			t.Errorf("%s: want search %q, got %+v", tt.purl, tt.search, o)
		}
		for _, ns := range tt.has {
			if !o.Has(ns) {
				t.Errorf("%s: expected %s to hold its records", tt.purl, ns)
			}
		}
		for _, ns := range tt.hasNot {
			if o.Has(ns) {
				t.Errorf("%s: expected %s not to hold its records", tt.purl, ns)
			}
		}
	}
}

// a distro's "fixed in 0" is a record saying the package was never affected
func TestNotAffected(t *testing.T) {
	nak := Affected{Constraints: []string{"< 0"}, FixStates: []string{"fixed"}, FixVersions: []string{"0"}}
	fixed := Affected{Constraints: []string{"< 2.42-r5"}, FixStates: []string{"fixed"}, FixVersions: []string{"2.42-r5"}}
	notFixed := Affected{FixStates: []string{"not-fixed"}}
	if !nak.NotAffected() || fixed.NotAffected() || notFixed.NotAffected() {
		t.Errorf("expected only fixed in 0 to say not affected")
	}
}

// a loaded file answers Looked from an index of its queries' rows
func TestLoadIndexesLookedRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lookups.json")
	data, _ := json.Marshal(File{Version: Version, Queries: []Query{{Rows: []string{"a", "b"}}, {Rows: []string{"c"}}}})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.looked) != 3 || !f.Looked("c") || f.Looked("d") {
		t.Errorf("expected the three rows indexed, got %v", f.looked)
	}
}
