package report

import (
	"reflect"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/lookup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
)

// ported from delta's TestWhy, one row per reason
func TestWhy(t *testing.T) {
	const ns = "ubuntu:distro:ubuntu:20.04"
	found := func(fix string, constraints ...string) *pairing.Detail {
		return &pairing.Detail{Namespace: ns, FixState: fix, Constraints: constraints, MatchTypes: []string{"exact-indirect-match"}}
	}
	rec := func(namespace string, fix string, constraints ...string) lookup.Affected {
		return lookup.Affected{Vulnerability: "CVE-1", Namespace: namespace, Package: "glibc", FixStates: []string{fix}, Constraints: constraints}
	}
	cpeMatch := func(constraint string) *pairing.Detail {
		return &pairing.Detail{Namespace: "nvd:cpe", FixState: "fixed", Constraints: []string{constraint}, MatchTypes: []string{"cpe-match"},
			CPEs: []string{"cpe:2.3:a:minio:minio:7.0.30:*:*:*:*:*:*:*"}}
	}
	cpeRec := func(constraint string) lookup.Affected {
		return lookup.Affected{Vulnerability: "CVE-1", Namespace: "nvd:cpe", CPE: "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*", FixStates: []string{"fixed"}, Constraints: []string{constraint}}
	}
	// a CPE match on a secureos package, which the candidate's distro record says is not affected
	const secureosPURL = "pkg:apk/secureos/glibc@2.42-r4?arch=x86_64&distro=secureos-2025.09.09"
	glibcCPE := &pairing.Detail{Namespace: "nvd:cpe", Constraints: []string{"< 2.43 (unknown)"}, MatchTypes: []string{"cpe-match"},
		CPEs: []string{"cpe:2.3:a:gnu:glibc:2.42:*:*:*:*:*:*:*"}}
	glibcCPERec := lookup.Affected{Vulnerability: "CVE-1", Namespace: "nvd:cpe", CPE: "cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*", Constraints: []string{"< 2.43"}}
	nak := lookup.Affected{Vulnerability: "CVE-1", Namespace: "secureos:distro:secureos:rolling", Package: "glibc",
		Constraints: []string{"< 0"}, FixStates: []string{"fixed"}, FixVersions: []string{"0"}}
	// searched is a DB whose records were looked up for the row
	searched := func(recs ...lookup.Affected) *lookup.File {
		return &lookup.File{Statuses: map[string]string{"CVE-1": "active"}, Queries: []lookup.Query{{Rows: []string{"r"}}}, Records: recs}
	}
	status := func(s string) *lookup.File { return &lookup.File{Statuses: map[string]string{"CVE-1": s}} }

	tests := []struct {
		name      string
		reference bool // reported by the reference, else by the candidate
		detail    *pairing.Detail
		lookups   map[string]*lookup.File
		purl      string
		want      *Why
	}{
		{
			name:    "rejected comes first",
			detail:  found("not-fixed"),
			lookups: map[string]*lookup.File{gatefile.Candidate: status("rejected"), gatefile.Reference: status(lookup.NotInDB)},
			want:    &Why{Key: WhyRejectedInCandidate, Secondary: []Reason{{Key: WhyAbsentInReference, To: ns}}},
		},
		{
			name:    "a new record",
			detail:  found("not-fixed"),
			lookups: map[string]*lookup.File{gatefile.Reference: status(lookup.NotInDB)},
			want:    &Why{Key: WhyAbsentInReference, To: ns},
		},
		{
			name:      "gone from the candidate DB",
			reference: true,
			detail:    found("not-fixed"),
			lookups:   map[string]*lookup.File{gatefile.Candidate: status(lookup.NotInDB)},
			want:      &Why{Key: WhyAbsentInCandidate, From: ns},
		},
		{
			name:    "no record for this release",
			detail:  found("wont-fix"),
			lookups: map[string]*lookup.File{gatefile.Reference: searched(rec("ubuntu:distro:ubuntu:19.04", "not-fixed"))},
			want:    &Why{Key: WhyPackageAbsentInRef, To: ns},
		},
		{
			name:    "moved between providers",
			detail:  found("not-fixed"),
			lookups: map[string]*lookup.File{gatefile.Reference: searched(rec("echo:distro:ubuntu:20.04", "not-fixed"))},
			want:    &Why{Key: WhyNamespaceChanged, From: "echo:distro:ubuntu:20.04", To: ns},
		},
		{
			name:    "fix state changed, and the constraint with it",
			detail:  found("wont-fix", "none (unknown)"),
			lookups: map[string]*lookup.File{gatefile.Reference: searched(rec(ns, "fixed", "< 2.31-0ubuntu9.9"))},
			want:    &Why{Key: WhyFixStateChanged, From: "fixed", To: "wont-fix", Secondary: []Reason{{Key: WhyConstraintChanged, From: "< 2.31-0ubuntu9.9"}}},
		},
		{
			name:    "constraint changed",
			detail:  found("fixed", "< 2.31-0ubuntu9.9 (deb)"),
			lookups: map[string]*lookup.File{gatefile.Reference: searched(rec(ns, "fixed", "< 2.31-0ubuntu9.7"))},
			want:    &Why{Key: WhyConstraintChanged, From: "< 2.31-0ubuntu9.7", To: "< 2.31-0ubuntu9.9"},
		},
		{
			name:    "same record, but the other grype didn't match",
			detail:  found("not-fixed", "none (unknown)"),
			lookups: map[string]*lookup.File{gatefile.Reference: searched(rec(ns, "not-fixed"))},
			want:    &Why{Key: WhySameButUnmatched},
		},
		{
			name:   "records aren't compared unless looked up: a run before lookups",
			detail: found("not-fixed"),
			want:   &Why{Key: WhyUnexplained},
		},
		{
			name: "grype's joined ranges are the record's ranges, and no fix state is none",
			detail: &pairing.Detail{Namespace: "nvd:cpe", Constraints: []string{"< 7.6.5||>= 8.0.0, < 8.6.6 (unknown)"}, MatchTypes: []string{"cpe-match"},
				CPEs: []string{"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}},
			lookups: map[string]*lookup.File{gatefile.Reference: searched(lookup.Affected{Vulnerability: "CVE-1", Namespace: "nvd:cpe", CPE: "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*",
				Constraints: []string{">= 8.0.0, < 8.6.6", "< 7.6.5"}})},
			want: &Why{Key: WhySameButUnmatched, Secondary: []Reason{{Key: WhyCPEOnly}}},
		},
		{
			name:   "a CPE match not looked up",
			detail: cpeMatch("< 2023-03-20t20-16-18z (unknown)"),
			want:   &Why{Key: WhyCPEOnly},
		},
		{
			name:    "the same CPE record, not matched by the other side",
			detail:  cpeMatch("< 2023-03-20t20-16-18z (unknown)"),
			lookups: map[string]*lookup.File{gatefile.Reference: searched(cpeRec("< 2023-03-20t20-16-18z"))},
			want:    &Why{Key: WhySameButUnmatched, Secondary: []Reason{{Key: WhyCPEOnly}}},
		},
		{
			name:      "the other DB's distro says the package is not affected: fixed in 0",
			reference: true,
			detail:    glibcCPE,
			lookups:   map[string]*lookup.File{gatefile.Candidate: searched(glibcCPERec, nak)},
			purl:      secureosPURL,
			want: &Why{Key: WhyDistroNotAffected, To: "secureos:distro:secureos:rolling",
				Secondary: []Reason{{Key: WhySameButUnmatched}, {Key: WhyCPEOnly}}},
		},
		{
			name:      "a distro record that is not a NAK explains nothing",
			reference: true,
			detail:    glibcCPE,
			lookups: map[string]*lookup.File{gatefile.Candidate: searched(glibcCPERec, lookup.Affected{Vulnerability: "CVE-1", Namespace: "secureos:distro:secureos:rolling", Package: "glibc",
				Constraints: []string{"< 2.42-r5"}, FixStates: []string{"fixed"}, FixVersions: []string{"2.42-r5"}})},
			purl: secureosPURL,
			want: &Why{Key: WhySameButUnmatched, Secondary: []Reason{{Key: WhyCPEOnly}}},
		},
		{
			name:      "a NAK in another distro explains nothing",
			reference: true,
			detail:    glibcCPE,
			lookups:   map[string]*lookup.File{gatefile.Candidate: searched(glibcCPERec, nak)},
			purl:      "pkg:apk/wolfi/glibc@2.42-r4?distro=wolfi-20230201",
			want:      &Why{Key: WhySameButUnmatched, Secondary: []Reason{{Key: WhyCPEOnly}}},
		},
		{
			name:    "the CPE record's range changed",
			detail:  cpeMatch("< 2023-03-20t20-16-18z (unknown)"),
			lookups: map[string]*lookup.File{gatefile.Reference: searched(cpeRec("< 2022-01-01"))},
			want:    &Why{Key: WhyConstraintChanged, From: "< 2022-01-01", To: "< 2023-03-20t20-16-18z", Secondary: []Reason{{Key: WhyCPEOnly}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := gatefile.Candidate
			if tt.reference {
				setup = gatefile.Reference
			}
			m := &pairing.Match{Identity: pairing.Identity{PackageID: "p", Group: "CVE-1"}, Vulnerability: "CVE-1", Package: pairing.Package{Name: "glibc", PURL: tt.purl},
				Rows: map[string][]int{setup: {0}}, Details: map[string]*pairing.Detail{setup: tt.detail}}
			row := Match{Row: "r", InCandidate: !tt.reference, InReference: tt.reference}
			explain(&row, m, tt.lookups)
			if !reflect.DeepEqual(row.Why, tt.want) {
				t.Errorf("want %+v, got %+v", tt.want, row.Why)
			}
		})
	}
}

// only the other DB's records about one of the row's ids, its package and its ecosystem are
// attached, and a CPE match's by CPE product
func TestRelatedRecords(t *testing.T) {
	d := &pairing.Detail{Namespace: "github:language:javascript"}
	got := related([]lookup.Affected{
		{Vulnerability: "CVE-1", Namespace: "github:language:javascript", Package: "lodash", FixStates: []string{"fixed"}},
		{Vulnerability: "CVE-1", Namespace: "github:language:python", Package: "lodash"},
		{Vulnerability: "CVE-2", Namespace: "github:language:javascript", Package: "lodash"},
	}, d, []string{"GHSA-1", "CVE-1"}, []string{"lodash"}, lookup.OS{})
	if len(got) != 1 || got[0].Namespace != "github:language:javascript" || got[0].Vulnerability != "CVE-1" {
		t.Errorf("expected only the javascript lodash record for an alias of the row, got %+v", got)
	}

	cpe := &pairing.Detail{Namespace: "nvd:cpe", MatchTypes: []string{"cpe-match"}, CPEs: []string{"cpe:2.3:a:minio:minio:7.0.30:*:*:*:*:*:*:*"}}
	got = related([]lookup.Affected{
		{Vulnerability: "CVE-2023-28434", Namespace: "nvd:cpe", CPE: "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*"},
		{Vulnerability: "CVE-2023-28434", Namespace: "nvd:cpe", CPE: "cpe:2.3:a:minio:console:*:*:*:*:*:*:*:*"},
		{Vulnerability: "CVE-2023-28434", Namespace: "wolfi:distro:wolfi:rolling", Package: "minio"},
	}, cpe, []string{"CVE-2023-28434"}, []string{"minio"}, lookup.OS{})
	if len(got) != 1 || got[0].CPE != "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*" {
		t.Errorf("expected only the minio:minio CPE record, got %+v", got)
	}

	// a CPE match on a distro package keeps its distro's records for the package, a NAK included
	glibc := &pairing.Detail{Namespace: "nvd:cpe", MatchTypes: []string{"cpe-match"}, CPEs: []string{"cpe:2.3:a:gnu:glibc:2.42:*:*:*:*:*:*:*"}}
	secureos := lookup.PackageOS(&pairing.Match{Package: pairing.Package{PURL: "pkg:apk/secureos/glibc-2.42@2.42-r4?distro=secureos-2025.09.09"}})
	got = related([]lookup.Affected{
		{Vulnerability: "CVE-2026-4438", Namespace: "nvd:cpe", CPE: "cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*"},
		{Vulnerability: "CVE-2026-4438", Namespace: "secureos:distro:secureos:rolling", Package: "glibc-2.42", Constraints: []string{"< 0"}, FixStates: []string{"fixed"}, FixVersions: []string{"0"}},
		{Vulnerability: "CVE-2026-4438", Namespace: "wolfi:distro:wolfi:rolling", Package: "glibc-2.42"},
		{Vulnerability: "CVE-2026-4438", Namespace: "secureos:distro:secureos:rolling", Package: "musl"},
	}, glibc, []string{"CVE-2026-4438"}, []string{"glibc-2.42", "glibc"}, secureos)
	if len(got) != 2 || got[1].Namespace != "secureos:distro:secureos:rolling" || !got[1].NotAffected() {
		t.Errorf("expected the CPE record and the secureos glibc-2.42 NAK, got %+v", got)
	}
}

// real scans of one image, the candidate matching rpm by CPE too: every row carries a row id unique
// in the gate and each setup's record, and only the one-sided rows carry a reason, here from no
// lookups at all
func TestRowsCarryDetailAndWhy(t *testing.T) {
	cand, ref := scan(t, fixture.Path("grype", "v0.120.1-cpes", "rpm.json")), scan(t, fixture.Grype("v0.120.1", "rpm"))
	a := pairing.NewAliases(nil)
	a.AddScan(cand)
	a.AddScan(ref)
	r := pairing.Pair(a, pairing.Subject{Name: "rpm", Packages: packagesOf(t, "rpm"),
		Scans: map[string]*models.Document{gatefile.Candidate: cand, gatefile.Reference: ref}})
	g := &gatefile.Gate{Name: "rpm", Path: "gates/rpm.yaml", Undecided: gatefile.UndecidedFail, Reference: &gatefile.Setup{}}
	v := Build(g, header(), analysis.Evaluate(nil, nil), []SubjectInput{{Name: "rpm", Result: r}}, nil)
	rows, oneSided, cpeOnly := map[string]bool{}, 0, 0
	for _, m := range v.Subjects[0].Matches {
		if rows[m.Row] || len(m.Row) != 16 {
			t.Errorf("%s: row id %q is not 16 hex unique in the gate", m.ID, m.Row)
		}
		rows[m.Row] = true
		if m.InCandidate != (m.Candidate != nil) || m.InReference != (m.Reference != nil) {
			t.Errorf("%s: expected a record for each setup that reported it", m.ID)
		}
		if m.Candidate != nil && (m.Candidate.Namespace == "" || m.Candidate.Distro != "rockylinux 9.8" || len(m.Candidate.Matchers) == 0) {
			t.Errorf("%s: expected the candidate's namespace, distro and matcher, got %+v", m.ID, m.Candidate)
		}
		if (m.InCandidate != m.InReference) != (m.Why != nil) {
			t.Errorf("%s: expected a reason exactly when one setup reported it, got %+v", m.ID, m.Why)
		}
		if m.Why != nil {
			oneSided++
			if m.Why.Key == WhyCPEOnly {
				cpeOnly++
			}
			if m.Why.Key != WhyUnexplained && m.Why.Key != WhyCPEOnly {
				t.Errorf("%s: with no lookups only the grype output explains a row, got %+v", m.ID, m.Why)
			}
		}
		if m.SourcePackage == "" {
			t.Errorf("%s: expected a source package", m.ID)
		}
	}
	if oneSided == 0 || cpeOnly == 0 {
		t.Fatalf("expected rows only the candidate's CPE matching reports, got %d one-sided, %d by CPE", oneSided, cpeOnly)
	}
	out := render(t, Summarize([]Gate{v}), Options{Format: "json"})
	for _, k := range []string{`"row": "`, `"why": {`, `"fixState": "`, `"sourcePackage": "`, `"distro": "rockylinux 9.8"`, `"cpes": [`} {
		if !strings.Contains(out, k) {
			t.Errorf("expected json to carry %s", k)
		}
	}
}
