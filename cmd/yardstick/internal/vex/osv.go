package vex

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
)

// osvRecord is the part of an OSV record a label can come from.
type osvRecord struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Modified string   `json:"modified"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

// ImportOSV turns the versions an OSV record states into global labels on that package: each
// listed affected version and last_affected version is tp, and each fixed version is fp with the
// fix installed. A version range alone states no version, so an affected entry with only one is
// skipped and listed, as is a package with no purl.
//
// ponytail: global labels only; a record never names an image, so nothing narrower is possible.
func ImportOSV(name string, data []byte, opts Options) (*Imported, error) {
	var rec osvRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if opts.Source == "" {
		opts.Source = "osv"
	}
	vuln := osvVulnerability(rec)
	observed, _ := time.Parse(time.RFC3339Nano, rec.Modified)
	out := &Imported{}
	for i, a := range rec.Affected {
		base, err := packageurl.FromString(a.Package.PURL)
		t := pkg.TypeFromPURL(a.Package.PURL)
		if a.Package.PURL == "" || err != nil || t == pkg.UnknownPkg || !labels.ValidType(string(t)) {
			out.Skipped = append(out.Skipped, fmt.Sprintf("%s affected[%d] (%s %s): no package URL with a known type", name, i, a.Package.Ecosystem, a.Package.Name))
			continue
		}
		stated := statedVersions(a.Versions, a.Ranges)
		if len(stated) == 0 {
			out.Skipped = append(out.Skipped, fmt.Sprintf("%s affected[%d] (%s): only a range, which states no version", name, i, a.Package.PURL))
			continue
		}
		for _, sv := range stated {
			p := base
			p.Version = sv.version
			l := labels.Label{
				Package:       p.ToString(),
				Vulnerability: vuln,
				Verdict:       sv.verdict,
				Justification: sv.justification,
				Author:        opts.Author,
				FirstIssued:   opts.Now.UTC().Format(time.RFC3339),
				LastUpdated:   opts.Now.UTC().Format(time.RFC3339),
				Evidence: []labels.Evidence{{
					Facts: []labels.Fact{{
						Source:     opts.Source,
						About:      map[string]string{"record": rec.ID, "package": a.Package.PURL},
						Field:      sv.field,
						Value:      sv.version,
						ObservedAt: stamp(observed, opts.Now),
					}},
					Interpretation: fmt.Sprintf("OSV record %s lists %s as %s", rec.ID, sv.version, sv.meaning),
				}},
			}
			out.Placed = append(out.Placed, labels.Placed{File: labels.GlobalFile(string(t)), Label: l})
		}
	}
	return out, nil
}

// osvVulnerability is the id labels name: the record's CVE alias when it has one, so the label
// joins the alias group grype's matches reach, else the record's own id.
func osvVulnerability(rec osvRecord) string {
	for _, a := range append([]string{rec.ID}, rec.Aliases...) {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return rec.ID
}

type statedVersion struct {
	version, field, meaning string
	verdict                 labels.Verdict
	justification           string
}

// statedVersions are the versions a record names outright: listed versions and last_affected
// events are affected, fixed events are fixed. Introduced events only open a range.
func statedVersions(versions []string, ranges []struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}) []statedVersion {
	seen := map[string]bool{}
	var out []statedVersion
	add := func(sv statedVersion) {
		if sv.version != "" && sv.version != "0" && !seen[sv.version] {
			seen[sv.version] = true
			out = append(out, sv)
		}
	}
	for _, v := range versions {
		add(statedVersion{version: v, field: "affected.versions", meaning: "affected", verdict: labels.TP})
	}
	for _, r := range ranges {
		if r.Type == "GIT" {
			continue // a commit is not a package version
		}
		for _, e := range r.Events {
			add(statedVersion{version: e["last_affected"], field: "affected.ranges.last_affected", meaning: "the last affected version", verdict: labels.TP})
			add(statedVersion{version: e["fixed"], field: "affected.ranges.fixed", meaning: "the fix", verdict: labels.FP, justification: fixInstalled})
		}
	}
	return out
}
