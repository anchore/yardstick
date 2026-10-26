package subject

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// filter drops every package whose type the subject does not keep, with the relationships that
// touch one, and points the subject at the filtered syft-json. It is cached under the unfiltered
// digest plus the kept types, so both setups and every rerun scan the same bytes.
func filter(res *Resolved) error {
	kept := strings.Join(res.KeepTypes, ",")
	cached := cache.Dir("sboms-filtered", strings.ReplaceAll(res.UnfilteredDigest, ":", "-"), kept+".syft.json")
	if data, err := os.ReadFile(cached); err == nil {
		cache.Touch(cached)
		sb, err := Decode(cached)
		if err != nil {
			return err
		}
		res.SBOM, res.Digest, res.Packages, res.Syft = cached, digest(data), packages(sb), syftVersion(sb)
		return nil
	}
	sb, err := Decode(res.SBOM)
	if err != nil {
		return err
	}
	var drop []artifact.ID
	for _, p := range sb.Artifacts.Packages.Sorted() {
		if !slices.Contains(res.KeepTypes, string(p.Type)) {
			drop = append(drop, p.ID())
		}
	}
	log.Debugf("subject %s: dropping %d of %d packages not of type [%s]", res.Name, len(drop), sb.Artifacts.Packages.PackageCount(), kept)
	sb.Artifacts.Packages.Delete(drop...)
	if sb.Artifacts.Packages.PackageCount() == 0 {
		return fmt.Errorf("packages.keepTypes [%s] keeps none of the SBOM's packages", kept)
	}
	gone := map[artifact.ID]bool{}
	for _, id := range drop {
		gone[id] = true
	}
	var rels []artifact.Relationship
	for _, r := range sb.Relationships {
		if !gone[r.From.ID()] && !gone[r.To.ID()] {
			rels = append(rels, r)
		}
	}
	sb.Relationships = rels
	data, err := format.Encode(*sb, syftjson.NewFormatEncoder())
	if err != nil {
		return err
	}
	if err := cache.WriteFile(cached, data); err != nil {
		return err
	}
	res.SBOM, res.Digest, res.Packages, res.Syft = cached, digest(data), packages(sb), syftVersion(sb)
	return nil
}

// packages lists an SBOM's packages as labels pair against them.
func packages(sb *sbom.SBOM) []Package {
	var out []Package
	for _, p := range sb.Artifacts.Packages.Sorted() {
		out = append(out, Package{ID: string(p.ID()), Name: p.Name, Version: p.Version, Type: string(p.Type), PURL: p.PURL})
	}
	return out
}

// syftVersion is the syft version an SBOM's descriptor names, when syft made it.
func syftVersion(sb *sbom.SBOM) string {
	if sb.Descriptor.Name != "syft" {
		return ""
	}
	return sb.Descriptor.Version
}
