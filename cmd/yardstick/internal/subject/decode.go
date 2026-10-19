package subject

import (
	"fmt"
	"os"
	"strings"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cpes"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/purls"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

// decoderNames are the formats format.Decode tries, for errors.
var decoderNames = []string{
	string(syftjson.ID), string(cyclonedxjson.ID), string(cyclonedxxml.ID),
	string(spdxjson.ID), string(spdxtagvalue.ID), string(purls.ID), string(cpes.ID),
}

// Decode reads an SBOM document in any format syft reads: syft-json, CycloneDX or SPDX. A file
// no decoder accepts is an error naming it and the formats tried.
func Decode(path string) (*sbom.SBOM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, _, _, err := format.Decode(f)
	if err != nil || s == nil {
		return nil, fmt.Errorf("%s is not an SBOM syft can decode (tried %s): %v", path, strings.Join(decoderNames, ", "), err)
	}
	return s, nil
}
