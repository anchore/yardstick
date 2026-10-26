// Package collect builds SBOMs with syft from a catalog and scans subjects with each setup's
// grype. grype's output is decoded with grype's own presenter models, never a copy of them.
package collect

import (
	"encoding/json"

	"github.com/anchore/grype/grype/presenter/models"
)

// Decode reads grype's JSON output.
func Decode(data []byte) (models.Document, error) {
	var doc models.Document
	err := json.Unmarshal(data, &doc)
	return doc, err
}
