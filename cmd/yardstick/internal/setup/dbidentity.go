package setup

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// dbSchemaDir is where grype v6 keeps its DB under GRYPE_DB_CACHE_DIR.
const dbSchemaDir = "6"

// dirIdentity names a dir: DB by what it holds, so a scan of it can be keyed. In order:
//
//  1. the digest grype writes to import.json beside an imported DB. Grype checks it against
//     vulnerability.db on every start, so a DB edited in place after its import fails to load
//     rather than scanning under a stale name.
//  2. a sha256 of vulnerability.db, for a DB grype-db built that was never imported.
//
// grype v6 also records its schema and a build timestamp in the DB's db_metadata table. That is
// left out on purpose: a timestamp rounded to the second is not an identity for a DB that can be
// edited in place, and reading it needs a SQLite driver.
//
// It returns "" for a directory holding neither file, which a scan cannot be keyed by.
func dirIdentity(dir string) string {
	schema := filepath.Join(dir, dbSchemaDir)
	if data, err := os.ReadFile(filepath.Join(schema, "import.json")); err == nil {
		var im struct {
			Digest string `json:"digest"`
		}
		if json.Unmarshal(data, &im) == nil && im.Digest != "" {
			log.Debugf("dir: DB %s is identified by grype's import metadata", dir)
			return im.Digest
		}
		log.Debugf("dir: DB %s has an import.json with no digest, hashing the DB file instead", dir)
	}
	sum, err := install.FileSHA256(filepath.Join(schema, "vulnerability.db"))
	switch {
	case err == nil:
		log.Debugf("dir: DB %s is identified by a sha256 of its DB file", dir)
		return "sha256:" + sum
	case !errors.Is(err, fs.ErrNotExist):
		log.Debugf("dir: DB %s cannot be hashed: %v", dir, err)
	default:
		log.Debugf("dir: DB %s has no %s/vulnerability.db", dir, dbSchemaDir)
	}
	return ""
}
