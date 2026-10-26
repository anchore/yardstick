package collect

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anchore/yardstick/cmd/yardstick/internal/bus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
)

// keyVersion is bumped whenever Scan changes how it invokes grype, so scans stored by an older
// yardstick are not reused. 2 logs at trace.
const keyVersion = 2

// noConfig stands in for the config digest of a setup that declares none, which runs with an
// empty config file.
const noConfig = "none"

// key is everything a scan's output depends on. The gate, subject and setup names are left out
// on purpose, so a scan is shared by whichever gate asks for it.
type key struct {
	Version int               `json:"version"`
	Grype   string            `json:"grype"`
	DB      string            `json:"db"`
	Config  string            `json:"config"`
	Env     map[string]string `json:"env,omitempty"`
	// Inherited digests the --inherit-env variables that can change a scan, without their values.
	Inherited string `json:"inherited,omitempty"`
	SBOM      string `json:"sbom"`
}

// scanKey is the hex key a setup's scan of an SBOM is stored under, where sbomDigest is the
// digest of the SBOM grype reads (after any keepTypes filter) and inherited is the digest of the
// inherited env. It reports false when the DB has no identity: a dir: DB holding no DB file.
func scanKey(p setup.Prepared, sbomDigest, inherited string) (string, bool) {
	db := filepath.Base(p.DB.Dir)
	if filepath.Dir(p.DB.Dir) != cache.Dir("grype-db") {
		// a dir: DB is named by what it holds, so it is reused until its contents change
		if p.DB.Checksum == "" {
			return "", false
		}
		db = "dir:" + p.DB.Checksum
	}
	k := key{Version: keyVersion, Grype: p.Grype.SHA256, DB: db, Config: noConfig, Env: p.Env, Inherited: inherited, SBOM: sbomDigest}
	if p.Config != nil {
		k.Config = p.Config.SHA256
	}
	data, _ := json.Marshal(k) // a struct of strings and a string map
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), true
}

// scanResult is one scan, run or reused.
type scanResult struct {
	Out     []byte
	Matches int
	// Key is the key the scan is stored under, empty when it can't be keyed.
	Key    string
	Reused bool
	// Log is grype's stderr from the scan, gzipped, and LogSHA256 the sha256 of its text; no log
	// when a stored scan has none.
	Log       []byte
	LogSHA256 string
}

// scanOrReuse returns a stored scan when one exists under the scan's key, else runs grype and
// stores what it wrote. A stored scan grype's models cannot decode is as good as absent. A scan
// that runs is announced as started on the bus, and one that is reused is not.
//
// Under --rescan the stored scan is not read, so every scan runs and replaces what is stored.
func (m Scans) scanOrReuse(ctx context.Context, p setup.Prepared, sub *runrecord.Subject, setupName string) (scanResult, error) {
	what := fmt.Sprintf("%s with the %s setup", sub.Name, setupName)
	run := func() (scanResult, error) {
		log.Infof("scanning %s", what)
		defer log.Timed("scanning %s", what)()
		bus.ScanStarted(sub.Name, setupName)
		out, stderr, matches, err := Scan(ctx, m.Run, p, sub.SBOM)
		if err != nil {
			return scanResult{}, err
		}
		res := scanResult{Out: out, Matches: matches}
		res.Log, res.LogSHA256, err = gzipLog(stderr)
		return res, err
	}
	k, keyed := scanKey(p, sub.Digest, m.Run.InheritedDigest())
	if !keyed {
		log.Debugf("the DB of %s has no identity, so its scan is not cached", what)
		return run()
	}
	path := cache.Dir("scans", k+".json")
	logPath := cache.Dir("scans", k+".log.gz")
	if m.Rescan {
		log.Debugf("--rescan: not reading %s", path)
	} else if data, readErr := os.ReadFile(path); readErr == nil {
		doc, decodeErr := Decode(data)
		if decodeErr == nil {
			log.Infof("reusing the stored scan of %s", what)
			log.Debugf("scan cache hit: %s", path)
			cache.Touch(path)
			res := scanResult{Out: data, Matches: len(doc.Matches), Key: k, Reused: true}
			res.Log, res.LogSHA256 = storedLog(logPath)
			return res, nil
		}
		log.Warnf("stored scan %s does not decode, scanning again: %v", path, decodeErr)
	}
	res, err := run()
	if err != nil {
		return scanResult{}, err
	}
	res.Key = k
	// a scan that can't be stored is still a good scan
	if err := cache.WriteFile(logPath, res.Log); err != nil {
		log.Warnf("unable to store the scan's log under %s: %v", logPath, err)
	}
	if err := cache.WriteFile(path, res.Out); err != nil {
		log.Warnf("unable to store the scan under %s: %v", path, err)
	}
	return res, nil
}

// storedLog reads a stored scan's gzipped log and the sha256 of its text; nothing when it is
// missing or damaged, since the scan is good without it.
func storedLog(path string) ([]byte, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ""
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, zr); err != nil { //nolint:gosec // G110: a log yardstick wrote into its own cache
		return nil, ""
	}
	return data, hex.EncodeToString(h.Sum(nil))
}
