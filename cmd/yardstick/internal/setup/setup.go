// Package setup prepares a gate's candidate or reference setup to scan with: grype installed, the
// DB resolved and imported into the cache by checksum, the config file hashed, the declared env
// recorded. What a setup resolved to is what the run record and the report header print.
package setup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/bus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// Prepared is a setup with everything resolved, ready to scan.
type Prepared struct {
	Grype  install.Tool      `json:"grype"`
	DB     DB                `json:"db"`
	Config *File             `json:"config,omitempty"`
	Env    map[string]string `json:"env,omitempty"`
}

// MarshalJSON writes the env with its credentials masked: a Prepared goes into the run record, which
// a CI run uploads with its scans, and to the label UI.
func (p Prepared) MarshalJSON() ([]byte, error) {
	type plain Prepared
	q := plain(p)
	q.Env = execute.MaskEnv(p.Env)
	return json.Marshal(q)
}

// DB is a resolved, pinned grype vulnerability DB.
type DB struct {
	Requested string `json:"requested"`          // as the gate file wrote it, e.g. latest
	Source    string `json:"source"`             // the archive URL or path, or the directory for dir:
	Checksum  string `json:"checksum,omitempty"` // sha256:..., or grype's xxh64:... for a dir: DB it imported
	Dir       string `json:"dir,omitempty"`      // GRYPE_DB_CACHE_DIR to scan with, recorded for the skills
}

// File is a config file a tool was given, identified by content as well as path.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Preparer prepares the setups of one invocation, sharing one tool resolver, so latest means
// one version for grype and one DB per grype version.
type Preparer struct {
	Tools *install.Resolver
	Run   execute.Runner

	mu       sync.Mutex
	latest   map[string]DB     // by grype binary digest, env and config: what decides the listing
	archives map[string]string // archive path to its checksum, so one archive is read once
	dirs     map[string]string // dir: DB path to its identity, so one DB is hashed once
}

func NewPreparer(tools *install.Resolver, run execute.Runner) *Preparer {
	return &Preparer{Tools: tools, Run: run, latest: map[string]DB{}, archives: map[string]string{}, dirs: map[string]string{}}
}

// Prepare resolves one setup; name (candidate or reference) is in every error.
func (p *Preparer) Prepare(ctx context.Context, name string, s *gatefile.Setup) (Prepared, error) {
	spec, err := install.ParseSpec("grype", s.Grype)
	if err != nil {
		return Prepared{}, fmt.Errorf("%s: %w", name, err)
	}
	task := bus.StartTask(event.Install, "%s", spec)
	grype, err := p.Tools.Install(ctx, spec)
	task.Done(err)
	if err != nil {
		return Prepared{}, fmt.Errorf("%s: %w", name, err)
	}
	out := Prepared{Grype: grype, Env: s.Env}
	if s.Config != "" {
		sum, err := fileSHA256(s.Config)
		if err != nil {
			return Prepared{}, fmt.Errorf("%s: unable to read grype config: %w", name, err)
		}
		out.Config = &File{Path: s.Config, SHA256: sum}
	}
	if out.DB, err = p.prepareDB(ctx, grype, s, out.Config); err != nil {
		return Prepared{}, fmt.Errorf("%s: unable to prepare DB %q with %s: %w", name, s.DB, grype.Spec, err)
	}
	return out, nil
}

// prepareDB resolves the DB and imports it into a cache directory keyed by its identity, so
// each distinct DB is downloaded and imported once.
func (p *Preparer) prepareDB(ctx context.Context, grype install.Tool, s *gatefile.Setup, cfg *File) (DB, error) {
	task := bus.StartTask(event.ResolveDB, "%s for %s", s.DB, grype.Spec)
	db, err := p.resolveDB(ctx, grype, s, cfg)
	task.Done(err)
	if err != nil {
		return DB{}, err
	}
	db.Requested = s.DB
	if db.Dir != "" {
		return db, nil
	}
	identity := strings.ReplaceAll(db.Checksum, ":", "-")
	if identity == "" {
		sum := sha256.Sum256([]byte(db.Source))
		identity = "source-" + hex.EncodeToString(sum[:])
	}
	db.Dir = cache.Dir("grype-db", identity)
	if _, err := os.Stat(filepath.Join(db.Dir, importedMarker)); err == nil {
		log.Debugf("DB cache hit: %s", db.Dir)
		cache.Touch(db.Dir)
		return db, nil
	}
	log.Debugf("DB cache miss: %s", db.Dir)
	src := db.Source
	if db.Checksum != "" && isURL(src) {
		src += "?checksum=" + url.QueryEscape(db.Checksum)
	}
	log.Infof("importing DB %s", identity)
	log.Debugf("DB source: %s", db.Source)
	defer log.Timed("importing DB %s", identity)()
	task = bus.StartTask(event.ImportDB, "%s", identity)
	err = p.importDB(ctx, grype, s.Env, src, db)
	task.Done(err)
	return db, err
}

// importedMarker is written last into an imported DB's directory, so a directory holding it is a
// whole DB.
const importedMarker = ".yardstick-imported"

// importDB imports into a temporary directory beside the DB's final one and renames it into place
// when whole. grype's import deletes the directory it imports into before moving its own in, so
// two processes importing into one directory can pull the DB out from under each other. A rename
// onto a DB that is already there fails, and then the other process's copy is used.
func (p *Preparer) importDB(ctx context.Context, grype install.Tool, env map[string]string, src string, db DB) error {
	parent := filepath.Dir(db.Dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	removeStaleImports(parent)
	cfg, err := execute.EmptyConfig()
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, importPrefix+"*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if _, _, err := p.Run.Run(ctx, execute.Cmd{Bin: grype.Bin, Args: []string{"-c", cfg, "db", "import", src}, DBDir: tmp, Env: env}); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, importedMarker), []byte(db.Source+"\n"), 0o600); err != nil {
		return err
	}
	// a directory with no marker is what an import killed under the old layout left behind
	if _, err := os.Stat(filepath.Join(db.Dir, importedMarker)); err != nil {
		_ = os.RemoveAll(db.Dir)
	}
	if err := os.Rename(tmp, db.Dir); err != nil {
		if _, statErr := os.Stat(filepath.Join(db.Dir, importedMarker)); statErr != nil {
			return err
		}
		log.Debugf("DB %s was imported by another process, using it", db.Dir)
	}
	return nil
}

const importPrefix = ".import-"

// removeStaleImports deletes import directories a killed run left behind.
func removeStaleImports(dir string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && strings.HasPrefix(e.Name(), importPrefix) && time.Since(info.ModTime()) > cache.StaleTemp {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}

func (p *Preparer) resolveDB(ctx context.Context, grype install.Tool, s *gatefile.Setup, cfg *File) (DB, error) {
	switch {
	case s.DB == "latest":
		return p.latestDB(ctx, grype, s.Env, cfg)
	case strings.HasPrefix(s.DB, "dir:"):
		dir := strings.TrimPrefix(s.DB, "dir:")
		p.mu.Lock()
		defer p.mu.Unlock()
		identity, ok := p.dirs[dir]
		if !ok {
			identity = dirIdentity(dir)
			p.dirs[dir] = identity
		}
		return DB{Source: dir, Dir: dir, Checksum: identity}, nil
	case isURL(s.DB):
		// grype checks an archive's checksum as it imports it, and the DB is then cached by content
		if u, sum, ok := strings.Cut(s.DB, "@sha256:"); ok {
			return DB{Source: u, Checksum: "sha256:" + sum}, nil
		}
		log.Warnf("DB %s has no @sha256:<checksum>, so it is imported unverified and cached by its URL, as if what it serves never changed", s.DB)
		return DB{Source: s.DB}, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	sum, ok := p.archives[s.DB]
	if !ok {
		var err error
		if sum, err = fileSHA256(s.DB); err != nil {
			return DB{}, fmt.Errorf("unable to read DB archive: %w", err)
		}
		p.archives[s.DB] = sum
	}
	return DB{Source: s.DB, Checksum: "sha256:" + sum}, nil
}

// latestDB asks grype which DB it would download, with the setup's env and config (either can move
// db.update-url), once per grype binary, env and config per invocation, so two setups on db: latest
// that would ask the same thing compare one DB even when a new one is published mid-run.
func (p *Preparer) latestDB(ctx context.Context, grype install.Tool, env map[string]string, cfg *File) (DB, error) {
	cfgPath, cfgSum := "", ""
	if cfg != nil {
		cfgPath, cfgSum = cfg.Path, cfg.SHA256
	}
	k, _ := json.Marshal(struct {
		Grype, Config string
		Env           map[string]string
	}{grype.SHA256, cfgSum, env})
	key := string(k)
	p.mu.Lock()
	defer p.mu.Unlock()
	if db, ok := p.latest[key]; ok {
		log.Debugf("latest DB cache hit for %s: %s", grype.Spec, db.Checksum)
		return db, nil
	}
	log.Infof("looking up the latest DB for %s", grype.Spec)
	defer log.Timed("looking up the latest DB for %s", grype.Spec)()
	if cfgPath == "" {
		var err error
		if cfgPath, err = execute.EmptyConfig(); err != nil {
			return DB{}, err
		}
	}
	out, _, err := p.Run.Run(ctx, execute.Cmd{Bin: grype.Bin, Args: []string{"-c", cfgPath, "db", "list", "-o", "text"}, Env: env})
	if err != nil {
		return DB{}, err
	}
	fields := parseFields(out)
	if fields["DB URL"] == "" || fields["Checksum"] == "" {
		return DB{}, fmt.Errorf("unexpected `grype db list` output:\n%s", out)
	}
	db := DB{Source: fields["DB URL"], Checksum: fields["Checksum"]}
	p.latest[key] = db
	log.Debugf("latest DB for %s: %s (%s)", grype.Spec, db.Checksum, db.Source)
	return db, nil
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// parseFields reads "Key:   value" lines.
func parseFields(out []byte) map[string]string {
	fields := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if k, v, ok := strings.Cut(scanner.Text(), ":"); ok {
			fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return fields
}
