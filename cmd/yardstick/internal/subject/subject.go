// Package subject resolves a gate's subjects to the SBOM both setups scan: an sbom: document read
// where the gate names it, or an image's SBOM found in a fixed order (the first claims source
// holding it, the cache, then a syft run with the effective catalog). A packages.keepTypes filter
// is applied before either setup sees the SBOM.
package subject

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/bus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// From says where a subject's SBOM came from.
type From string

const (
	FromSource From = "source" // a claims source held it
	FromCache  From = "cache"  // built earlier with the same catalog
	FromBuilt  From = "built"  // built by this run
	FromFile   From = "file"   // an sbom: document, where the gate file names it
)

// Resolved is a subject with the SBOM both setups scan.
type Resolved struct {
	gatefile.Subject
	// Dir is the subject's directory in every claims source: its labels are read from there.
	Dir string `json:"dir"`
	// SBOM is the file both setups scan, and Digest the sha256 of its bytes.
	SBOM   string `json:"path"`
	Digest string `json:"digest"`
	// UnfilteredDigest is the SBOM's digest before packages.keepTypes; the same as Digest
	// without a filter. A label's seenIn.sbom is compared with it.
	UnfilteredDigest string `json:"unfilteredDigest"`
	From             From   `json:"from"`
	// Source is the claims source the SBOM came from, when From is source.
	Source string `json:"source,omitempty"`
	// Frozen is set when the image could not be pulled and a claims source held its SBOM.
	Frozen bool `json:"frozen,omitempty"`
	// Syft is the syft version that built the SBOM, from its descriptor; empty for a document
	// another tool made.
	Syft     string    `json:"syft,omitempty"`
	Packages []Package `json:"packages"`
	Warnings []string  `json:"warnings,omitempty"`
}

// Package is a package of the scanned SBOM, as labels pair against it.
type Package struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	PURL    string `json:"purl,omitempty"`
}

// Types are the package types in the scanned SBOM, sorted: the type files a gate reads.
func (r *Resolved) Types() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range r.Packages {
		if !seen[p.Type] {
			seen[p.Type] = true
			out = append(out, p.Type)
		}
	}
	sort.Strings(out)
	return out
}

// Catalog is a catalog ready to build with: its config file's bytes read and hashed.
type Catalog struct {
	gatefile.Catalog
	// ConfigData is the syft config's bytes; nil when the catalog names none.
	ConfigData []byte
	// Origin says where the catalog came from: the gate file, or a claims source's catalog.yaml.
	Origin string
}

// Digest identifies what a catalog builds: syft, its config, platform and env. Two catalogs
// with one digest build the same SBOM from one image.
func (c *Catalog) Digest(platform string) string {
	sum := sha256.Sum256(c.ConfigData)
	data, _ := json.Marshal(struct {
		Syft, Config, Platform string
		Env                    map[string]string
	}{c.Syft, hex.EncodeToString(sum[:]), platform, c.Env})
	sum = sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CachePath is where an image's SBOM built with a catalog for a platform is cached.
func CachePath(image ref.Ref, cat *Catalog, platform string) string {
	return cache.Dir("sboms", image.Digest, strings.ReplaceAll(cat.Digest(platform), ":", "-")+".syft.json")
}

// WriteFile writes a file whole or not at all: through a temp file and a rename.
func WriteFile(target string, data []byte) error {
	return cache.WriteFile(target, data)
}

// Builder builds an image's SBOM with a catalog, returning syft-json.
type Builder func(ctx context.Context, image ref.Ref, platform string, cat *Catalog) ([]byte, error)

// Resolver resolves one gate's subjects.
type Resolver struct {
	Sources []*claims.Source
	// Catalog is the gate's catalog:, nil when it sets none.
	Catalog *gatefile.Catalog
	// Rebuild skips the claims sources (--rebuild-sboms), so a syft setup can be tried on purpose.
	Rebuild bool
	// NoBuild returns ErrWouldBuild where an SBOM would be built, so score can ask which SBOM a
	// subject resolves to without running syft.
	NoBuild bool
	Build   Builder
}

// ErrWouldBuild is a subject whose SBOM no claims source or cache holds, under NoBuild.
var ErrWouldBuild = errors.New("its SBOM would have to be built")

// Resolve finds a subject's SBOM, filters it when the subject keeps some types, and reads its
// packages.
func (r *Resolver) Resolve(ctx context.Context, s gatefile.Subject) (*Resolved, error) {
	defer log.Timed("resolving the SBOM of %s", s.Name)()
	var res *Resolved
	var err error
	if s.Ref.Kind == ref.SBOM {
		res, err = document(s)
	} else {
		res, err = r.image(ctx, s)
	}
	if err != nil {
		return nil, fmt.Errorf("subject %s: %w", s.Name, err)
	}
	res.UnfilteredDigest = res.Digest
	log.Debugf("subject %s: SBOM from %s (%s), digest %s", s.Name, res.From, res.SBOM, res.Digest)
	if len(s.KeepTypes) > 0 {
		if err := filter(res); err != nil {
			return nil, fmt.Errorf("subject %s: %w", s.Name, err)
		}
		log.Debugf("subject %s: %d packages kept by packages.keepTypes, digest %s", s.Name, len(res.Packages), res.Digest)
		return res, nil
	}
	sb, err := Decode(res.SBOM)
	if err != nil {
		return nil, fmt.Errorf("subject %s: %w", s.Name, err)
	}
	res.Packages, res.Syft = packages(sb), syftVersion(sb)
	return res, nil
}

// document is an sbom: subject: scanned where it is, addressed by its bytes.
func document(s gatefile.Subject) (*Resolved, error) {
	data, err := os.ReadFile(s.Ref.Path)
	if err != nil {
		return nil, err
	}
	d := digest(data)
	return &Resolved{Subject: s, Dir: claimsv1.DocumentDir(d), SBOM: s.Ref.Path, Digest: d, From: FromFile}, nil
}

// image finds an image's SBOM: the first claims source holding it, the cache, then a build.
func (r *Resolver) image(ctx context.Context, s gatefile.Subject) (*Resolved, error) {
	res := &Resolved{Subject: s, Dir: claimsv1.ImageDir(s.Ref)}
	cat, err := r.effectiveCatalog()
	if err != nil {
		return nil, err
	}
	if res.Platform == "" && cat != nil {
		res.Platform = cat.Platform
	}
	var held []byte
	var heldBy *claims.Source
	for _, src := range r.Sources {
		data, err := src.ReadFile(path.Join(res.Dir, claimsv1.ImageSBOMFile))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("claims source %s: %w", src.Locator, err)
		}
		held, heldBy = data, src
		break
	}
	if held != nil && !r.Rebuild {
		log.Debugf("subject %s: claims source %s holds its SBOM", s.Name, heldBy.Locator)
		return r.fromSource(res, held, heldBy)
	}
	if cat == nil {
		if r.Rebuild {
			return nil, errors.New("--rebuild-sboms builds every image SBOM, and there is no catalog to build with: set catalog: in the gate or add catalog.yaml to a claims source")
		}
		return nil, errors.New("no claims source holds its SBOM and there is no catalog to build one with: set catalog: in the gate, add catalog.yaml to a claims source, or build it with yardstick collect sboms")
	}
	cached := CachePath(s.Ref, cat, res.Platform)
	if data, err := os.ReadFile(cached); err == nil {
		cache.Touch(cached)
		res.SBOM, res.Digest, res.From = cached, digest(data), FromCache
		return res, nil
	}
	if r.NoBuild {
		return nil, ErrWouldBuild
	}
	task := bus.StartTask(event.BuildSBOM, "%s", s.Name)
	data, err := r.Build(ctx, s.Ref, res.Platform, cat)
	task.Done(err)
	if err != nil {
		if held == nil {
			return nil, err
		}
		// ponytail: any failed build counts as the image being gone; the warning carries why
		res.Frozen = true
		res.Warnings = append(res.Warnings, fmt.Sprintf("subject %s is frozen: building its SBOM failed, so the SBOM %s holds is scanned: %v", s.Name, heldBy.Locator, err))
		return r.fromSource(res, held, heldBy)
	}
	if err := cache.WriteFile(cached, data); err != nil {
		return nil, err
	}
	res.SBOM, res.Digest, res.From = cached, digest(data), FromBuilt
	return res, nil
}

// fromSource scans the SBOM a claims source holds. The bytes read through the source are what is
// scanned, copied into the cache by digest, so a symlink in a corpus never points grype elsewhere.
func (r *Resolver) fromSource(res *Resolved, data []byte, src *claims.Source) (*Resolved, error) {
	res.Digest, res.From, res.Source = digest(data), FromSource, src.Locator
	res.SBOM = cache.Dir("sboms-read", strings.ReplaceAll(res.Digest, ":", "-")+".syft.json")
	if _, err := os.Stat(res.SBOM); err != nil {
		if err := cache.WriteFile(res.SBOM, data); err != nil {
			return nil, err
		}
	} else {
		cache.Touch(res.SBOM)
	}
	if r.Catalog == nil {
		return res, nil
	}
	// the corpus SBOM is what labels pair against, so it is used; a gate pinning another syft
	// setup is told
	doc, err := claimsv1.ReadSyftDocument(data)
	if err != nil {
		return nil, fmt.Errorf("%s in %s: %w", claimsv1.ImageSBOMFile, src.Locator, err)
	}
	var cfg []byte
	if r.Catalog.Config != "" {
		if cfg, err = os.ReadFile(r.Catalog.Config); err != nil {
			return nil, fmt.Errorf("catalog config: %w", err)
		}
	}
	drift, err := claimsv1.DescriptorDrift(doc, r.Catalog, cfg)
	if err != nil {
		return nil, err
	}
	for _, d := range drift {
		res.Warnings = append(res.Warnings, fmt.Sprintf("subject %s: the SBOM from %s was built with %s; it is scanned anyway, since its labels pair against it", res.Name, src.Locator, d))
	}
	return res, nil
}

// effectiveCatalog is the gate's catalog:, else the catalog.yaml of the first claims source that
// has one, with its config read through that source; nil when there is neither.
func (r *Resolver) effectiveCatalog() (*Catalog, error) {
	if r.Catalog != nil {
		c := &Catalog{Catalog: *r.Catalog, Origin: "the gate's catalog:"}
		if c.Config != "" {
			var err error
			if c.ConfigData, err = os.ReadFile(c.Config); err != nil {
				return nil, fmt.Errorf("catalog config: %w", err)
			}
		}
		return c, nil
	}
	for _, src := range r.Sources {
		data, err := src.ReadFile(claimsv1.CatalogFile)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("claims source %s: %w", src.Locator, err)
		}
		// config paths stay relative to the corpus root, and are read through the source
		parsed, err := gatefile.ParseCatalog(data, "")
		if err == nil {
			err = parsed.CheckData()
		}
		if err != nil {
			return nil, fmt.Errorf("claims source %s: %s: %w", src.Locator, claimsv1.CatalogFile, err)
		}
		c := &Catalog{Catalog: *parsed, Origin: src.Locator + "/" + claimsv1.CatalogFile}
		if c.Config != "" {
			if c.ConfigData, err = src.ReadFile(filepath.ToSlash(c.Config)); err != nil {
				return nil, fmt.Errorf("claims source %s: catalog config: %w", src.Locator, err)
			}
			if err := gatefile.CheckDataConfig(c.ConfigData); err != nil {
				return nil, fmt.Errorf("claims source %s: %s: %w", src.Locator, claimsv1.CatalogFile, err)
			}
			// syft reads the config from a file of its own, keyed by content
			c.Config = cache.Dir("catalog-config", digest(c.ConfigData)[len("sha256:"):]+".yaml")
			if err := cache.WriteFile(c.Config, c.ConfigData); err != nil {
				return nil, err
			}
		}
		return c, nil
	}
	return nil, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PlatformWarnings warns for each platform the subject's label files record that is not the
// platform this run catalogs: those labels were written against another platform's packages.
func (r *Resolved) PlatformWarnings(recorded []string) []string {
	var out []string
	for _, p := range recorded {
		if r.Platform != "" && p != r.Platform {
			out = append(out, fmt.Sprintf("subject %s: its label files record platform %s, and this run catalogs %s", r.Name, p, r.Platform))
		}
	}
	return out
}
