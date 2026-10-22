// Package install resolves tool specs (grype@latest, syft@v1.54.1, or a path to a binary) and
// installs released tools into yardstick's cache through binny, one binny store per tool version,
// so installs are digest-checked and several versions of one tool coexist.
package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/anchore/binny"
	"github.com/anchore/binny/tool"
	"github.com/anchore/binny/tool/githubrelease"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// Spec names a tool and a version (grype@v0.120.1, grype@latest), or a binary by path.
type Spec struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
}

func (s Spec) String() string {
	if s.Path != "" {
		return s.Path
	}
	return s.Name + "@" + s.Version
}

// repos are the tools yardstick installs from GitHub releases.
var repos = map[string]string{
	"grype": "anchore/grype",
	"syft":  "anchore/syft",
}

// ParseSpec reads <name>@<version> or a path to a binary; name is the tool expected.
func ParseSpec(name, s string) (Spec, error) {
	if strings.ContainsRune(s, filepath.Separator) {
		abs, err := filepath.Abs(s)
		if err != nil {
			return Spec{}, err
		}
		return Spec{Name: name, Path: abs}, nil
	}
	n, v, _ := strings.Cut(s, "@")
	if n != name || v == "" {
		return Spec{}, fmt.Errorf("expected %s@<version> or a path to a %s binary, got %q", name, name, s)
	}
	if _, ok := repos[n]; !ok {
		return Spec{}, fmt.Errorf("yardstick does not know how to install %q", n)
	}
	return Spec{Name: n, Version: v}, nil
}

// Tool is an installed tool, ready to run.
type Tool struct {
	Spec   Spec   `json:"spec"`          // resolved: a concrete version, never latest
	Bin    string `json:"bin,omitempty"` // where it ran from, for the skills; never part of a key
	SHA256 string `json:"sha256"`
}

// Resolver resolves latest once per invocation, so every setup naming grype@latest gets one
// version, and installs released tools into the cache.
type Resolver struct {
	mu       sync.Mutex
	resolved map[Spec]Spec
	// newTool makes the binny tool for a name; tests swap in one that never touches the network
	newTool func(name string) (binny.Tool, error)
}

func NewResolver() *Resolver {
	return &Resolver{resolved: map[Spec]Spec{}, newTool: githubTool}
}

func githubTool(name string) (binny.Tool, error) {
	return tool.New(tool.Config{
		Name: name,
		InstallerConfig: tool.DetailConfig{
			Method:     githubrelease.InstallMethod,
			Parameters: githubrelease.InstallerParameters{Binary: name, Repo: repos[name]},
		},
	})
}

// Resolve turns latest into the version it means for this invocation.
func (r *Resolver) Resolve(ctx context.Context, s Spec) (Spec, error) {
	if s.Path != "" {
		return s, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if got, ok := r.resolved[s]; ok {
		log.Debugf("resolve cache hit: %s is %s", s, got.Version)
		return got, nil
	}
	defer log.Timed("resolving %s", s)()
	t, err := r.newTool(s.Name)
	if err != nil {
		return Spec{}, err
	}
	v, err := t.ResolveVersion(ctx, binny.VersionIntent{Want: s.Version})
	if err != nil {
		return Spec{}, fmt.Errorf("unable to resolve %s: %w", s, err)
	}
	out := Spec{Name: s.Name, Version: v}
	log.Infof("resolved %s to %s", s, v)
	r.resolved[s] = out
	return out, nil
}

// Install resolves the spec and installs it into its own binny store under the cache, unless it
// is already there. A path is used in place.
func (r *Resolver) Install(ctx context.Context, s Spec) (Tool, error) {
	s, err := r.Resolve(ctx, s)
	if err != nil {
		return Tool{}, err
	}
	if s.Path != "" {
		log.Infof("using %s binary at %s", s.Name, s.Path)
		sum, err := FileSHA256(s.Path)
		if err != nil {
			return Tool{}, fmt.Errorf("unable to read %s binary %s: %w", s.Name, s.Path, err)
		}
		return Tool{Spec: s, Bin: s.Path, SHA256: sum}, nil
	}

	defer log.Timed("installing %s", s)()
	t, err := r.newTool(s.Name)
	if err != nil {
		return Tool{}, err
	}
	// binny keeps one entry per tool name in a store, so each version gets a store of its own
	storeDir := cache.Dir("tools", s.Name, s.Version)
	log.Debugf("tool store for %s: %s", s, storeDir)
	store, err := binny.NewStore(storeDir)
	if err != nil {
		return Tool{}, err
	}
	verify := tool.VerifyConfig{VerifySHA256Digest: true}
	// binny reinstalls over a binary whose digest changed; yardstick refuses it instead, since
	// something rewrote a cached tool
	var mismatch *binny.ErrDigestMismatch
	if err := tool.Check(store, s.Name, s.Version, verify); errors.As(err, &mismatch) {
		return Tool{}, fmt.Errorf("%s: the cached binary no longer matches the digest recorded when it was installed (%s); remove %s to reinstall it", s, mismatch.Actual, store.Root())
	}
	log.Infof("installing %s", s)
	err = tool.Install(ctx, t, binny.VersionIntent{Want: s.Version}, store, verify)
	if errors.Is(err, tool.ErrAlreadyInstalled) {
		log.Infof("using cached %s", s)
		cache.Touch(storeDir)
	} else if err != nil {
		return Tool{}, fmt.Errorf("unable to install %s: %w", s, err)
	}
	entry, err := store.Get(s.Name, s.Version)
	if err != nil {
		return Tool{}, fmt.Errorf("%s: %w", s, err)
	}
	return Tool{Spec: s, Bin: entry.Path(), SHA256: entry.Digests["sha256"]}, nil
}

// FileSHA256 is the hex sha256 of a file's bytes.
func FileSHA256(path string) (string, error) {
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
