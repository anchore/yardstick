package subject

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// the manifest the fixture deb SBOM was cataloged from
const debDigest = "sha256:617d48dd2601779266746a9a382bfb9f3fee2744fba698733b320366f41718b0"

func read(t *testing.T, p string) []byte {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func write(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func imageSubject(t *testing.T) gatefile.Subject {
	t.Helper()
	r, err := ref.Parse("oci:docker.io/anchore/yardstick-fixture-deb@" + debDigest)
	if err != nil {
		t.Fatal(err)
	}
	return gatefile.Subject{Ref: r, Written: r.String(), Name: "deb"}
}

func documentSubject(t *testing.T, p string, keep ...string) gatefile.Subject {
	t.Helper()
	r, err := ref.Parse("sbom:" + p)
	if err != nil {
		t.Fatal(err)
	}
	return gatefile.Subject{Ref: r, Written: r.String(), Name: filepath.Base(p), KeepTypes: keep}
}

func source(t *testing.T, dir string) *claims.Source {
	t.Helper()
	s, err := claims.Open(gatefile.Source{Locator: dir})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// builder stands in for syft: it hands back the fixture deb SBOM, which syft built, and counts
// its calls.
type builder struct {
	calls int
	err   error
	got   *Catalog
}

func (b *builder) build(_ context.Context, _ ref.Ref, _ string, cat *Catalog) ([]byte, error) {
	b.calls++
	b.got = cat
	if b.err != nil {
		return nil, b.err
	}
	return os.ReadFile(fixture.SBOM("deb", "syft"))
}

func pinned(syft string) *gatefile.Catalog {
	return &gatefile.Catalog{Syft: syft}
}

func TestDocumentSubjects(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	dir := t.TempDir()
	r := &Resolver{}

	// three formats of one image's SBOM read to the same packages
	var sets [][]string
	for _, f := range []string{"syft", "cdx", "spdx"} {
		p := filepath.Join(dir, "deb."+f+".json")
		write(t, p, read(t, fixture.SBOM("deb", f)))
		res, err := r.Resolve(context.Background(), documentSubject(t, p))
		if err != nil {
			t.Fatal(err)
		}
		if res.From != FromFile || res.SBOM != p || res.Dir != corpus.DocumentDir(res.Digest) {
			t.Errorf("%s: expected the document scanned in place under sbom/<its digest>, got %s %s %s", f, res.From, res.SBOM, res.Dir)
		}
		var purls []string
		for _, p := range res.Packages {
			purls = append(purls, p.Name+"@"+p.Version+" "+p.Type)
		}
		slices.Sort(purls)
		sets = append(sets, purls)
	}
	if len(sets[0]) == 0 || !slices.Equal(sets[0], sets[1]) || !slices.Equal(sets[0], sets[2]) {
		t.Errorf("syft-json, CycloneDX and SPDX read to different packages: %d, %d, %d", len(sets[0]), len(sets[1]), len(sets[2]))
	}

	// moving the file keeps its address; editing a byte changes it
	moved := filepath.Join(dir, "elsewhere", "vendor.json")
	write(t, moved, read(t, fixture.SBOM("deb", "cdx")))
	a, _ := r.Resolve(context.Background(), documentSubject(t, filepath.Join(dir, "deb.cdx.json")))
	b, _ := r.Resolve(context.Background(), documentSubject(t, moved))
	if a.Dir != b.Dir {
		t.Errorf("moving a document changed its address: %s, then %s", a.Dir, b.Dir)
	}
	write(t, moved, append(read(t, moved), '\n'))
	if c, err := r.Resolve(context.Background(), documentSubject(t, moved)); err != nil || c.Dir == a.Dir {
		t.Errorf("editing a document kept its address %s", c.Dir)
	}

	// a document no decoder reads fails naming the subject, the file and the formats tried
	truncated := filepath.Join(dir, "truncated.json")
	write(t, truncated, read(t, fixture.SBOM("deb", "cdx"))[:500])
	_, err := r.Resolve(context.Background(), documentSubject(t, truncated))
	if err == nil || !strings.Contains(err.Error(), "truncated.json") || !strings.Contains(err.Error(), "cyclonedx-json") || !strings.Contains(err.Error(), "spdx-json") {
		t.Errorf("expected an error naming the subject and the formats tried, got %v", err)
	}
}

// corpusWithDeb is a claims source holding the deb image's SBOM.
func corpusWithDeb(t *testing.T, s gatefile.Subject) string {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, corpus.ImageDir(s.Ref), corpus.ImageSBOMFile), read(t, fixture.SBOM("deb", "syft")))
	return dir
}

func TestImageSBOMOrder(t *testing.T) {
	ctx := context.Background()
	s := imageSubject(t)

	t.Run("the first source holding it", func(t *testing.T) {
		t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
		empty, holding := t.TempDir(), corpusWithDeb(t, s)
		b := &builder{}
		r := &Resolver{Sources: []*claims.Source{source(t, empty), source(t, holding), source(t, corpusWithDeb(t, s))}, Catalog: pinned("syft@v1.54.1"), Build: b.build}
		res, err := r.Resolve(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		if res.From != FromSource || res.Source != holding || b.calls != 0 {
			t.Errorf("expected the SBOM from %s and no build, got %s from %q, %d builds", holding, res.From, res.Source, b.calls)
		}
		if len(res.Warnings) != 0 {
			t.Errorf("a catalog matching the SBOM warned: %v", res.Warnings)
		}
		age(t, res.SBOM)
		if _, err := r.Resolve(ctx, s); err != nil {
			t.Fatal(err)
		}
		touched(t, res.SBOM)
		if !slices.Contains(res.Types(), "deb") {
			t.Errorf("expected the SBOM's deb packages, got types %v", res.Types())
		}
	})

	t.Run("built with the gate's catalog, then cached", func(t *testing.T) {
		t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
		b := &builder{}
		r := &Resolver{Sources: []*claims.Source{source(t, t.TempDir())}, Catalog: pinned("syft@v1.54.1"), Build: b.build}
		res, err := r.Resolve(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		if res.From != FromBuilt || b.calls != 1 || !strings.HasPrefix(res.SBOM, os.Getenv("YARDSTICK_CACHE_DIR")) {
			t.Errorf("expected one build into the cache, got %s at %s, %d builds", res.From, res.SBOM, b.calls)
		}
		age(t, res.SBOM)
		again, err := r.Resolve(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		touched(t, res.SBOM)
		if again.From != FromCache || b.calls != 1 || again.Digest != res.Digest {
			t.Errorf("expected the cached SBOM the second time, got %s, %d builds", again.From, b.calls)
		}
		// a catalog pinning another syft does not use that cache entry
		r.Catalog = pinned("syft@v1.52.0")
		if other, _ := r.Resolve(ctx, s); other.From != FromBuilt || b.calls != 2 {
			t.Errorf("an SBOM cached for another catalog was used: %s, %d builds", other.From, b.calls)
		}
		// under NoBuild a cached SBOM still resolves, and a miss is ErrWouldBuild with no build
		r.NoBuild = true
		if cached, err := r.Resolve(ctx, s); err != nil || cached.From != FromCache || b.calls != 2 {
			t.Errorf("expected the cached SBOM under NoBuild, got %v, %d builds", err, b.calls)
		}
		r.Catalog = pinned("syft@v1.50.0")
		if _, err := r.Resolve(ctx, s); !errors.Is(err, ErrWouldBuild) || b.calls != 2 {
			t.Errorf("expected ErrWouldBuild and no build, got %v, %d builds", err, b.calls)
		}
	})

	t.Run("built with the first source's catalog.yaml", func(t *testing.T) {
		t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
		withCatalog := t.TempDir()
		write(t, filepath.Join(withCatalog, corpus.CatalogFile), []byte("syft: syft@v1.54.1\nconfig: syft.yaml\nplatform: linux/arm64\n"))
		write(t, filepath.Join(withCatalog, "syft.yaml"), []byte("scope: all-layers\n"))
		b := &builder{}
		r := &Resolver{Sources: []*claims.Source{source(t, t.TempDir()), source(t, withCatalog)}, Build: b.build}
		res, err := r.Resolve(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		if res.From != FromBuilt || b.got.Syft != "syft@v1.54.1" || string(b.got.ConfigData) != "scope: all-layers\n" || res.Platform != "linux/arm64" {
			t.Errorf("expected a build with the source's catalog, got %s with %+v", res.From, b.got)
		}
		if data, err := os.ReadFile(b.got.Config); err != nil || string(data) != "scope: all-layers\n" {
			t.Errorf("syft is handed a config file it can read, got %v", err)
		}
	})

	t.Run("no SBOM and no catalog", func(t *testing.T) {
		t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
		r := &Resolver{Sources: []*claims.Source{source(t, t.TempDir())}, Build: (&builder{}).build}
		_, err := r.Resolve(ctx, s)
		if err == nil || !strings.Contains(err.Error(), "subject deb") || !strings.Contains(err.Error(), "yardstick collect sboms") {
			t.Errorf("expected an error naming the subject and yardstick collect sboms, got %v", err)
		}
	})

	t.Run("rebuild skips the sources", func(t *testing.T) {
		t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
		b := &builder{}
		r := &Resolver{Sources: []*claims.Source{source(t, corpusWithDeb(t, s))}, Catalog: pinned("syft@v1.54.1"), Rebuild: true, Build: b.build}
		if res, err := r.Resolve(ctx, s); err != nil || res.From != FromBuilt || b.calls != 1 {
			t.Errorf("expected a build although the source holds the SBOM, got %v, %d builds", err, b.calls)
		}
	})
}

func TestCatalogDrift(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	s := imageSubject(t)
	src := source(t, corpusWithDeb(t, s))
	r := &Resolver{Sources: []*claims.Source{src}, Catalog: pinned("syft@v1.52.0"), Build: (&builder{}).build}
	res, err := r.Resolve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if res.From != FromSource || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "subject deb") || !strings.Contains(res.Warnings[0], "1.54.1") || !strings.Contains(res.Warnings[0], "1.52.0") {
		t.Errorf("expected the corpus SBOM and a warning naming the subject and both versions, got %s %v", res.From, res.Warnings)
	}
	r.Catalog = nil
	if res, _ := r.Resolve(context.Background(), s); len(res.Warnings) != 0 {
		t.Errorf("a gate with no catalog warned: %v", res.Warnings)
	}
}

// oracle is a published SBOM with rpm and python packages, from the vulnerability-match-labels
// fixture.
func oracle(t *testing.T) string {
	t.Helper()
	f, err := os.Open(fixture.Path("vml", "sbom", "docker.io+oraclelinux@sha256-a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495.syft.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "oracle.syft.json")
	write(t, p, data)
	return p
}

func TestKeepTypes(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("YARDSTICK_CACHE_DIR", cacheDir)
	p := oracle(t)
	r := &Resolver{}
	full, err := r.Resolve(context.Background(), documentSubject(t, p))
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Resolve(context.Background(), documentSubject(t, p, "python"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Types(), []string{"python"}) || !slices.Contains(full.Types(), "rpm") {
		t.Errorf("expected only python packages, got %v (unfiltered %v)", res.Types(), full.Types())
	}
	if res.UnfilteredDigest != full.Digest || res.Digest == full.Digest || res.Dir != full.Dir {
		t.Errorf("expected the unfiltered digest kept and addressing the labels, got %s / %s", res.UnfilteredDigest, res.Digest)
	}
	want := filepath.Join(cacheDir, "sboms-filtered", strings.ReplaceAll(full.Digest, ":", "-"), "python.syft.json")
	if res.SBOM != want {
		t.Errorf("expected the filtered SBOM cached at %s, got %s", want, res.SBOM)
	}
	// every relationship left is between packages kept, or a package and a file
	sb, err := Decode(res.SBOM)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range sb.Relationships {
		for _, id := range []string{string(rel.From.ID()), string(rel.To.ID())} {
			if p := full.pkg(id); p != nil && p.Type != "python" {
				t.Errorf("a relationship to a dropped %s package survived: %s", p.Type, p.Name)
			}
		}
	}
	// a rerun reads the cached filter
	age(t, res.SBOM)
	again, err := r.Resolve(context.Background(), documentSubject(t, p, "python"))
	if err != nil || again.Digest != res.Digest {
		t.Errorf("expected the same filtered SBOM from the cache, got %v", err)
	}
	touched(t, res.SBOM)
	_, err = r.Resolve(context.Background(), documentSubject(t, p, "java-archive"))
	if err == nil || !strings.Contains(err.Error(), "oracle.syft.json") || !strings.Contains(err.Error(), "java-archive") {
		t.Errorf("expected a filter that keeps nothing to fail naming the subject and filter, got %v", err)
	}
}

func (r *Resolved) pkg(id string) *Package {
	for i := range r.Packages {
		if r.Packages[i].ID == id {
			return &r.Packages[i]
		}
	}
	return nil
}

func TestFrozen(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	s := imageSubject(t)
	unpullable := &builder{err: errors.New("unable to pull docker.io/anchore/yardstick-fixture-deb: manifest unknown")}
	r := &Resolver{Sources: []*claims.Source{source(t, corpusWithDeb(t, s))}, Catalog: pinned("syft@v1.54.1"), Rebuild: true, Build: unpullable.build}
	res, err := r.Resolve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Frozen || res.From != FromSource || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "manifest unknown") {
		t.Errorf("expected the corpus SBOM scanned and the subject frozen with why, got %+v", res)
	}
	// frozen is derived each run, never stored: a source with nothing for it fails as any miss
	r.Sources = []*claims.Source{source(t, t.TempDir())}
	if _, err := r.Resolve(context.Background(), s); err == nil || !strings.Contains(err.Error(), "manifest unknown") {
		t.Errorf("expected an unpullable image with no SBOM to fail, got %v", err)
	}
}

func TestPlatformWarnings(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	s := imageSubject(t)
	r := &Resolver{Sources: []*claims.Source{source(t, corpusWithDeb(t, s))}, Catalog: &gatefile.Catalog{Syft: "syft@v1.54.1", Platform: "linux/amd64"}}
	res, err := r.Resolve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if res.Platform != "linux/amd64" {
		t.Errorf("expected the effective catalog's platform recorded, got %q", res.Platform)
	}
	got := res.PlatformWarnings([]string{"linux/amd64", "linux/arm64"})
	if len(got) != 1 || !strings.Contains(got[0], "subject deb") || !strings.Contains(got[0], "linux/arm64") || !strings.Contains(got[0], "linux/amd64") {
		t.Errorf("expected one warning naming the subject and both platforms, got %v", got)
	}
}

// a claims source's catalog.yaml is data: it may not choose a binary or set variables beyond
// syft's own, while the gate's own catalog: may
func TestSourceCatalogIsData(t *testing.T) {
	s := imageSubject(t)
	for _, tc := range []struct{ name, catalog, want string }{
		{"syft by path", "syft: ./bin/syft\n", "not a path to a binary"},
		{"syft by absolute path", "syft: /usr/local/bin/syft\n", "not a path to a binary"},
		{"a loader variable", "syft: syft@v1.54.1\nenv: {LD_PRELOAD: /tmp/x.so}\n", "only SYFT_* variables, got LD_PRELOAD"},
		{"a proxy variable", "syft: syft@v1.54.1\nenv: {SYFT_PARALLELISM: '2', HTTPS_PROXY: http://attacker:8080}\n", "got HTTPS_PROXY"},
		{"an output file variable", "syft: syft@v1.54.1\nenv: {SYFT_LEGACYFILE: ~/.ssh/authorized_keys}\n", "may not set SYFT_LEGACYFILE"},
		{"a registry variable", "syft: syft@v1.54.1\nenv: {SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY: 'true'}\n", "may not set SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY"},
		{"an output file in the config", "syft: syft@v1.54.1\nconfig: syft.yaml\n", "got legacyFile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
			dir := t.TempDir()
			write(t, filepath.Join(dir, corpus.CatalogFile), []byte(tc.catalog))
			write(t, filepath.Join(dir, "syft.yaml"), []byte("scope: all-layers\nlegacyFile: ~/.ssh/authorized_keys\n"))
			b := &builder{}
			_, err := (&Resolver{Sources: []*claims.Source{source(t, dir)}, Build: b.build}).Resolve(context.Background(), s)
			if err == nil || !strings.Contains(err.Error(), "claims source "+dir) || !strings.Contains(err.Error(), tc.want) || b.calls != 0 {
				t.Errorf("expected a refusal naming the source and %q with no build, got %v (%d builds)", tc.want, err, b.calls)
			}
		})
	}
	t.Run("syft variables from a source", func(t *testing.T) {
		t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
		dir := t.TempDir()
		write(t, filepath.Join(dir, corpus.CatalogFile), []byte("syft: syft@v1.54.1\nenv: {SYFT_PARALLELISM: '2'}\n"))
		b := &builder{}
		if _, err := (&Resolver{Sources: []*claims.Source{source(t, dir)}, Build: b.build}).Resolve(context.Background(), s); err != nil || b.got.Env["SYFT_PARALLELISM"] != "2" {
			t.Errorf("expected a build with the source's SYFT_* env, got %v", err)
		}
	})
	t.Run("a syft binary by path is keyed by its bytes", func(t *testing.T) {
		t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
		syft := filepath.Join(t.TempDir(), "syft")
		write(t, syft, []byte("one build of syft"))
		b := &builder{}
		resolve := func() {
			t.Helper()
			if _, err := (&Resolver{Catalog: &gatefile.Catalog{Syft: syft}, Build: b.build}).Resolve(context.Background(), s); err != nil {
				t.Fatal(err)
			}
		}
		resolve()
		resolve()
		if b.calls != 1 {
			t.Fatalf("expected the second resolve to reuse the cached SBOM, got %d builds", b.calls)
		}
		write(t, syft, []byte("a rebuilt syft"))
		resolve()
		if b.calls != 2 {
			t.Errorf("expected a rebuilt syft at the same path to build again, got %d builds", b.calls)
		}
	})
	t.Run("the gate's own catalog", func(t *testing.T) {
		t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
		b := &builder{}
		gate := &gatefile.Catalog{Syft: "/opt/syft/bin/syft", Env: map[string]string{"LD_LIBRARY_PATH": "/opt/syft/lib"}}
		if _, err := (&Resolver{Catalog: gate, Build: b.build}).Resolve(context.Background(), s); err != nil || b.got.Syft != gate.Syft {
			t.Errorf("expected the gate's catalog used as written, got %v", err)
		}
	})
}

// age sets a cache entry's modification time to 20 days ago, and touched says whether a later use
// moved it to now: cache-entries-record-last-use.
func age(t *testing.T, path string) {
	t.Helper()
	old := time.Now().Add(-20 * 24 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func touched(t *testing.T, path string) {
	t.Helper()
	if info, err := os.Stat(path); err != nil || time.Since(info.ModTime()) > time.Minute {
		t.Errorf("expected %s used by this run, got modification time %v, %v", path, info.ModTime(), err)
	}
}
