package claims

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
)

// bundle zips a corpus directory the way the publish workflow does: entries sorted, paths
// relative to the corpus root under prefix, one fixed time and mode.
func bundle(t *testing.T, root, prefix string) []byte {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			paths = append(paths, filepath.ToSlash(rel))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range paths {
		h := &zip.FileHeader{Name: prefix + p, Method: zip.Deflate, Modified: time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)}
		h.SetMode(0o644)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// host stands in for the publication bucket: snapshots by digest, commit records, the latest
// pointer, and a log of every request.
type host struct {
	*httptest.Server
	mu        sync.Mutex
	objects   map[string][]byte
	requests  []string
	bytesSent int
	// cutAfter, when set, sends only that many bytes of a snapshot and drops the connection
	cutAfter int
}

func newHost(t *testing.T) *host {
	t.Helper()
	h := &host{objects: map[string][]byte{}}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		data, ok := h.objects[r.URL.Path]
		h.requests = append(h.requests, r.URL.Path+" "+r.Header.Get("Range"))
		cut := h.cutAfter
		h.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		cw := &countingWriter{ResponseWriter: w, h: h}
		if cut > 0 && strings.HasPrefix(r.URL.Path, "/claims/snapshots/") {
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			_, _ = cw.Write(data[:cut])
			panic(http.ErrAbortHandler)
		}
		http.ServeContent(cw, r, "", time.Time{}, bytes.NewReader(data))
	}))
	t.Cleanup(h.Close)
	t.Setenv(URLVar, h.URL)
	return h
}

type countingWriter struct {
	http.ResponseWriter
	h *host
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.h.mu.Lock()
	c.h.bytesSent += len(p)
	c.h.mu.Unlock()
	return c.ResponseWriter.Write(p)
}

// publish puts a corpus up as a snapshot, returning its digest.
func (h *host) publish(t *testing.T, root string) string {
	t.Helper()
	data := bundle(t, root, "")
	sum := sha256.Sum256(data)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.objects["/claims/snapshots/"+hex.EncodeToString(sum[:])+".zip"] = data
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (h *host) put(t *testing.T, path string, v any) {
	t.Helper()
	data, _ := json.Marshal(v)
	h.mu.Lock()
	h.objects[path] = data
	h.mu.Unlock()
}

func (h *host) reset() {
	h.mu.Lock()
	h.requests, h.bytesSent = nil, 0
	h.mu.Unlock()
}

func openRemoteAt(t *testing.T, ref string) (*Source, error) {
	t.Helper()
	return Open(gatefile.Source{Locator: "github.com/anchore/delta-prototype@" + ref, Remote: &gatefile.Remote{Repository: "github.com/anchore/delta-prototype", Ref: ref}})
}

// the published snapshot passes the suite every source kind does
func TestRemoteSnapshot(t *testing.T) {
	h := newHost(t)
	conformance(t, func(t *testing.T, root string) *Source {
		t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
		s, err := openRemoteAt(t, h.publish(t, root))
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

// remote-reference-resolution
func TestRemoteReferenceResolution(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	h := newHost(t)
	older := h.publish(t, corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP))))
	newer := h.publish(t, corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.TP))))
	const commit = "4f2a9c1e00000000000000000000000000000000"
	h.put(t, "/claims/commits/"+commit+".json", pointer{Digest: older})
	h.put(t, "/claims/latest-v1.json", pointer{Digest: newer, Commit: "77aa000000000000000000000000000000000000"})

	s, err := openRemoteAt(t, "main")
	if err != nil || s.Digest != newer || s.Commit != "77aa000000000000000000000000000000000000" {
		t.Fatalf("expected @main to load the snapshot latest-v1.json names, got %v %+v", err, s)
	}
	h.reset()
	s, err = openRemoteAt(t, commit)
	if err != nil || s.Digest != older {
		t.Fatalf("expected the commit's snapshot, got %v", err)
	}
	for _, r := range h.requests {
		if strings.Contains(r, "latest") {
			t.Errorf("a pinned reference read a latest pointer: %s", r)
		}
	}
	if _, err := openRemoteAt(t, "deadbeef00000000000000000000000000000000"); err == nil || !strings.Contains(err.Error(), "deadbeef00000000000000000000000000000000") {
		t.Errorf("expected an unpublished commit to fail naming it, got %v", err)
	}
	// unset, the default host is read
	t.Setenv(URLVar, "")
	orig := defaultURL
	defaultURL = h.URL
	t.Cleanup(func() { defaultURL = orig })
	if s, err := openRemoteAt(t, "main"); err != nil || s.Digest != newer {
		t.Errorf("expected no %s to read the default host, got %v", URLVar, err)
	}
}

// a corpus big enough that reading one subject is a small part of it: the oraclelinux SBOM is
// several hundred KiB deflated
func bigCorpus(t *testing.T) string {
	t.Helper()
	root := corpus(t,
		at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP)),
		at(claimsv1.TypeFile(otherDir, "deb"), label(libudv, "CVE-2021-33910", claimsv1.TP)),
	)
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
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(otherDir), claimsv1.ImageSBOMFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func snapshotRequests(h *host) (n int) {
	for _, r := range h.requests {
		if strings.HasPrefix(r, "/claims/snapshots/") {
			n++
		}
	}
	return n
}

// snapshot-cached-once-by-digest and snapshot-read-in-place
func TestSnapshotReadInPlace(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("YARDSTICK_CACHE_DIR", cacheDir)
	h := newHost(t)
	digest := h.publish(t, bigCorpus(t))
	h.put(t, "/claims/latest-v1.json", pointer{Digest: digest, Commit: "77aa000000000000000000000000000000000000"})
	zipped := h.objects["/claims/snapshots/"+strings.TrimPrefix(digest, "sha256:")+".zip"]

	read := func() (*Source, error) {
		t.Helper()
		s, err := openRemoteAt(t, "main")
		if err != nil {
			return nil, err
		}
		got, err := setOf(t, s).Read(Subject{Name: "test-image", Dir: dir, Types: []string{"deb"}})
		if err != nil || len(got.Labels) != 1 {
			t.Fatalf("expected the subject's one label, got %v %v", got, err)
		}
		return s, nil
	}
	cached := func() []string {
		entries, _ := os.ReadDir(filepath.Join(cacheDir, "claims"))
		var out []string
		for _, e := range entries {
			out = append(out, e.Name())
		}
		return out
	}

	// a download cut off partway is never read and leaves nothing behind
	h.cutAfter = len(zipped) / 2
	if _, err := read(); err == nil {
		t.Fatal("expected a cut-off download to fail the run")
	}
	if got := cached(); len(got) != 0 {
		t.Errorf("expected nothing of a partial download in the cache, got %v", got)
	}

	// the next run downloads the whole zip once, and reads only the subject's entries from it
	h.cutAfter = 0
	h.reset()
	s, err := read()
	if err != nil {
		t.Fatal(err)
	}
	if snapshotRequests(h) != 1 || h.bytesSent < len(zipped) {
		t.Errorf("expected the pointer and one whole download, got %d bytes of %d in %v", h.bytesSent, len(zipped), h.requests)
	}
	for _, r := range h.requests {
		if strings.Contains(r, "bytes=") {
			t.Errorf("a range was requested: %s", r)
		}
	}
	// the other image's entries, its large SBOM among them, are never decompressed
	if got := s.Read(); len(got) != 1 || got[0] != dir+"/deb.json" {
		t.Errorf("expected only the subject's entries read, got %v", got)
	}
	// nothing extracted: the cache holds the zip, named by its digest, and nothing else
	if got := cached(); len(got) != 1 || got[0] != strings.TrimPrefix(digest, "sha256:")+".zip" {
		t.Errorf("expected only <hex>.zip in the cache, got %v", got)
	}

	h.reset()
	zipPath := filepath.Join(cacheDir, "claims", strings.TrimPrefix(digest, "sha256:")+".zip")
	old := time.Now().Add(-20 * 24 * time.Hour)
	if err := os.Chtimes(zipPath, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := read(); err != nil {
		t.Fatal(err)
	}
	if snapshotRequests(h) != 0 || len(h.requests) != 1 {
		t.Errorf("expected the second run to fetch only the pointer, got %v", h.requests)
	}
	// cache-entries-record-last-use: reading the snapshot again is a use
	if info, err := os.Stat(zipPath); err != nil || time.Since(info.ModTime()) > time.Minute {
		t.Errorf("expected the snapshot used by this run, got modification time %v, %v", info.ModTime(), err)
	}
}

func TestCorruptedSnapshot(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("YARDSTICK_CACHE_DIR", cacheDir)
	h := newHost(t)
	digest := h.publish(t, bigCorpus(t))
	key := "/claims/snapshots/" + strings.TrimPrefix(digest, "sha256:") + ".zip"
	h.objects[key] = append([]byte(nil), h.objects[key]...)
	h.objects[key][100] ^= 0xff
	_, err := openRemoteAt(t, digest)
	if err == nil || !strings.Contains(err.Error(), digest) || !strings.Contains(err.Error(), "digest is sha256:") {
		t.Fatalf("expected a failure naming both digests, got %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(cacheDir, "claims")); len(entries) != 0 {
		t.Errorf("expected the download deleted, got %v", entries)
	}
}

// a digest or commit becomes a cache path and a URL: one that is not lowercase hex of its length
// is refused before either is built, from a gate's reference or a pointer the host serves
func TestRemoteDigestsAreHex(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("YARDSTICK_CACHE_DIR", cacheDir)
	h := newHost(t)
	good := h.publish(t, corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP))))
	traversal := "sha256:" + strings.Repeat("../", 21) + "x"
	const commit = "4f2a9c1e00000000000000000000000000000000"
	for _, tc := range []struct {
		name, ref string
		latest    pointer
		commit    pointer
		want      string
	}{
		{"from a reference", traversal, pointer{}, pointer{}, "is not sha256:<64 lowercase hex>"},
		{"uppercase hex in a reference", "sha256:" + strings.ToUpper(strings.TrimPrefix(good, "sha256:")), pointer{}, pointer{}, "is not sha256:<64 lowercase hex>"},
		{"from the latest pointer", "main", pointer{Digest: traversal}, pointer{}, "is not sha256:<64 lowercase hex>"},
		{"from a commit record", commit, pointer{}, pointer{Digest: traversal}, "is not sha256:<64 lowercase hex>"},
		{"a commit in the latest pointer", "main", pointer{Digest: good, Commit: "../../../../../../../../../../../../../x"}, pointer{}, "is not a 40-character lowercase hex sha"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.put(t, "/claims/latest-v1.json", tc.latest)
			h.put(t, "/claims/commits/"+commit+".json", tc.commit)
			h.reset()
			_, err := openRemoteAt(t, tc.ref)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected a refusal saying %q, got %v", tc.want, err)
			}
			if snapshotRequests(h) != 0 {
				t.Errorf("a snapshot was requested: %v", h.requests)
			}
			if entries, _ := os.ReadDir(cacheDir); len(entries) != 0 {
				t.Errorf("the cache was written: %v", entries)
			}
		})
	}
}

// github stands in for GitHub's API: refs resolved to commits, each commit's archive holding a
// corpus under tests/quality/claims, and a log of every request with its credentials.
type github struct {
	*httptest.Server
	mu       sync.Mutex
	refs     map[string]string // ref to commit
	archives map[string][]byte // commit to zipball
	requests []string
}

func newGitHub(t *testing.T) *github {
	t.Helper()
	g := &github{refs: map[string]string{}, archives: map[string][]byte{}}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.requests = append(g.requests, r.URL.Path+" "+r.Header.Get("Authorization"))
		if ref, ok := strings.CutPrefix(r.URL.Path, "/repos/anchore/vunnel/commits/"); ok && r.Header.Get("Accept") == "application/vnd.github.sha" {
			if c, ok := g.refs[ref]; ok {
				_, _ = io.WriteString(w, c)
				return
			}
		}
		if data, ok := g.archives[strings.TrimPrefix(r.URL.Path, "/repos/anchore/vunnel/zipball/")]; ok {
			_, _ = w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(g.Close)
	orig := githubAPI
	githubAPI = g.URL
	t.Cleanup(func() { githubAPI = orig })
	return g
}

// push makes root the claims directory at ref, returning the commit.
func (g *github) push(t *testing.T, ref, root string) string {
	t.Helper()
	data := bundle(t, root, "anchore-vunnel-0000000/tests/quality/claims/")
	sum := sha256.Sum256(data)
	commit := hex.EncodeToString(sum[:20])
	g.mu.Lock()
	g.refs[ref], g.archives[commit] = commit, data
	g.mu.Unlock()
	return commit
}

func openArchiveAt(t *testing.T, p, ref string) (*Source, error) {
	t.Helper()
	return Open(gatefile.Source{Locator: "github.com/anchore/vunnel/" + p + "@" + ref, Remote: &gatefile.Remote{Repository: "github.com/anchore/vunnel", Path: p, Ref: ref}})
}

// a claims directory in another repository passes the suite every source kind does
func TestRepositoryClaimsDirectory(t *testing.T) {
	g := newGitHub(t)
	conformance(t, func(t *testing.T, root string) *Source {
		t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
		g.push(t, "main", root)
		s, err := openArchiveAt(t, "tests/quality/claims", "main")
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

// @main re-resolves on every open and downloads an archive once per commit
func TestRepositoryArchiveCachedByCommit(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("YARDSTICK_CACHE_DIR", cacheDir)
	t.Setenv("GITHUB_TOKEN", "")
	g := newGitHub(t)
	first := g.push(t, "main", corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP))))
	downloads := func() (n int) {
		g.mu.Lock()
		defer g.mu.Unlock()
		for _, r := range g.requests {
			if strings.Contains(r, "/zipball/") {
				n++
			}
		}
		return n
	}
	for range 2 {
		s, err := openArchiveAt(t, "tests/quality/claims", "main")
		if err != nil || s.Commit != first {
			t.Fatalf("expected commit %s, got %v %+v", first, err, s)
		}
	}
	if downloads() != 1 {
		t.Errorf("expected one download of an unchanged commit, got %v", g.requests)
	}

	// main moves: the next open downloads the new commit's archive
	second := g.push(t, "main", corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.TP))))
	s, err := openArchiveAt(t, "tests/quality/claims", "main")
	if err != nil || s.Commit != second || !s.Downloaded || downloads() != 2 {
		t.Fatalf("expected the moved main downloaded, got %v %+v %v", err, s, g.requests)
	}
	got, err := setOf(t, s).Read(Subject{Name: "test-image", Dir: dir, Types: []string{"deb"}})
	if err != nil || len(got.Labels) != 1 || got.Labels[0].Verdict != claimsv1.TP {
		t.Errorf("expected the new commit's label, got %+v %v", got, err)
	}

	// a full commit is read from the cache without asking GitHub anything
	g.mu.Lock()
	g.requests = nil
	g.mu.Unlock()
	if s, err := openArchiveAt(t, "tests/quality/claims", first); err != nil || s.Downloaded || len(g.requests) != 0 {
		t.Errorf("expected a cached commit opened offline, got %v %v", err, g.requests)
	}

	// GITHUB_TOKEN goes with every request when it is set
	t.Setenv("GITHUB_TOKEN", "s3cret")
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	if _, err := openArchiveAt(t, "tests/quality/claims", "main"); err != nil {
		t.Fatal(err)
	}
	for _, r := range g.requests {
		if !strings.HasSuffix(r, " Bearer s3cret") {
			t.Errorf("expected the token sent, got %q", r)
		}
	}
}

// a path the archive does not hold is an error naming the repository, ref and path
func TestRepositoryPathMissing(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	g := newGitHub(t)
	g.push(t, "main", corpus(t))
	_, err := openArchiveAt(t, "tests/quality/nope", "main")
	if err == nil || !strings.Contains(err.Error(), "github.com/anchore/vunnel at main has no directory tests/quality/nope") {
		t.Errorf("expected the repository, ref and path named, got %v", err)
	}
	if _, err := openArchiveAt(t, "tests/quality/claims", "gone"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("expected an unknown ref refused, got %v", err)
	}
}

// reopening a set reuses its remote sources, with no request to the host, and opens local ones again
func TestReopenReusesRemoteSources(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	h := newHost(t)
	digest := h.publish(t, corpus(t))
	h.put(t, "/claims/latest-v1.json", pointer{Digest: digest})
	sources := []gatefile.Source{
		{Locator: "github.com/anchore/delta-prototype@main", Remote: &gatefile.Remote{Repository: "github.com/anchore/delta-prototype", Ref: "main"}},
		{Locator: t.TempDir()},
	}
	set, err := OpenSet(sources)
	if err != nil {
		t.Fatal(err)
	}
	h.reset()
	again, err := set.Reopen(sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.requests) != 0 {
		t.Errorf("expected no request on reopen, got %v", h.requests)
	}
	if again.Sources[0] != set.Sources[0] || again.Sources[1] == set.Sources[1] {
		t.Error("expected the remote source reused and the local one opened again")
	}
	if err := again.Close(); err != nil {
		t.Error(err)
	}
	if _, err := fs.ReadFile(again.Sources[0].FS, claimsv1.VocabularyFile); err == nil {
		t.Error("expected a closed snapshot unreadable")
	}
}

// set swaps a package variable for the length of a test
func set[T any](t *testing.T, v *T, to T) {
	t.Helper()
	orig := *v
	*v = to
	t.Cleanup(func() { *v = orig })
}

// the host the digest comes from is https, or this machine
func TestClaimsURLMustBeHTTPS(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	for _, base := range []string{"http://yardstick.example.com", "ftp://yardstick.example.com"} {
		t.Setenv(URLVar, base)
		if _, err := openRemoteAt(t, "main"); err == nil || !strings.Contains(err.Error(), "must be an https:// URL") {
			t.Errorf("%s: expected refused, got %v", base, err)
		}
	}
	for _, base := range []string{"https://yardstick.example.com", "http://127.0.0.1:1", "http://localhost:1", "http://[::1]:1"} {
		if err := checkBase(base); err != nil {
			t.Errorf("%s: expected allowed, got %v", base, err)
		}
	}
}

// a snapshot over the size cap is refused while it downloads, and a file over the file cap
// before a byte of it is read
func TestSnapshotSizeLimits(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	h := newHost(t)
	digest := h.publish(t, bigCorpus(t))
	size := int64(len(h.objects["/claims/snapshots/"+strings.TrimPrefix(digest, "sha256:")+".zip"]))

	set(t, &maxDownload, size-1)
	if _, err := openRemoteAt(t, digest); err == nil || !strings.Contains(err.Error(), "more than a claims snapshot may be") {
		t.Fatalf("expected a snapshot over the cap refused, got %v", err)
	}
	set(t, &maxDownload, size)
	s, err := openRemoteAt(t, digest)
	if err != nil {
		t.Fatal(err)
	}
	set(t, &maxFile, 10)
	if _, err := s.ReadFile(claimsv1.VocabularyFile); err == nil || !strings.Contains(err.Error(), "uncompressed") {
		t.Errorf("expected a file over the cap refused, got %v", err)
	}
}

// a download is bounded by the gaps between bytes, not its whole length: a slow one that keeps
// moving finishes, and one that stalls is given up
func TestDownloadIdleTimeout(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	data := bytes.Repeat([]byte("x"), 10)
	var stall atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		for i, b := range data {
			if stall.Load() && i == 5 {
				<-r.Context().Done()
				return
			}
			_, _ = w.Write([]byte{b})
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	t.Cleanup(srv.Close)
	set(t, &downloadIdle, 100*time.Millisecond)

	dir := t.TempDir()
	if err := download(srv.URL, "", dir, filepath.Join(dir, "moving.zip")); err != nil {
		t.Errorf("expected a slow download that keeps moving to finish, got %v", err)
	}
	stall.Store(true)
	if err := download(srv.URL, "", dir, filepath.Join(dir, "stalled.zip")); err == nil || !strings.Contains(err.Error(), "no data for") {
		t.Errorf("expected a stalled download given up, got %v", err)
	}
}
