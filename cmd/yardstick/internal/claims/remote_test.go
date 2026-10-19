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
	"testing"
	"time"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
)

// bundle zips a corpus directory the way the publish workflow does: entries sorted, paths
// relative to the corpus root, one fixed time and mode.
func bundle(t *testing.T, root string) []byte {
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
		h := &zip.FileHeader{Name: p, Method: zip.Deflate, Modified: time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)}
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
	data := bundle(t, root)
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
