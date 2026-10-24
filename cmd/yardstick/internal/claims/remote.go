package claims

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/bus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// URLVar names the base URL published snapshots are read from: the public address of the bucket
// the publish workflow writes claims/matches/latest-v<major>.json, claims/matches/commits/<sha>.json
// and claims/matches/snapshots/<hex>.zip into. Unset, snapshots are read from DefaultURL.
const URLVar = "YARDSTICK_CLAIMS_URL"

// publishedRoot is where the match label snapshots and their pointers are published, beside any
// other label kind's
const publishedRoot = "/claims/" + corpus.MatchesDir

// DefaultURL is where anchore/claims publishes its snapshots.
const DefaultURL = "https://yardstick.anchore.io"

var (
	// defaultURL is DefaultURL, a variable so a test never reaches the real host
	defaultURL    = DefaultURL
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// httpClient reads pointers and resolves refs, small reads with a timeout for the whole request
	httpClient = &http.Client{Timeout: 2 * time.Minute}
	// downloadClient fetches whole snapshots, which on a slow link can take longer than any
	// whole-request timeout while still moving: it bounds connecting and the wait for headers, and
	// download bounds the gaps between bytes
	downloadClient = &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: time.Minute,
	}}
	// downloadIdle is how long a download may go without a byte before it is given up
	downloadIdle = time.Minute
	// maxDownload and maxFile bound a snapshot and any one file in it, uncompressed: a claims source
	// can be a third party's repository, and a zip bomb there is refused rather than read
	maxDownload int64 = 4 << 30
	maxFile     int64 = 512 << 20
	// githubAPI is where a claims directory in a GitHub repository is resolved and downloaded from,
	// a variable for the same reason
	githubAPI = "https://api.github.com"
)

// pointer is a published JSON object naming a snapshot.
type pointer struct {
	Digest string `json:"digest"`
	Commit string `json:"commit,omitempty"`
}

// openRemote resolves a published reference to its snapshot and opens the snapshot's zip in
// place, once it is downloaded whole and verified: @main through the latest pointer for the format major this yardstick reads, @<commit>
// through that commit's record, and @sha256:<hex> directly.
func openRemote(s gatefile.Source) (*Source, error) {
	base := strings.TrimSuffix(os.Getenv(URLVar), "/")
	if base == "" {
		base = defaultURL
	}
	if err := checkBase(base); err != nil {
		return nil, fmt.Errorf("claims source %s: %w", s.Locator, err)
	}
	// a digest names its snapshot already; anything else is read from the host
	var resolving *bus.Task
	if !strings.HasPrefix(s.Remote.Ref, "sha256:") {
		resolving = bus.StartTask(event.ResolveClaims, "%s", s.Locator)
	}
	p, err := resolve(base, s.Remote.Ref)
	resolving.Done(err)
	if err != nil {
		return nil, fmt.Errorf("claims source %s: %w", s.Locator, err)
	}
	log.Infof("opening remote claims source %s, resolved to snapshot %s", s.Locator, p.Digest)
	// resolve accepts only sha256:<64 lowercase hex>, so the digest is safe in a path and a URL
	hexDigest := strings.TrimPrefix(p.Digest, "sha256:")
	final := filepath.Join(cache.Dir("claims"), hexDigest+".zip")
	f, size, downloaded, err := openSnapshot(base+publishedRoot+"/snapshots/"+hexDigest+".zip", final, p.Digest, details(s.Locator, p))
	if err != nil {
		return nil, fmt.Errorf("claims source %s: snapshot %s: %w", s.Locator, p.Digest, err)
	}
	// read in place, never extracted; the file stays open until the source is closed
	zr, err := zip.NewReader(f, size)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("claims source %s: snapshot %s: %w", s.Locator, p.Digest, err)
	}
	return &Source{Locator: s.Locator, Kind: Remote, FS: boundedFS{zr}, Digest: p.Digest, Commit: p.Commit, Downloaded: downloaded, closer: f, read: map[string]string{}}, nil
}

// openArchive reads a claims directory in a GitHub repository: the ref is resolved to its commit,
// and that commit's archive is opened in place from the cache, downloaded first when it is not
// there, the way a snapshot is. A commit names its archive's content, so @main re-resolves on
// every open and downloads only when the commit moved.
func openArchive(s gatefile.Source) (*Source, error) {
	r := s.Remote
	host, repo, _ := strings.Cut(r.Repository, "/")
	if host != "github.com" {
		return nil, fmt.Errorf("claims source %s: a claims directory is read only from a github.com repository", s.Locator)
	}
	commit := r.Ref
	if !commitPattern.MatchString(commit) {
		resolving := bus.StartTask(event.ResolveClaims, "%s", s.Locator)
		var err error
		commit, err = resolveCommit(repo, r.Ref)
		resolving.Done(err)
		if err != nil {
			return nil, fmt.Errorf("claims source %s: %w", s.Locator, err)
		}
	}
	log.Infof("opening claims directory %s, resolved to commit %s", s.Locator, commit)
	fail := func(err error) error {
		return fmt.Errorf("claims source %s: commit %s: %w", s.Locator, commit, err)
	}
	// the commit is checked hex and the repository is the gate file's [A-Za-z0-9_.-] segments, none
	// of them only dots, so both are safe in a file name and a URL
	final := filepath.Join(cache.Dir("claims"), "github-"+strings.ReplaceAll(repo, "/", "-")+"-"+commit+".zip")
	f, size, downloaded, err := openSnapshot(githubAPI+"/repos/"+repo+"/zipball/"+commit, final, "", []string{s.Locator, "commit " + commit})
	if err != nil {
		return nil, fail(err)
	}
	src, err := archiveDir(f, size, r)
	if err != nil {
		f.Close()
		return nil, fail(err)
	}
	return &Source{Locator: s.Locator, Kind: Remote, FS: src, Commit: commit, Downloaded: downloaded, closer: f, read: map[string]string{}}, nil
}

// archiveDir is the claims directory inside a GitHub repository archive.
func archiveDir(f *os.File, size int64, r *gatefile.Remote) (fs.FS, error) {
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return nil, err
	}
	// GitHub's archive holds the repository under one top-level directory, <owner>-<repo>-<short sha>
	top, err := fs.ReadDir(zr, ".")
	if err != nil || len(top) != 1 || !top[0].IsDir() {
		return nil, errors.New("the archive is not one top-level directory")
	}
	dir := path.Join(top[0].Name(), r.Path)
	if info, err := fs.Stat(zr, dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%s at %s has no directory %s", r.Repository, r.Ref, r.Path)
	}
	return fs.Sub(boundedFS{zr}, dir)
}

// boundedFS refuses to open a file over maxFile. A zip entry's size is the uncompressed size it
// declares, and archive/zip fails a read that inflates past it, so nothing larger is ever read.
type boundedFS struct{ fs.FS }

func (b boundedFS) Open(name string) (fs.File, error) {
	f, err := b.FS.Open(name)
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err == nil && !info.IsDir() && info.Size() > maxFile {
		f.Close()
		return nil, fmt.Errorf("%s is %d bytes uncompressed, over the %d bytes a claims file may be", name, info.Size(), maxFile)
	}
	return f, nil
}

// checkBase refuses a snapshot host over plain http unless it is this machine: the pointer it
// serves carries the digest the snapshot is checked against, so a host anyone on the path can
// answer for verifies nothing.
func checkBase(base string) error {
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("%s %q: %w", URLVar, base, err)
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && loopback(u.Hostname()):
		return nil
	}
	return fmt.Errorf("%s %q must be an https:// URL (http:// only for a loopback host)", URLVar, base)
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// resolveCommit asks GitHub which commit a branch, tag or short sha names.
func resolveCommit(repo, r string) (string, error) {
	u := githubAPI + "/repos/" + repo + "/commits/" + r
	req, err := http.NewRequest(http.MethodGet, u, nil) //nolint:noctx // a short read; the client has a timeout
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github.sha")
	resp, err := do(httpClient, req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", u, err)
	}
	// the commit becomes part of a cache path and a URL
	commit := strings.TrimSpace(string(body))
	if !commitPattern.MatchString(commit) {
		return "", fmt.Errorf("GET %s: %q is not a 40-character lowercase hex sha", u, commit)
	}
	return commit, nil
}

// do sends a request, with GITHUB_TOKEN as its credentials when it goes to GitHub's API. The
// client drops them on the redirect from there to the archive host.
func do(c *http.Client, req *http.Request) (*http.Response, error) {
	if t := os.Getenv("GITHUB_TOKEN"); t != "" && strings.HasPrefix(req.URL.String(), githubAPI+"/") {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	return c.Do(req) //nolint:gosec // every caller builds the URL from a fixed host and checked path segments
}

// Details names a remote source's snapshot in full, as the line under its download does.
func (s *Source) Details() []string {
	return details(s.Locator, pointer{Digest: s.Digest, Commit: s.Commit})
}

func details(locator string, p pointer) []string {
	// only the commit is labeled: a locator and a sha256: digest say what they are, and the digest
	// fits an 80-column line whole
	d := []string{locator}
	if p.Commit != "" {
		d = append(d, "commit "+p.Commit)
	}
	if p.Digest == "" {
		// a claims directory in a repository is named by its commit alone
		return d
	}
	return append(d, p.Digest)
}

// resolve turns a reference into the snapshot it names. A digest or commit becomes part of a
// cache path and a URL, so each is checked to be lowercase hex of its length wherever it comes
// from: the gate file or a pointer the host serves.
func resolve(base, r string) (pointer, error) {
	var p pointer
	switch {
	case strings.HasPrefix(r, "sha256:"):
		p.Digest = r
	case r == "main":
		u := base + publishedRoot + "/latest-" + claimsv1.Major + ".json"
		if err := getJSON(u, &p); err != nil {
			return p, fmt.Errorf("no published snapshot of label format %s: %w", claimsv1.Major, err)
		}
	case commitPattern.MatchString(r):
		if err := getJSON(base+publishedRoot+"/commits/"+r+".json", &p); err != nil {
			return p, fmt.Errorf("no snapshot was published for commit %s: %w", r, err)
		}
		p.Commit = r
	default:
		return p, fmt.Errorf("%q names no snapshot: use @main, the full 40-character commit sha, or @sha256:<snapshot digest>", r)
	}
	if !ref.ValidDigest(p.Digest) {
		return pointer{}, fmt.Errorf("snapshot digest %q is not sha256:<64 lowercase hex>", p.Digest)
	}
	if p.Commit != "" && !commitPattern.MatchString(p.Commit) {
		return pointer{}, fmt.Errorf("commit %q is not a 40-character lowercase hex sha", p.Commit)
	}
	switch {
	case r == "main":
		log.Debugf("latest-%s.json named snapshot %s", claimsv1.Major, p.Digest)
	case p.Commit != "":
		log.Debugf("commit record %s named snapshot %s", p.Commit, p.Digest)
	}
	return p, nil
}

func getJSON(u string, v any) error {
	// the host is YARDSTICK_CLAIMS_URL or DefaultURL and the path a validated reference
	resp, err := httpClient.Get(u) //nolint:noctx,gosec // a short pointer read; the client has a timeout
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v); err != nil {
		return fmt.Errorf("GET %s: %w", u, err)
	}
	return nil
}

// openSnapshot opens a zip from the cache at final, downloading it first when it is not there, and
// says whether it did. No byte of a snapshot is read before the whole zip is on disk and its sha256
// is the digest it was published under; a repository archive, which has no published digest, is
// read once it is on disk whole.
func openSnapshot(url, final, digest string, details []string) (*os.File, int64, bool, error) {
	downloaded := false
	if _, err := os.Stat(final); err != nil {
		log.Infof("downloading claims %s", details[0])
		task := bus.StartDetailedTask(event.DownloadClaims, "", details)
		err := download(url, digest, filepath.Dir(final), final)
		task.Done(err)
		if err != nil {
			return nil, 0, false, err
		}
		downloaded = true
	} else {
		log.Infof("using cached claims %s", filepath.Base(final))
		cache.Touch(final)
	}
	f, err := os.Open(final)
	if err != nil {
		return nil, 0, false, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, false, err
	}
	return f, info.Size(), downloaded, nil
}

// staleDownload is how old a download left by a killed run must be before another run removes it.
const staleDownload = time.Hour

// download fetches the whole zip into a temp file beside final, hashing it as it is written, and
// renames it into place only when the digest matches, or with no digest once it is whole. A failed, cut off or mismatched download is
// deleted, so nothing of it stays in the cache.
func download(url, digest, dir, final string) error {
	defer log.Timed("downloading and verifying %s", url)()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	removeStale(dir)
	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	// a download that stops moving for downloadIdle is cancelled; one that keeps moving runs on
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	idle := time.AfterFunc(downloadIdle, cancel)
	defer idle.Stop()
	// the host is YARDSTICK_CLAIMS_URL, DefaultURL or githubAPI, and the path a checked digest or commit
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // see above
	if err != nil {
		return err
	}
	resp, err := do(downloadClient, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(idleReader{resp.Body, idle}, maxDownload+1))
	switch {
	case err != nil && ctx.Err() != nil:
		return fmt.Errorf("GET %s: no data for %s", url, downloadIdle)
	case err != nil:
		return fmt.Errorf("GET %s: %w", url, err)
	case n > maxDownload:
		return fmt.Errorf("GET %s: over %d bytes, more than a claims snapshot may be", url, maxDownload)
	}
	log.Tracef("downloaded %d bytes from %s", n, url)
	if err := tmp.Close(); err != nil {
		return err
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); digest != "" && got != digest {
		return fmt.Errorf("the download's digest is %s, not %s as published; it was deleted", got, digest)
	}
	log.Infof("downloaded claims %s, %d bytes", filepath.Base(final), n)
	return os.Rename(tmp.Name(), final)
}

// idleReader restarts the idle timer on every read that returns bytes.
type idleReader struct {
	r     io.Reader
	timer *time.Timer
}

func (i idleReader) Read(p []byte) (int, error) {
	n, err := i.r.Read(p)
	if n > 0 {
		i.timer.Reset(downloadIdle)
	}
	return n, err
}

// removeStale deletes downloads a killed run left behind.
func removeStale(dir string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && strings.HasPrefix(e.Name(), ".download-") && time.Since(info.ModTime()) > staleDownload {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
