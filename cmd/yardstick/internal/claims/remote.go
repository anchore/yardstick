package claims

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/bus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// URLVar names the base URL published snapshots are read from: the public address of the bucket
// the publish workflow writes claims/latest-v<major>.json, claims/commits/<sha>.json and
// claims/snapshots/<hex>.zip into. Unset, snapshots are read from DefaultURL.
const URLVar = "YARDSTICK_CLAIMS_URL"

// DefaultURL is where anchore/match-claims publishes its snapshots.
const DefaultURL = "https://yardstick.anchore.io"

var (
	// defaultURL is DefaultURL, a variable so a test never reaches the real host
	defaultURL    = DefaultURL
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	httpClient    = &http.Client{Timeout: 2 * time.Minute}
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
	f, size, downloaded, err := openSnapshot(base+"/claims/snapshots/"+hexDigest+".zip", p.Digest, details(s.Locator, p))
	if err != nil {
		return nil, fmt.Errorf("claims source %s: snapshot %s: %w", s.Locator, p.Digest, err)
	}
	// read in place, never extracted; the file stays open for the life of the process
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return nil, fmt.Errorf("claims source %s: snapshot %s: %w", s.Locator, p.Digest, err)
	}
	return &Source{Locator: s.Locator, Kind: Remote, FS: zr, Digest: p.Digest, Commit: p.Commit, Downloaded: downloaded, read: map[string]string{}}, nil
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
		u := base + "/claims/latest-" + claimsv1.Major + ".json"
		if err := getJSON(u, &p); err != nil {
			return p, fmt.Errorf("no published snapshot of label format %s: %w", claimsv1.Major, err)
		}
	case commitPattern.MatchString(r):
		if err := getJSON(base+"/claims/commits/"+r+".json", &p); err != nil {
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

// openSnapshot opens a snapshot's zip from the cache, downloading it first when it is not there, and
// says whether it did. No byte of a snapshot is read before the whole zip is on disk and its sha256
// is the digest it was published under.
func openSnapshot(url, digest string, details []string) (*os.File, int64, bool, error) {
	dir := cache.Dir("claims")
	final := filepath.Join(dir, strings.TrimPrefix(digest, "sha256:")+".zip")
	downloaded := false
	if _, err := os.Stat(final); err != nil {
		log.Infof("downloading claims snapshot %s", digest)
		task := bus.StartDetailedTask(event.DownloadClaims, "", details)
		err := download(url, digest, dir, final)
		task.Done(err)
		if err != nil {
			return nil, 0, false, err
		}
		downloaded = true
	} else {
		log.Infof("using cached claims snapshot %s", digest)
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
// renames it into place only when the digest matches. A failed, cut off or mismatched download is
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
	resp, err := httpClient.Get(url) //nolint:noctx,gosec // the host is YARDSTICK_CLAIMS_URL or DefaultURL and the path a checked digest
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	log.Tracef("downloaded %d bytes from %s", n, url)
	if err := tmp.Close(); err != nil {
		return err
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != digest {
		return fmt.Errorf("the download's digest is %s, not %s as published; it was deleted", got, digest)
	}
	log.Infof("verified claims snapshot %s, %d bytes", digest, n)
	return os.Rename(tmp.Name(), final)
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
