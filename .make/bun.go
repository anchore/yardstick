package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/anchore/go-make/config"
	"github.com/anchore/go-make/fetch"
	"github.com/anchore/go-make/file"
	"github.com/anchore/go-make/lang"
	"github.com/anchore/go-make/log"
	"github.com/anchore/go-make/run"
	"github.com/anchore/go-make/template"
)

// bun names its linux and darwin amd64 builds x64, which binny 0.13's github-release method has no
// alias for, so it never finds an asset there. It is pinned here the way tsc is.
// ponytail: no automatic updates; bump the version and the digests (from the release API's asset
// digests) together.
const bunVersion = "1.4.3"

var bunDigests = map[string]string{
	"darwin/arm64": "80afd4c069b46a6fa8f3ec520bebc750a7843e4a8d5b9583d29ad436c00a3403",
	"darwin/amd64": "62660e6438eb872278877acca77e1152d5d031324df368d4a81b428211489d2d",
	"linux/arm64":  "efa9813da5ed72423bf847f916e8d2c47c0d776add972354026a75e10da9aa21",
	"linux/amd64":  "3e730528d89775f03f87f05c06787c4df4099d0a37f3f252e7b829cb23816e18",
}

// bun is the path to the pinned bun at .tool/bun (where Taskfile.yaml runs Playwright from),
// downloading and verifying it on first use or when the one there is another version.
func bun() string {
	bin := filepath.Join(template.Render(config.ToolDir), "bun")
	if file.Exists(bin) {
		if v, err := run.Command(bin, run.Args("--version"), run.Quiet()); err == nil && strings.TrimSpace(v) == bunVersion {
			return bin
		}
	}

	platform := runtime.GOOS + "/" + runtime.GOARCH
	want, ok := bunDigests[platform]
	if !ok {
		lang.Throw(fmt.Errorf("no pinned bun %s for %s", bunVersion, platform))
	}
	arch := map[string]string{"amd64": "x64", "arm64": "aarch64"}[runtime.GOARCH]
	name := fmt.Sprintf("bun-%s-%s", runtime.GOOS, arch)
	url := fmt.Sprintf("https://github.com/oven-sh/bun/releases/download/bun-v%s/%s.zip", bunVersion, name)

	buf := fetchPinned(url, want)
	zr := lang.Return(zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len())))
	f := lang.Return(zr.Open(name + "/bun"))
	defer func() { _ = f.Close() }()

	// write beside a temp name and move it into place, so a failed extract never looks installed
	tmp := lang.Return(os.CreateTemp(file.EnsureDir(filepath.Dir(bin)), "bun-"))
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err := io.Copy(tmp, io.LimitReader(f, int64(fetch.MaxFileSize)))
	lang.Throw(err)
	lang.Throw(tmp.Close())
	lang.Throw(os.Chmod(tmp.Name(), 0o755))
	lang.Throw(os.Rename(tmp.Name(), bin))
	log.Info("installed bun %s at %s", bunVersion, bin)
	return bin
}
