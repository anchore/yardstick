package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/anchore/go-make/template"
)

// tsc 7 is a native binary on the microsoft/TypeScript releases, but it reads lib/*.d.ts from
// beside itself, and binny keeps only the binary out of an archive. So it is pinned here instead.
// ponytail: no automatic updates; bump the version and the digests (from the release API's asset
// digests) together.
const tscVersion = "7.0.2"

var tscDigests = map[string]string{
	"darwin/arm64": "902e2fe1cf0799198ef902c6b8c310a450fef629a6baba41d45641ef75c04ebd",
	"darwin/amd64": "eba158cb54050f723d5ff781438f33de5640054440bb4f2bd170cfe9bc2eb551",
	"linux/arm64":  "c83d931ac9dd7549cde6e71246aa9d6a9812843023df3e277fe3b5dcf41dd0ea",
	"linux/amd64":  "7ecad6f67377e831856367ab062ef394f21506a611405bf8ac0ff039348637d3",
}

// tsc is the path to the pinned tsc, downloading and verifying it into .tool/ on first use.
func tsc() string {
	dir := filepath.Join(template.Render(config.ToolDir), "typescript-"+tscVersion)
	bin := filepath.Join(dir, "tsc")
	if file.Exists(bin) {
		return bin
	}

	platform := runtime.GOOS + "/" + runtime.GOARCH
	want, ok := tscDigests[platform]
	if !ok {
		lang.Throw(fmt.Errorf("no pinned tsc %s for %s", tscVersion, platform))
	}
	arch := map[string]string{"amd64": "x64"}[runtime.GOARCH]
	if arch == "" {
		arch = runtime.GOARCH
	}
	url := fmt.Sprintf("https://github.com/microsoft/TypeScript/releases/download/v%s/typescript-%s-%s.tgz", tscVersion, runtime.GOOS, arch)

	buf := bytes.Buffer{}
	lang.Return(fetch.Fetch(url, fetch.Writer(&buf)))
	sum := sha256.Sum256(buf.Bytes())
	if got := hex.EncodeToString(sum[:]); got != want {
		lang.Throw(fmt.Errorf("tsc %s: sha256 %s, want %s", url, got, want))
	}

	// extract package/lib/ beside a temp name and move it into place, so a failed extract never
	// looks installed
	tmp := lang.Return(os.MkdirTemp(file.EnsureDir(filepath.Dir(dir)), "typescript-"))
	defer func() { _ = os.RemoveAll(tmp) }()
	zr := lang.Return(gzip.NewReader(&buf))
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		lang.Throw(err)
		name, ok := strings.CutPrefix(h.Name, "package/lib/")
		if !ok || h.Typeflag != tar.TypeReg || name == "" || strings.Contains(name, "/") {
			continue
		}
		out := lang.Return(os.OpenFile(filepath.Join(tmp, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode)&0o755))
		_, err = io.Copy(out, io.LimitReader(tr, int64(fetch.MaxFileSize)))
		lang.Throw(err)
		lang.Throw(out.Close())
	}
	lang.Throw(os.Rename(tmp, dir))
	log.Info("installed tsc %s at %s", tscVersion, bin)
	return bin
}
