package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/lang"
	"github.com/anchore/go-make/run"
	"github.com/anchore/go-make/template"
)

// e2e runs the label UI's Playwright tests in Playwright's image, so the host needs docker and no
// Node. The tests use the host's node_modules, and the config starts the seed, a static linux
// build of cmd/yardstick/internal/testkit/seed, which serves a fresh workspace in the container.
// The repo is mounted at its own path because the seed finds its fixtures by source path.
func e2e(docker []string, playwright ...string) func() {
	return func() {
		root := template.Render("{{RootDir}}")
		Run(tsc(), run.Args("--noEmit", "-p", web+"/e2e"))
		Run("go build -o .tmp/e2e/seed ./cmd/yardstick/internal/testkit/seed",
			run.Env("GOOS", "linux"), run.Env("GOARCH", runtime.GOARCH), run.Env("CGO_ENABLED", "0"))
		// ctrl-c reaches playwright: go-make sends docker SIGINT, docker passes it on, and --init
		// forwards it
		Run("docker run --rm --init --ipc=host", run.Args(
			"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "-e", "HOME=/tmp", "-e", "NPM_CONFIG_UPDATE_NOTIFIER=false",
			"-v", root+":"+root, "-w", root+"/"+web), run.Args(docker...),
			run.Args("mcr.microsoft.com/playwright:v"+playwrightVersion()+"-noble", "npx", "playwright", "test"), run.Args(playwright...),
			run.Stdout(os.Stdout))
	}
}

var exactVersion = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// playwrightVersion is @playwright/test's exact version in package.json, which names the image.
func playwrightVersion() string {
	var pkg struct {
		DevDependencies map[string]string `json:"devDependencies"`
	}
	lang.Throw(json.Unmarshal(lang.Return(os.ReadFile(web+"/package.json")), &pkg))
	v := pkg.DevDependencies["@playwright/test"]
	if !exactVersion.MatchString(v) {
		lang.Throw(fmt.Errorf("@playwright/test in %s/package.json must be an exact version, since it names the docker image: got %q", web, v))
	}
	return v
}
