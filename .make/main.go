package main

import (
	"os"
	"path/filepath"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/file"
	"github.com/anchore/go-make/run"
	"github.com/anchore/go-make/tasks/golint"
	"github.com/anchore/go-make/tasks/goreleaser"
	"github.com/anchore/go-make/tasks/gotest"
)

// web is the label UI's source: package.json, tsconfig.json and src/
const web = "cmd/yardstick/internal/labelserver/web"

// webDeps installs the UI's npm packages and generates its wire types: what both tsc and the
// bundler need before they run
func webDeps() {
	Run(bun(), run.Args("install", "--frozen-lockfile"), run.InDir(web))
	if file.Exists(web + "/tygo.yaml") {
		Run("tygo generate --config " + web + "/tygo.yaml")
		unionEnums(web + "/src/gen")
	}
}

// taskfile forwards to a task in Taskfile.yaml, which holds the shell orchestration. It runs in the
// terminal's process group with its stdin and stdout, so ctrl-c and a tty reach what it starts
// (go-make's gotask wrapper gives each command its own group and holds stdout back).
func taskfile(name string) func() {
	return func() { Run("task", run.Args(name), run.Interactive(), run.Stdout(os.Stdout)) }
}

func main() {
	Makefile(
		golint.Tasks(),
		goreleaser.Tasks(),
		// the label server's tests fetch the built UI; test/cli runs real grype, under make cli
		gotest.Tasks(gotest.ExcludeGlob("**/test/**")).DependsOn("generate"),
		// make unit also runs the label UI's unit tests (web/bunfig.toml roots them at src/)
		Task{
			Name:         "unit:web",
			Description:  "run the label UI's unit tests with bun test",
			Dependencies: Deps("generate"),
			RunsOn:       Deps("unit"),
			Run:          func() { Run(bun(), run.Args("test"), run.InDir(web)) },
		},

		// yardstick-specific tasks not covered by go-make built-ins

		Task{
			Name:        "generate",
			Description: "build the label UI into labelserver/assets/dist: bun install, tygo, tsc (the UI and its e2e tests), then esbuild",
			Run: func() {
				webDeps()
				Run(tsc(), run.Args("--noEmit", "-p", web))
				Run(tsc(), run.Args("--noEmit", "-p", web+"/e2e"))
				Run("go run ./" + web + "/build")
			},
		},

		Task{
			Name:        "dev",
			Description: "serve the label UI with live reload beside tsc --watch (YARDSTICK_DEV_DIR: the workspace, default the repo root; ARGS: more claims serve args)",
			Run:         dev,
		},

		Task{
			Name:        "dev:e2e",
			Description: "make dev over a fresh copy of the e2e tests' workspace, in .tmp/dev-e2e (ARGS: more claims serve args)",
			Run:         devE2E,
		},

		Task{
			Name:         "e2e",
			Description:  "run the label UI's Playwright tests on the pinned bun (HEADED=1 shows the browser; traces in web/test-results/)",
			Dependencies: Deps("generate"),
			Run:          taskfile("e2e"),
		},

		Task{
			Name:         "e2e:container",
			Description:  "run the label UI's Playwright tests headless in Playwright's linux docker image, for sandboxes where a host browser can't start",
			Dependencies: Deps("generate"),
			Run:          taskfile("e2e:container"),
		},

		Task{
			Name:         "e2e-ui",
			Description:  "open the label UI's Playwright tests in Playwright's UI mode",
			Dependencies: Deps("generate"),
			Run:          taskfile("e2e-ui"),
		},

		Task{
			Name:        "cli",
			Description: "run the CLI workflow tests in test/cli: real grype releases and labels on DBs built from a few vunnel records (cache in .tmp/cli/cache)",
			Run: func() {
				Run("go test -count=1 -timeout 15m -v ./test/cli",
					run.Env("YARDSTICK_CACHE_DIR", filepath.Join(file.Cwd(), ".tmp", "cli", "cache")), run.Stdout(os.Stdout))
			},
		},

		Task{
			Name:        "fixtures",
			Description: "regenerate test fixtures with the real, pinned syft, grype, vexctl and oras (needs docker)",
			Run:         taskfile("fixtures"),
		},
	)
}
