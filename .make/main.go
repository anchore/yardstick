package main

import (
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
	Run("bun install --frozen-lockfile", run.InDir(web))
	if file.Exists(web + "/tygo.yaml") {
		Run("tygo generate --config " + web + "/tygo.yaml")
	}
}

func main() {
	Makefile(
		golint.Tasks(),
		goreleaser.Tasks(),
		// the label server's tests fetch the built UI
		gotest.Tasks().DependsOn("generate"),
		// make unit also runs the label UI's unit tests (web/bunfig.toml roots them at src/)
		Task{
			Name:         "unit:web",
			Description:  "run the label UI's unit tests with bun test",
			Dependencies: Deps("generate"),
			RunsOn:       Deps("unit"),
			Run:          func() { Run("bun test", run.InDir(web)) },
		},

		// yardstick-specific tasks not covered by go-make built-ins

		Task{
			Name:        "generate",
			Description: "build the label UI into labelserver/assets/dist: bun install, tygo, tsc, then esbuild",
			Run: func() {
				webDeps()
				Run(tsc(), run.Args("--noEmit", "-p", web))
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
			Description:  "run the label UI's Playwright tests in Playwright's docker image (traces in web/test-results/)",
			Dependencies: Deps("generate"),
			Run:          e2e(nil),
		},

		Task{
			Name:         "e2e-ui",
			Description:  "the label UI's Playwright tests in UI mode, at http://127.0.0.1:8080",
			Dependencies: Deps("generate"),
			Run:          e2e([]string{"-p", "127.0.0.1:8080:8080"}, "--ui", "--ui-host=0.0.0.0", "--ui-port=8080"),
		},

		Task{
			Name:        "fixtures",
			Description: "regenerate test fixtures with the real, pinned syft, grype, vexctl and oras (needs docker)",
			Run: func() {
				Run("cmd/yardstick/internal/fixture/generate.sh")
				Run("cmd/yardstick/internal/fixture/generate-vex.sh")
				Run("cmd/yardstick/internal/fixture/generate-vml.sh")
				Run("cmd/yardstick/internal/fixture/generate-cpes.sh")
			},
		},
	)
}
