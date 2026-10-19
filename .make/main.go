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

func main() {
	Makefile(
		golint.Tasks(),
		goreleaser.Tasks(),
		// the label server's tests fetch the built UI
		gotest.Tasks().DependsOn("generate"),

		// yardstick-specific tasks not covered by go-make built-ins

		Task{
			Name:        "generate",
			Description: "build the label UI into labelserver/assets/dist: bun install, tygo, tsc, then esbuild",
			Run: func() {
				Run("bun install --frozen-lockfile", run.InDir(web))
				if file.Exists(web + "/tygo.yaml") {
					Run("tygo generate --config " + web + "/tygo.yaml")
				}
				Run(tsc(), run.Args("--noEmit", "-p", web))
				Run("go run ./" + web + "/build")
			},
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
