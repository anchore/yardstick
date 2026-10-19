package main

import (
	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/tasks/golint"
	"github.com/anchore/go-make/tasks/goreleaser"
	"github.com/anchore/go-make/tasks/gotest"
)

func main() {
	Makefile(
		golint.Tasks(),
		goreleaser.Tasks(),
		gotest.Tasks(),

		// yardstick-specific tasks not covered by go-make built-ins

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
