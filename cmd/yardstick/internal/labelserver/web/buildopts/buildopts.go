// Package buildopts is how the label UI is bundled, shared by the generator (web/build) and a dev
// build's watch mode so both produce the same assets/dist/. Only those import esbuild; the
// yardstick binary never does.
package buildopts

import (
	"path/filepath"

	"github.com/evanw/esbuild/pkg/api"
)

// Options bundles web/src (webDir is the web/ directory) into labelserver/assets/dist/.
func Options(webDir string) api.BuildOptions {
	return api.BuildOptions{
		AbsWorkingDir: webDir,
		EntryPoints: []string{
			"src/map/app.ts", "src/map/gates.ts",
			"src/map/app.css", "src/map/gates.css", "src/shared/tile.css",
			"src/app/main.ts", "src/app/app.css",
		},
		Outbase:    "src",
		Outdir:     filepath.Join(webDir, "..", "assets", "dist"),
		ChunkNames: "chunks/[name]-[hash]",
		Bundle:     true,
		Format:     api.FormatESModule,
		Splitting:  true,
		Target:     api.ES2022,
		Sourcemap:  api.SourceMapLinked,
		// the generator gathers each output's legal comments into one license file
		LegalComments: api.LegalCommentsExternal,
		Metafile:      true,
		Write:         true,
		LogLevel:      api.LogLevelWarning,
	}
}
