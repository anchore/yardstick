// Package fixture locates yardstick's test fixtures: SBOMs and grype output made by the real,
// pinned tools from the images under images/, by generate.sh. Tests in every package read them
// from here, so there is one copy, and none of it is written by hand.
package fixture

import (
	"path/filepath"
	"runtime"
)

// Images are the fixture images: a debian package database, a rocky linux rpm database with
// epochs, a scoped npm package, and one java package in two jars.
var Images = []string{"deb", "rpm", "npm", "java"}

// GrypeVersions are the grype releases the fixtures were scanned with, older first.
var GrypeVersions = []string{"v0.119.0", "v0.120.1"}

// Path is a path under testdata/.
func Path(elem ...string) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to locate the fixture package")
	}
	return filepath.Join(append([]string{filepath.Dir(file), "testdata"}, elem...)...)
}

// SBOM is an image's SBOM in one format: syft, cdx or spdx.
func SBOM(image, format string) string {
	return Path("sbom", image+"."+format+".json")
}

// Grype is grype's JSON output for an image's syft SBOM.
func Grype(version, image string) string {
	return Path("grype", version, image+".json")
}
