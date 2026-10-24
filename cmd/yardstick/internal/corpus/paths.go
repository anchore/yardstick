// Package corpus is a claims corpus on disk: the layout (where a subject's files sit), the writer
// every command writes labels through, corpus validation, and the SBOM checks that pair labels
// with packages and the catalog's syft setup. The label format is claims/v1; none of this belongs
// to one format version.
package corpus

import (
	"io/fs"
	"path"
	"regexp"
	"strings"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// The corpus layout. Paths are corpus-relative and slash-separated, so the same path names an
// entry in a directory and in a published zip.
//
//	pkg/oci/<registry>/<repository>/sha256-<hex>/{sbom.syft.json, matches/<type>.json, matches/image.json}
//	sbom/sha256-<hex>/{sbom.json, matches/<type>.json, matches/image.json}
//	global/matches/<type>.json
//	catalog.yaml, vocabulary.yaml
//
// Labels sit in a directory named for their kind, under a subject's directory and under global/.
// Vulnerability-match labels are the one kind there is, in matches/. A sibling directory of another
// name is a kind this yardstick does not read: validation lists it and fails nothing, so an older
// yardstick still reads a newer corpus.
//
// A digest names its directory with a dash, sha256-<hex>: a ':' in a committed path makes the
// repository's Go module unfetchable through the proxy. References keep sha256:<hex>.
const (
	ImageSBOMFile    = "sbom.syft.json"
	DocumentSBOMFile = "sbom.json"
	NoPackageFile    = "image.json"
	CatalogFile      = "catalog.yaml"
	// MatchesDir holds vulnerability-match labels, beside the subject's SBOM and under global/
	MatchesDir = "matches"

	imageRoot    = "pkg/oci"
	documentRoot = "sbom"
	globalRoot   = "global"
)

var typePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)

// ValidType says whether a package type can name a type file: syft's types are words joined by
// '-', not always lowercase (R-package), and a type never becomes more than one path segment.
func ValidType(t string) bool {
	return typePattern.MatchString(t) && t+".json" != NoPackageFile && t+".json" != DocumentSBOMFile
}

// ImageDir is an image subject's directory: the registry and full repository keep it legible,
// the digest keeps it content-addressed. Nothing in it depends on the SBOM, so a syft bump moves
// no label.
func ImageDir(r ref.Ref) string {
	return path.Join(imageRoot, r.Registry, r.Repository, DigestDir(r.Digest))
}

// DigestDir is a digest as a directory name: sha256-<hex> for sha256:<hex>.
func DigestDir(digest string) string {
	return strings.Replace(digest, "sha256:", "sha256-", 1)
}

// dirDigest reads a directory name back as the digest it spells, empty when it spells none.
func dirDigest(name string) string {
	hex, ok := strings.CutPrefix(name, "sha256-")
	if d := "sha256:" + hex; ok && ref.ValidDigest(d) {
		return d
	}
	return ""
}

// DocumentDir is an SBOM document subject's directory, keyed by the digest of its bytes.
func DocumentDir(digest string) string {
	return path.Join(documentRoot, DigestDir(digest))
}

// TypeFile is the file holding a subject's labels on packages of one type.
func TypeFile(dir, pkgType string) string {
	return path.Join(dir, MatchesDir, pkgType+".json")
}

// NoPackagePath is the file holding a subject's labels that name no package.
func NoPackagePath(dir string) string {
	return path.Join(dir, MatchesDir, NoPackageFile)
}

// GlobalFile is the file holding labels on one package type that hold on every subject.
func GlobalFile(pkgType string) string {
	return path.Join(globalRoot, MatchesDir, pkgType+".json")
}

// UnknownKind says whether a corpus directory is a label kind this yardstick does not read: a
// directory directly under a subject's directory or global/ that is not matches/.
func UnknownKind(dir string) bool {
	parent, name := path.Split(dir)
	if name == MatchesDir || parent == "" {
		return false
	}
	_, ok := Locate(NoPackagePath(path.Clean(parent)))
	return ok || path.Clean(parent) == globalRoot
}

// Kind is what a corpus file is about.
type Kind string

const (
	ImageSubject    Kind = "image"
	DocumentSubject Kind = "document"
	Global          Kind = "global"
)

// Location is a corpus path, read back.
type Location struct {
	Kind Kind
	Dir  string // the subject's directory, not its matches/; global/ for global files
	Base string // the file's name
	// Type is the package type of a type file, empty for image.json and the SBOMs.
	Type string
	// Registry, Repository and Digest are an image subject's; Digest alone a document's.
	Registry, Repository, Digest string
}

// IsLabelFile says whether the location holds labels rather than an SBOM.
func (l Location) IsLabelFile() bool {
	return l.Base == NoPackageFile || l.Type != ""
}

// Locate reads a corpus-relative path back into what it addresses, or reports that nothing
// belongs there.
func Locate(p string) (Location, bool) {
	dir, base := path.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	// label files sit in matches/, SBOMs beside it in the subject's directory
	dir, inMatches := strings.CutSuffix(dir, "/"+MatchesDir)
	loc := Location{Dir: dir, Base: base}
	if t, ok := strings.CutSuffix(base, ".json"); ok && ValidType(t) {
		loc.Type = t
	}
	placed := func(sbom string) bool {
		if inMatches {
			return loc.IsLabelFile()
		}
		return base == sbom
	}
	switch {
	case dir == globalRoot:
		loc.Kind = Global
		return loc, inMatches && loc.Type != ""
	case strings.HasPrefix(dir, documentRoot+"/"):
		loc.Kind, loc.Digest = DocumentSubject, dirDigest(strings.TrimPrefix(dir, documentRoot+"/"))
		return loc, loc.Digest != "" && placed(DocumentSBOMFile)
	case strings.HasPrefix(dir, imageRoot+"/"):
		parts := strings.Split(strings.TrimPrefix(dir, imageRoot+"/"), "/")
		if len(parts) < 3 {
			return loc, false
		}
		loc.Kind, loc.Registry = ImageSubject, parts[0]
		loc.Repository = strings.Join(parts[1:len(parts)-1], "/")
		loc.Digest = dirDigest(parts[len(parts)-1])
		return loc, loc.Digest != "" && placed(ImageSBOMFile)
	}
	return loc, false
}

// WalkLabelFiles parses every label file in a corpus, in path order, and hands each to fn with
// where it sits. Anything else in the tree is skipped.
func WalkLabelFiles(fsys fs.FS, fn func(p string, loc Location, f *claimsv1.File) error) error {
	return fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		loc, ok := Locate(p)
		if !ok || !loc.IsLabelFile() {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		f, err := claimsv1.Parse(p, data)
		if err != nil {
			return err
		}
		return fn(p, loc, f)
	})
}
