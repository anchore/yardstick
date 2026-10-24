// Package ref parses subject references: an image pinned by digest (oci:...) or an SBOM document
// (sbom:<path>). It is a leaf package so the gate file loader, the label paths and the claims
// sources all read a subject the same way.
package ref

import (
	"fmt"
	"regexp"
	"strings"
)

// Kind is what a subject is.
type Kind string

const (
	Image Kind = "oci"
	SBOM  Kind = "sbom"
)

// Ref is a parsed subject reference.
type Ref struct {
	Kind Kind
	// an image: the registry and full repository path, normalized as docker does
	// (ubuntu -> docker.io/library/ubuntu), the tag if one was written, and the digest
	Registry   string
	Repository string
	Tag        string
	Digest     string // sha256:<hex>
	// an SBOM document: where the file is. Its address is the digest of its bytes, known only
	// once the file is read.
	Path string
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidDigest says whether d is a sha256 digest, sha256:<64 hex>.
func ValidDigest(d string) bool {
	return digestPattern.MatchString(d)
}

// Parse reads oci:<image>@sha256:<digest> or sbom:<path>.
func Parse(s string) (Ref, error) {
	kind, rest, ok := strings.Cut(s, ":")
	switch {
	case ok && Kind(kind) == Image:
		return parseImage(s, rest)
	case ok && Kind(kind) == SBOM:
		if rest == "" {
			return Ref{}, fmt.Errorf("subject %q names no SBOM file", s)
		}
		return Ref{Kind: SBOM, Path: rest}, nil
	}
	return Ref{}, fmt.Errorf("subject %q is not one of the two kinds: oci:<image>@sha256:<digest> or sbom:<path>", s)
}

func parseImage(s, image string) (Ref, error) {
	name, digest, ok := strings.Cut(image, "@")
	if !ok {
		return Ref{}, fmt.Errorf("subject %q: the image must be pinned by digest (oci:<image>@sha256:<digest>)", s)
	}
	if !ValidDigest(digest) {
		return Ref{}, fmt.Errorf("subject %q: %q is not a sha256 digest", s, digest)
	}
	r := Ref{Kind: Image, Digest: digest}
	// a tag is after the last colon of the last path component; a registry port is in the first
	if i := strings.LastIndex(name, "/"); strings.Contains(name[i+1:], ":") {
		name, r.Tag, _ = strings.Cut(name[i+1:], ":")
		name = image[:i+1] + name
	}
	r.Registry, r.Repository = splitRegistry(name)
	if r.Repository == "" {
		return Ref{}, fmt.Errorf("subject %q names no image", s)
	}
	return r, nil
}

const dockerHub = "docker.io"

// splitRegistry splits a name into registry and repository the way docker does: the first
// component is a registry only when it looks like a host, and docker hub's single-component
// names live under library/.
func splitRegistry(name string) (registry, repository string) {
	first, rest, ok := strings.Cut(name, "/")
	if ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		registry, repository = first, rest
	} else {
		registry, repository = dockerHub, name
	}
	if registry == "index.docker.io" {
		registry = dockerHub
	}
	if registry == dockerHub && repository != "" && !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}
	return registry, repository
}

// Name is an image's registry and repository, e.g. docker.io/library/ubuntu.
func (r Ref) Name() string {
	return r.Registry + "/" + r.Repository
}

// Image is an image's reference as a puller takes it: <registry>/<repository>[:tag]@<digest>.
func (r Ref) Image() string {
	s := r.Name()
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	return s + "@" + r.Digest
}

func (r Ref) String() string {
	if r.Kind == SBOM {
		return "sbom:" + r.Path
	}
	return "oci:" + r.Image()
}
