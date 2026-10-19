package labels

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
)

// NoLongerPairing lists the labels of each image subject whose purl no package of the subject's
// sbom.syft.json has: after an SBOM rebuild, the labels that stopped pairing. They are listed for
// a person to look at and never removed. Corpus validation does not fail on them.
func NoLongerPairing(dir string) ([]Problem, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fsys := root.FS()
	var out []Problem
	err = fs.WalkDir(fsys, imageRoot, func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && p == imageRoot {
			return fs.SkipDir
		}
		if err != nil || d.IsDir() || d.Name() != ImageSBOMFile {
			return err
		}
		found, err := unpairedIn(fsys, path.Dir(p))
		out = append(out, found...)
		return err
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, err
}

func unpairedIn(fsys fs.FS, dir string) ([]Problem, error) {
	data, err := fs.ReadFile(fsys, path.Join(dir, ImageSBOMFile))
	if err != nil {
		return nil, err
	}
	doc, err := ReadSyftDocument(data)
	if err != nil {
		// a broken SBOM is a validation problem, reported there
		return nil, nil //nolint:nilerr
	}
	pkgs := make([]purl.Fields, len(doc.Artifacts))
	for i, a := range doc.Artifacts {
		pkgs[i] = purl.Package(a.PURL, a.Version)
	}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var out []Problem
	for _, e := range entries {
		t, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidType(t) {
			continue
		}
		p := path.Join(dir, e.Name())
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, err
		}
		f, err := Parse(p, data)
		if err != nil {
			continue
		}
		for _, l := range f.Labels {
			if !pairsAny(l.Package, pkgs) {
				out = append(out, Problem{File: p, Label: l.Key().String(), Rule: fmt.Sprintf("no package in %s has this purl; the label no longer pairs", ImageSBOMFile)})
			}
		}
	}
	return out, nil
}

func pairsAny(p string, pkgs []purl.Fields) bool {
	f, err := purl.Label(p)
	if err != nil {
		return false
	}
	for _, pkg := range pkgs {
		if f.Matches(pkg) {
			return true
		}
	}
	return false
}
