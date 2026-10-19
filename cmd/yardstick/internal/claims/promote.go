package claims

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// Promoted is what a promote wrote: the labels, and the SBOMs copied into the target.
type Promoted struct {
	Labels int
	SBOMs  []string
}

// Promote writes every label of a local claims directory into a corpus checkout through the label
// writer, replacing a target label with the same key, and copies into the target each SBOM a
// promoted label's seenIn.sbom names that the target does not hold, from the source directory or
// the SBOM cache. Nothing is written when any label is refused or any such SBOM is found nowhere.
// It neither commits nor pushes.
func Promote(src, dst string) (*Promoted, error) {
	defer log.Timed("promoting %s into %s", src, dst)()
	log.Infof("promoting claims from %s into %s", src, dst)
	for _, d := range []string{src, dst} {
		if info, err := os.Stat(d); err != nil || !info.IsDir() {
			return nil, fmt.Errorf("%s is not a local claims directory", d)
		}
	}
	root, err := os.OpenRoot(src)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dstRoot, err := os.OpenRoot(dst)
	if err != nil {
		return nil, err
	}
	defer dstRoot.Close()
	vocab, err := labels.FindVocabulary(dstRoot.FS(), root.FS())
	if err != nil {
		return nil, err
	}
	w := labels.Writer{Dir: dst, Vocab: vocab}

	var batch []labels.Placed
	copies := map[string][]byte{} // target path to the SBOM's bytes
	endWalk := log.Timed("walking %s for label files", src)
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		placed, err := promoted(root.FS(), dstRoot.FS(), w, p, copies)
		batch = append(batch, placed...)
		return err
	})
	endWalk()
	if err != nil {
		return nil, err
	}
	if err := w.Write(batch); err != nil {
		return nil, err
	}
	out := &Promoted{Labels: len(batch)}
	for p, data := range copies {
		if err := labels.WriteFile(dst, p, data); err != nil {
			return nil, err
		}
		out.SBOMs = append(out.SBOMs, p)
	}
	log.Infof("promoted %d labels and %d SBOMs into %s", out.Labels, len(out.SBOMs), dst)
	return out, nil
}

// promoted are one source file's labels, checked, with the SBOM each was written against found
// when the target lacks it.
func promoted(src, dst fs.FS, w labels.Writer, p string, copies map[string][]byte) ([]labels.Placed, error) {
	loc, ok := labels.Locate(p)
	if !ok || !loc.IsLabelFile() {
		return nil, nil
	}
	data, err := fs.ReadFile(src, p)
	if err != nil {
		return nil, err
	}
	f, err := labels.Parse(p, data)
	if err != nil {
		return nil, err
	}
	log.Debugf("promote read %s: %d labels", p, len(f.Labels))
	var out []labels.Placed
	for _, l := range f.Labels {
		placed := labels.Placed{File: p, Subject: f.Subject, Label: l}
		if err := w.Check(placed); err != nil {
			return nil, err
		}
		out = append(out, placed)
		if l.SeenIn == nil || l.SeenIn.SBOM == "" || loc.Kind == labels.Global {
			continue
		}
		if err := needSBOM(src, dst, loc, l, copies); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// needSBOM finds the SBOM a label was written against, when the target's subject directory holds
// none: in the source's subject directory, else in the SBOM cache.
func needSBOM(src, dst fs.FS, loc labels.Location, l labels.Label, copies map[string][]byte) error {
	name := labels.ImageSBOMFile
	if loc.Kind == labels.DocumentSubject {
		name = labels.DocumentSBOMFile
	}
	target := path.Join(loc.Dir, name)
	if _, ok := copies[target]; ok {
		return nil
	}
	if _, err := fs.Stat(dst, target); err == nil {
		// the target holds an SBOM for the subject already; promote never replaces one
		return nil
	}
	want := l.SeenIn.SBOM
	if data, err := fs.ReadFile(src, target); err == nil && sbomDigest(data) == want {
		copies[target] = data
		log.Debugf("SBOM %s for %s found in the source", want, target)
		return nil
	}
	for _, p := range cached(loc, want) {
		if data, err := os.ReadFile(p); err == nil && sbomDigest(data) == want {
			copies[target] = data
			log.Debugf("SBOM %s for %s found in the cache at %s", want, target, p)
			return nil
		}
	}
	return fmt.Errorf("%s: label %s was written against SBOM %s, which neither the source nor the SBOM cache holds", path.Join(loc.Dir, loc.Base), l.Key(), want)
}

// cached are the cache files that may hold an SBOM: read from a claims source by its digest, or
// built for the image.
func cached(loc labels.Location, want string) []string {
	out := []string{cache.Dir("sboms-read", strings.ReplaceAll(want, ":", "-")+".syft.json")}
	if loc.Kind == labels.ImageSubject {
		built, _ := filepath.Glob(filepath.Join(cache.Dir("sboms", loc.Digest), "*.syft.json"))
		out = append(out, built...)
	}
	return out
}

func sbomDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
