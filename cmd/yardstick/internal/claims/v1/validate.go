package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// Problem is one rule a corpus file breaks.
type Problem struct {
	File  string // corpus-relative
	Label string // the label's key, when the rule is about one label
	Rule  string
}

func (p Problem) String() string {
	if p.Label != "" {
		return p.File + ": label " + p.Label + ": " + p.Rule
	}
	return p.File + ": " + p.Rule
}

// corpusCheck is one validation pass over a corpus tree.
type corpusCheck struct {
	fsys     fs.FS
	vocab    *Vocabulary
	catalog  *gatefile.Catalog
	catCfg   []byte
	problems []Problem
	// labelDirs are subject directories holding label files, to check each holds its SBOM
	labelDirs map[string]Location
	// platforms records, per image directory, whether its digest is an index, from its SBOM
	index map[string]bool
	// unplatformed are label files with no subject.platform, by directory
	unplatformed map[string][]string
}

func (c *corpusCheck) addf(file, label, format string, args ...any) {
	c.problems = append(c.problems, Problem{File: file, Label: label, Rule: fmt.Sprintf(format, args...)})
}

// ValidateCorpus checks a corpus directory the way corpus CI does: the layout, every label
// file's format, sort order and keys, the vocabulary, advisory ids, and each SBOM against
// catalog.yaml. It returns every problem, sorted, rather than stopping at the first.
func ValidateCorpus(dir string) ([]Problem, error) {
	log.Infof("validating corpus %s", dir)
	defer log.Timed("validating corpus %s", dir)()
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%s is not a corpus directory", dir)
	}
	// the corpus is pull request content: every read goes through a root that refuses a path or
	// symlink leading outside it
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	c := &corpusCheck{fsys: root.FS(), labelDirs: map[string]Location{}, index: map[string]bool{}, unplatformed: map[string][]string{}}
	if err := c.loadRoot(); err != nil {
		return nil, err
	}
	endWalk := log.Timed("walking corpus %s", dir)
	err = fs.WalkDir(c.fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// a corpus is pull request content: a link could lead a read or a write outside it
			c.addf(p, "", "a symlink; a corpus holds plain files and directories only")
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && p != "." {
				return fs.SkipDir
			}
			return nil
		}
		c.file(p)
		return nil
	})
	endWalk()
	if err != nil {
		return nil, err
	}
	c.subjectDirs()
	sort.SliceStable(c.problems, func(i, j int) bool { return c.problems[i].File < c.problems[j].File })
	log.Debugf("corpus %s has %d problems", dir, len(c.problems))
	return c.problems, nil
}

func (c *corpusCheck) loadRoot() error {
	var err error
	if c.vocab, err = LoadVocabulary(c.fsys); err != nil {
		c.addf(VocabularyFile, "", "%v", err)
	} else if c.vocab == nil {
		c.addf(VocabularyFile, "", "missing: a corpus lists its justifications and fact sources")
	} else {
		for _, p := range c.vocab.CheckRules() {
			c.addf(VocabularyFile, "", "%s", p)
		}
	}
	data, err := fs.ReadFile(c.fsys, CatalogFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		c.addf(CatalogFile, "", "missing: a corpus records the syft setup its SBOMs are built with")
	case err != nil:
		return err
	default:
		// paths stay as written, relative to the corpus root, and are read only inside it
		if c.catalog, err = gatefile.ParseCatalog(data, ""); err != nil {
			c.addf(CatalogFile, "", "%v", err)
		} else if err := c.catalog.CheckData(); err != nil {
			c.addf(CatalogFile, "", "%v", err)
		} else if c.catalog.Config != "" {
			if c.catCfg, err = ReadCatalogConfig(c.fsys, c.catalog.Config); err != nil {
				c.addf(CatalogFile, "", "%v", err)
			}
		}
	}
	return nil
}

// file checks one file of the tree by where it is.
func (c *corpusCheck) file(p string) {
	if !strings.Contains(p, "/") {
		if strings.HasSuffix(p, ".json") {
			c.addf(p, "", "label files live under pkg/oci/, sbom/ or global/, not at the corpus root")
		}
		return
	}
	loc, ok := Locate(p)
	if !ok {
		c.addf(p, "", "not a place in the corpus layout: labels live at pkg/oci/<registry>/<repository>/sha256-<hex>/<type>.json or image.json, sbom/sha256-<hex>/, and global/<type>.json")
		return
	}
	data, err := fs.ReadFile(c.fsys, p)
	if err != nil {
		c.addf(p, "", "%v", err)
		return
	}
	switch {
	case loc.IsLabelFile():
		c.labelFile(p, loc, data)
	case loc.Base == ImageSBOMFile:
		c.imageSBOM(p, loc, data)
	case loc.Base == DocumentSBOMFile:
		sum := sha256.Sum256(data)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != loc.Digest {
			c.addf(p, "", "the document's digest is %s, not %s, which its directory names", got, loc.Digest)
		}
	}
}

func (c *corpusCheck) imageSBOM(p string, loc Location, data []byte) {
	doc, err := ReadSyftDocument(data)
	if err != nil {
		c.addf(p, "", "%v", err)
		return
	}
	// a digest that differs from the manifest syft cataloged is an index: its files say which
	// platform was cataloged
	c.index[loc.Dir] = doc.Source.Metadata.ManifestDigest != "" && doc.Source.Metadata.ManifestDigest != loc.Digest
	if c.catalog == nil {
		return
	}
	drift, err := DescriptorDrift(doc, c.catalog, c.catCfg)
	if err != nil {
		c.addf(CatalogFile, "", "%v", err)
		return
	}
	for _, d := range drift {
		c.addf(p, "", "built with %s; rebuild it with the catalog's setup", d)
	}
}

func (c *corpusCheck) labelFile(p string, loc Location, data []byte) {
	f, err := Parse(p, data)
	if err != nil {
		c.addf(p, "", "%v", err)
		return
	}
	if err := ValidateSchema(data); err != nil {
		c.addf(p, "", "does not match the v1 schema: %v", err)
	}
	if loc.Kind != Global {
		c.labelDirs[loc.Dir] = loc
		if f.Subject == nil {
			c.addf(p, "", "subject is required outside global/")
		} else if err := checkSubject(loc, f.Subject); err != nil {
			c.addf(p, "", "%v", err)
		} else if loc.Kind == ImageSubject && f.Subject.Platform == "" {
			c.unplatformed[loc.Dir] = append(c.unplatformed[loc.Dir], p)
		}
	} else if f.Subject != nil {
		c.addf(p, "", "a global file has no subject")
	}
	c.labels(p, loc, f.Labels)
}

func (c *corpusCheck) labels(p string, loc Location, labels []Label) {
	for i, l := range labels {
		key := l.Key().String()
		if err := checkPlacement(Placed{File: p, Subject: subjectFor(loc), Label: l}); err != nil {
			c.addf(p, key, "%v", err)
		}
		if c.vocab != nil {
			if err := c.vocab.CheckVulnerability(l.Vulnerability); err != nil {
				c.addf(p, key, "%v", err)
			}
			if err := c.vocab.CheckLabel(l); err != nil {
				c.addf(p, key, "%v", err)
			}
		}
		if i == 0 {
			continue
		}
		prev := labels[i-1]
		switch {
		case prev.Key() == l.Key() && prev.Verdict != l.Verdict:
			c.addf(p, key, "two verdicts (%s and %s) for one match; a file holds the one agreed call", prev.Verdict, l.Verdict)
		case prev.Key() == l.Key():
			c.addf(p, key, "listed twice; a file holds one label per package and vulnerability")
		case l.Key().Less(prev.Key()):
			c.addf(p, key, "out of order: labels are sorted by package then vulnerability, and this sorts before %s", prev.Key())
		}
	}
}

// subjectFor is a subject consistent with a location, for the placement check alone.
func subjectFor(loc Location) *Subject {
	switch loc.Kind {
	case ImageSubject:
		return &Subject{Image: loc.Registry + "/" + loc.Repository + "@" + loc.Digest}
	case DocumentSubject:
		return &Subject{SBOM: loc.Digest}
	}
	return nil
}

// subjectDirs checks what needs the whole tree: a subject directory with labels holds its SBOM,
// and an index-digest image records its platform in every file.
func (c *corpusCheck) subjectDirs() {
	for dir, loc := range c.labelDirs {
		sbom := ImageSBOMFile
		if loc.Kind == DocumentSubject {
			sbom = DocumentSBOMFile
		}
		if _, err := fs.Stat(c.fsys, path.Join(dir, sbom)); err != nil {
			c.addf(dir, "", "holds labels and no %s, the SBOM they pair against", sbom)
		}
		if c.index[dir] {
			for _, f := range c.unplatformed[dir] {
				c.addf(f, "", "the digest is an index, so subject.platform must say which platform was cataloged")
			}
		}
	}
}

// ReadCatalogConfig reads the syft config a corpus's catalog.yaml names, through the corpus root.
// A corpus is data, so a config path that is absolute, climbs out with ../, or is a symlink leading
// outside the corpus is refused rather than read.
func ReadCatalogConfig(root fs.FS, config string) ([]byte, error) {
	cfg := filepath.ToSlash(config)
	if !fs.ValidPath(cfg) {
		return nil, fmt.Errorf("config %q must be a path inside the corpus, relative to its root", config)
	}
	data, err := fs.ReadFile(root, cfg)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return data, nil
}
