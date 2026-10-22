package v1

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// Placed is a label and the corpus file it belongs in.
type Placed struct {
	File    string   // corpus-relative: TypeFile, NoPackageFile under a subject dir, or GlobalFile
	Subject *Subject // the file's subject; nil for global files
	Label   Label
}

// Writer writes labels into one claims source, the writable one, through the only path every
// command shares: claims add, claims import and the label UI.
type Writer struct {
	Dir   string
	Vocab *Vocabulary
}

// rename renames inside a corpus; tests make it fail to show a failed write leaves the old file.
var rename = func(root *os.Root, oldname, newname string) error { return root.Rename(oldname, newname) }

// Written is one key a write placed a label under, and the label it replaced there; Prior is nil
// when the key was new. Revert takes it back.
type Written struct {
	File  string
	Key   Key
	Prior *Label
}

// Write checks every label, then rewrites each file the batch touches once: a label replaces
// the one with its key (see carry), and the file stays sorted. Nothing is written when any label
// is refused. It returns each key written, once, with the label it replaced; on an error part
// way, the keys in the files written before it.
func (w Writer) Write(batch []Placed) ([]Written, error) {
	byFile := map[string][]Placed{}
	for _, p := range batch {
		if err := w.Check(p); err != nil {
			return nil, err
		}
		byFile[p.File] = append(byFile[p.File], p)
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, nil
	}
	log.Infof("writing %d labels to %d files in %s", len(batch), len(files), w.Dir)
	defer log.Timed("writing labels to %s", w.Dir)()
	// a corpus can be someone else's pull request: every read and write stays inside it, so a
	// symlinked directory in it never leads a write elsewhere
	root, err := openCorpus(w.Dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var out []Written
	for _, f := range files {
		written, err := w.writeFile(root, f, byFile[f])
		if err != nil {
			return out, err
		}
		out = append(out, written...)
	}
	return out, nil
}

// carry is the label replacing prior: it keeps prior's firstIssued and notes (the new ones after
// them, less any the same author already said, so a re-import adds nothing), and prior's evidence
// when the new label brings none and makes the same call, since evidence for another verdict
// cites rules that refuse it.
func carry(prior, l Label) Label {
	if prior.FirstIssued != "" {
		l.FirstIssued = prior.FirstIssued
	}
	notes := slices.Clone(prior.Notes)
	for _, n := range l.Notes {
		if !slices.ContainsFunc(notes, func(o Note) bool { return o.Text == n.Text && o.Author == n.Author }) {
			notes = append(notes, n)
		}
	}
	l.Notes = notes
	if len(l.Evidence) == 0 && l.Verdict == prior.Verdict {
		l.Evidence = prior.Evidence
	}
	return l
}

func openCorpus(dir string) (*os.Root, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return os.OpenRoot(dir)
}

// Check refuses a label the writer would not write, naming the field.
func (w Writer) Check(p Placed) (err error) {
	where := fmt.Sprintf("%s: label %s", p.File, p.Label.Key())
	defer func() {
		if err != nil {
			log.Debugf("writer refuses %v", err)
		}
	}()
	if err := checkPlacement(p); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if err := CheckRequired(p.Label, w.Vocab); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if w.Vocab == nil {
		return fmt.Errorf("%s: no %s to check the justification and fact sources against", where, VocabularyFile)
	}
	if err := w.Vocab.CheckVulnerability(p.Label.Vulnerability); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if err := w.Vocab.CheckLabel(p.Label); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	return nil
}

// checkPlacement says whether a label belongs in the file: package labels in type files and
// global files, package-less ones in image.json, and a subject matching the directory.
func checkPlacement(p Placed) error {
	loc, ok := Locate(p.File)
	if !ok || !loc.IsLabelFile() {
		return fmt.Errorf("%s is not a label file in the corpus layout", p.File)
	}
	switch {
	case loc.Type != "" && p.Label.Package == "":
		return fmt.Errorf("package is required in %s", loc.Base)
	case loc.Base == NoPackageFile && p.Label.Package != "":
		return fmt.Errorf("package must be absent in %s, which holds labels that name no package", NoPackageFile)
	case loc.Kind == Global && p.Subject != nil:
		return errors.New("a global label has no subject")
	case loc.Kind != Global && p.Subject == nil:
		return errors.New("a subject is required outside global/")
	}
	return checkSubject(loc, p.Subject)
}

// checkSubject says whether a file's subject is the one its directory addresses.
func checkSubject(loc Location, s *Subject) error {
	switch loc.Kind {
	case ImageSubject:
		want := loc.Registry + "/" + loc.Repository
		name, digest, _ := strings.Cut(s.Image, "@")
		if i := strings.LastIndex(name, "/"); strings.Contains(name[i+1:], ":") {
			name = name[:i+1] + strings.SplitN(name[i+1:], ":", 2)[0]
		}
		if name != want || digest != loc.Digest {
			return fmt.Errorf("subject.image %s is not %s@%s, which the path names", s.Image, want, loc.Digest)
		}
	case DocumentSubject:
		if s.SBOM != loc.Digest {
			return fmt.Errorf("subject.sbom %s is not %s, which the path names", s.SBOM, loc.Digest)
		}
	}
	return nil
}

// CheckRequired refuses a label missing a required field, with a verdict outside tp, fp and
// unclear, or an fp or unclear verdict without a justification.
func CheckRequired(l Label, v *Vocabulary) error {
	switch {
	case l.Vulnerability == "":
		return errors.New("vulnerability is required")
	case l.Verdict != TP && l.Verdict != FP && l.Verdict != Unclear:
		return fmt.Errorf("verdict must be tp, fp or unclear, got %q", l.Verdict)
	case l.Author == "":
		return errors.New("author is required")
	case l.Verdict != TP && l.Justification == "":
		msg := fmt.Sprintf("%s needs a justification", l.Verdict)
		if v != nil {
			msg += " (one of: " + strings.Join(v.Allowed(l.Verdict), ", ") + ")"
		}
		return errors.New(msg)
	}
	for name, t := range map[string]string{"firstIssued": l.FirstIssued, "lastUpdated": l.LastUpdated} {
		if _, err := time.Parse(time.RFC3339, t); err != nil {
			return fmt.Errorf("%s must be an RFC 3339 time, got %q", name, t)
		}
	}
	if err := checkNotesAndTools(l); err != nil {
		return err
	}
	for i, e := range l.Evidence {
		if len(e.Facts) == 0 {
			return fmt.Errorf("evidence[%d] needs at least one fact", i)
		}
		for j, f := range e.Facts {
			if f.Source == "" || f.Field == "" || f.About == nil {
				return fmt.Errorf("evidence[%d].facts[%d] needs source, about and field", i, j)
			}
			if _, err := time.Parse(time.RFC3339, f.ObservedAt); err != nil {
				return fmt.Errorf("evidence[%d].facts[%d].observedAt must be an RFC 3339 time, got %q", i, j, f.ObservedAt)
			}
		}
	}
	return nil
}

// checkNotesAndTools refuses a note without text, author or an RFC 3339 time, and a seenIn tool
// without a name or version.
func checkNotesAndTools(l Label) error {
	for i, n := range l.Notes {
		if n.Text == "" || n.Author == "" {
			return fmt.Errorf("notes[%d] needs text and author", i)
		}
		if _, err := time.Parse(time.RFC3339, n.At); err != nil {
			return fmt.Errorf("notes[%d].at must be an RFC 3339 time, got %q", i, n.At)
		}
	}
	if l.SeenIn != nil {
		for i, t := range l.SeenIn.Tools {
			if t.Name == "" || t.Version == "" {
				return fmt.Errorf("seenIn.tools[%d] needs name and version", i)
			}
		}
	}
	return nil
}

func (w Writer) writeFile(root *os.Root, rel string, placed []Placed) ([]Written, error) {
	target := filepath.FromSlash(rel)
	f := &File{Schema: Version}
	if data, err := root.ReadFile(target); err == nil {
		if f, err = Parse(rel, data); err != nil {
			return nil, err
		}
		// what this writes is Version, so an older file is raised to it; a newer one keeps its own,
		// since its unknown fields are carried through untouched
		if !newer(f.Schema) {
			f.Schema = Version
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	byKey := map[Key]int{}
	for i, l := range f.Labels {
		byKey[l.Key()] = i
	}
	// a key the batch places twice reports, and carries forward, what the file held
	var out []Written
	priors := map[Key]*Label{}
	for _, p := range placed {
		if err := mergeSubject(rel, f, p.Subject); err != nil {
			return nil, err
		}
		l, k := p.Label, p.Label.Key()
		i, ok := byKey[k]
		if _, seen := priors[k]; !seen {
			var prior *Label
			if ok {
				held := f.Labels[i]
				prior = &held
			}
			priors[k] = prior
			out = append(out, Written{File: rel, Key: k, Prior: prior})
		}
		if prior := priors[k]; prior != nil {
			l = carry(*prior, l)
		}
		if ok {
			f.Labels[i] = l
			continue
		}
		byKey[k] = len(f.Labels)
		f.Labels = append(f.Labels, l)
	}
	sort.SliceStable(f.Labels, func(i, j int) bool { return f.Labels[i].Key().Less(f.Labels[j].Key()) })
	data, err := Marshal(f)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(root, target, data); err != nil {
		return nil, err
	}
	return out, nil
}

// Revert takes writes back: a key with no Prior is removed, and one with a Prior gets it back as
// it was. Each file is rewritten once, and deleted when it is left with no labels. Every file is
// read and every key found before anything is written, so a key that is not there reverts nothing.
func (w Writer) Revert(written []Written) error {
	byFile := map[string][]Written{}
	for _, k := range written {
		if loc, ok := Locate(k.File); !ok || !loc.IsLabelFile() {
			return fmt.Errorf("%s is not a label file in the corpus layout", k.File)
		}
		if p := k.Prior; p != nil {
			if p.Key() != k.Key {
				return fmt.Errorf("%s: the label to restore is %s, not %s", k.File, p.Key(), k.Key)
			}
			if err := CheckRequired(*p, nil); err != nil {
				return fmt.Errorf("%s: the label to restore, %s: %w", k.File, k.Key, err)
			}
		}
		byFile[k.File] = append(byFile[k.File], k)
	}
	if len(byFile) == 0 {
		return nil
	}
	root, err := openCorpus(w.Dir)
	if err != nil {
		return err
	}
	defer root.Close()
	kept := map[string]*File{}
	for rel, ks := range byFile {
		data, err := root.ReadFile(filepath.FromSlash(rel))
		if err != nil {
			return err
		}
		f, err := Parse(rel, data)
		if err != nil {
			return err
		}
		for _, k := range ks {
			i := slices.IndexFunc(f.Labels, func(l Label) bool { return l.Key() == k.Key })
			switch {
			case i < 0:
				return fmt.Errorf("%s: no label %s", rel, k.Key)
			case k.Prior != nil:
				f.Labels[i] = *k.Prior
			default:
				f.Labels = slices.Delete(f.Labels, i, i+1)
			}
		}
		kept[rel] = f
	}
	log.Infof("reverting %d labels in %d files in %s", len(written), len(kept), w.Dir)
	for _, rel := range slices.Sorted(maps.Keys(kept)) {
		f, target := kept[rel], filepath.FromSlash(rel)
		if len(f.Labels) == 0 {
			if err := root.Remove(target); err != nil {
				return err
			}
			continue
		}
		data, err := Marshal(f)
		if err != nil {
			return err
		}
		if err := writeAtomic(root, target, data); err != nil {
			return err
		}
	}
	return nil
}

// mergeSubject keeps the subject a file already names, and refuses a label about another.
func mergeSubject(rel string, f *File, s *Subject) error {
	switch {
	case s == nil || f.Subject == nil:
		if f.Subject == nil {
			f.Subject = s
		}
	case s.Image != f.Subject.Image || s.SBOM != f.Subject.SBOM:
		return fmt.Errorf("%s is about %s%s, not %s%s", rel, f.Subject.Image, f.Subject.SBOM, s.Image, s.SBOM)
	case s.Platform != f.Subject.Platform && s.Platform != "" && f.Subject.Platform != "":
		return fmt.Errorf("%s records platform %s, and the label was written against %s", rel, f.Subject.Platform, s.Platform)
	case f.Subject.Platform == "":
		f.Subject.Platform = s.Platform
	}
	return nil
}

// writeAtomic writes a file inside a corpus root through a temp file in the same directory and
// a rename, so a crash leaves either the old file or the new one.
func writeAtomic(root *os.Root, target string, data []byte) error {
	dir := filepath.Dir(target)
	if err := root.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.tmp-%d-%d", filepath.Base(target), os.Getpid(), time.Now().UnixNano()))
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return err
	}
	return rename(root, tmp, target)
}

// WriteFile writes a file into a corpus, by its corpus-relative path, whole or not at all and
// never outside the corpus, as the writer writes label files.
func WriteFile(dir, rel string, data []byte) error {
	root, err := openCorpus(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return writeAtomic(root, filepath.FromSlash(rel), data)
}
