// Package claims reads labels from a gate's ordered claims sources: local corpus directories,
// published snapshots and claims directories in GitHub repositories. Reads take the union of every
// source, the last source holding a key decides its verdict (with a warning when an earlier one
// disagrees), and writes go to the last source, which must be local. A gate reads only the files
// its own subjects need.
package claims

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing/fstest"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// Kinds of source.
const (
	Corpus = "corpus" // a local directory in the corpus layout
	Remote = "remote" // a published snapshot, or a claims directory in a GitHub repository
)

// Source is one claims source, read as a file system in the corpus layout.
type Source struct {
	Locator string
	Kind    string
	FS      fs.FS
	// Dir is a local source's directory; empty for a remote one.
	Dir string
	// Digest and Commit identify a remote source's snapshot.
	Digest, Commit string
	// Downloaded is true when this process fetched the snapshot rather than finding it cached.
	Downloaded bool

	closer io.Closer // what backs FS: the local root, or the snapshot's zip file

	mu   sync.Mutex
	read map[string]string // corpus path read to the sha256 of its bytes
}

// Open opens a gate's claims source.
func Open(s gatefile.Source) (*Source, error) {
	defer log.Timed("opening claims source %s", s.Locator)()
	switch {
	case s.Remote != nil && s.Remote.Path != "":
		return openArchive(s)
	case s.Remote != nil:
		return openRemote(s)
	}
	log.Infof("opening local claims source %s", s.Locator)
	info, err := os.Stat(s.Locator)
	if s.Create && errors.Is(err, os.ErrNotExist) {
		// empty until the first write creates it
		return &Source{Locator: s.Locator, Kind: Corpus, FS: fstest.MapFS{}, Dir: s.Locator, read: map[string]string{}}, nil
	}
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("claims source %s is not a directory", s.Locator)
	}
	// a claims directory can be pull request content; reads stay inside it, symlinks included
	root, err := os.OpenRoot(s.Locator)
	if err != nil {
		return nil, fmt.Errorf("claims source %s: %w", s.Locator, err)
	}
	return &Source{Locator: s.Locator, Kind: Corpus, FS: root.FS(), Dir: s.Locator, closer: root, read: map[string]string{}}, nil
}

// Close releases what the source holds open.
func (s *Source) Close() error {
	if s.closer == nil {
		return nil
	}
	return s.closer.Close()
}

// ReadFile reads one corpus file, recording it toward the source's snapshot identity. A file
// that is not there is fs.ErrNotExist.
func (s *Source) ReadFile(p string) ([]byte, error) {
	data, err := fs.ReadFile(s.FS, p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	s.mu.Lock()
	s.read[p] = hex.EncodeToString(sum[:])
	s.mu.Unlock()
	return data, nil
}

// Read is every corpus path this source has read, sorted.
func (s *Source) Read() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.read))
	for p := range s.read {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Snapshot identifies what was read: a published snapshot's digest, or for any other source a
// content hash over the files read, which changes exactly when one of them does.
func (s *Source) Snapshot() string {
	if s.Digest != "" {
		return s.Digest
	}
	h := sha256.New()
	for _, p := range s.Read() {
		s.mu.Lock()
		fmt.Fprintf(h, "%s\x00%s\n", p, s.read[p])
		s.mu.Unlock()
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Set is a gate's claims sources, in gate order.
type Set struct {
	Sources []*Source
	// vocab is what Vocabulary answers; nil when no source has one
	vocab *claimsv1.Vocabulary
}

// OpenSet opens every source of a gate, in order.
func OpenSet(sources []gatefile.Source) (*Set, error) {
	return openSet(sources, nil)
}

// Reopen is the set opened again, for a long-lived reader such as the label server: its remote
// sources are reused as they are, since a snapshot never changes and resolving @main again costs a
// request each time, and its local ones are opened afresh. The set it was reopened from keeps
// working, and closing it would close the remote sources the two share.
func (s *Set) Reopen(sources []gatefile.Source) (*Set, error) {
	remote := map[string]*Source{}
	for _, src := range s.Sources {
		if src.Kind == Remote {
			remote[src.Locator] = src
		}
	}
	return openSet(sources, remote)
}

func openSet(sources []gatefile.Source, remote map[string]*Source) (*Set, error) {
	set := &Set{}
	for _, gs := range sources {
		if s := remote[gs.Locator]; s != nil && gs.Remote != nil {
			set.Sources = append(set.Sources, s)
			continue
		}
		s, err := Open(gs)
		if err != nil {
			_ = set.Close()
			return nil, err
		}
		set.Sources = append(set.Sources, s)
	}
	vocab, err := set.findVocabulary()
	if err != nil {
		_ = set.Close()
		return nil, err
	}
	set.vocab = vocab
	return set, nil
}

// findVocabulary is every source's vocabulary merged, in order: the one vocabulary a set reads and
// writes by; nil when no source has one.
func (s *Set) findVocabulary() (*claimsv1.Vocabulary, error) {
	named := make([]claimsv1.NamedFS, len(s.Sources))
	for i, src := range s.Sources {
		named[i] = claimsv1.NamedFS{Name: src.Locator, FS: src.FS}
	}
	return claimsv1.MergeVocabularies(named...)
}

// VocabularyPath is the writable source's vocabulary.yaml, where a namespace the set lacks would be
// added; empty when no source is writable.
func (s *Set) VocabularyPath() string {
	if w := s.writable(); w != nil {
		return filepath.Join(w.Dir, claimsv1.VocabularyFile)
	}
	return ""
}

// writable is the last source when it is local, else nil.
func (s *Set) writable() *Source {
	if len(s.Sources) == 0 || s.Sources[len(s.Sources)-1].Kind != Corpus {
		return nil
	}
	return s.Sources[len(s.Sources)-1]
}

// Close closes every source in the set.
func (s *Set) Close() error {
	var errs []error
	for _, src := range s.Sources {
		errs = append(errs, src.Close())
	}
	return errors.Join(errs...)
}

// Writer is a label writer into the last source, which must be a local directory, checking
// against Vocabulary. A source not there yet is created by the first write.
func (s *Set) Writer() (corpus.Writer, error) {
	if len(s.Sources) == 0 {
		return corpus.Writer{}, errors.New("no claims source to write labels to")
	}
	last := s.writable()
	if last == nil {
		return corpus.Writer{}, fmt.Errorf("writes need a local last claims source, and the last is %s; add one with --claims <path>", s.Sources[len(s.Sources)-1].Locator)
	}
	if err := s.vocab.CheckWritable(); err != nil {
		return corpus.Writer{}, err
	}
	return corpus.Writer{Dir: last.Dir, Vocab: s.vocab}, nil
}

// Subject is what a gate reads labels for: a subject's directory in the corpus layout and the
// package types present in its SBOM.
type Subject struct {
	Name  string
	Dir   string
	Types []string
}

// Label is a label as a gate reads it: one per scope and key across every source.
type Label struct {
	claimsv1.Label
	// Global is set for a label from global/, which holds on every subject.
	Global bool
	// File is where it was read, corpus-relative.
	File string
	// Held is each source holding this key, with its verdict, in source order.
	Held []SourceVerdict
}

// Source is the source the label was read from: the last one holding its key.
func (l Label) Source() string {
	return l.Held[len(l.Held)-1].Source
}

// Disagrees says whether the sources holding the key give different verdicts; the last source's
// verdict is the one used.
func (l Label) Disagrees() bool {
	for _, h := range l.Held {
		if h.Verdict != l.Held[0].Verdict {
			return true
		}
	}
	return false
}

// SourceVerdict is one source's verdict on a key.
type SourceVerdict struct {
	Source  string
	Verdict claimsv1.Verdict
}

// Labels are one subject's labels across every source.
type Labels struct {
	Labels []Label
	// Platforms are the subject.platform values its files record, for the platform warning.
	Platforms []string
	Warnings  []string
}

// scopedKey keys the union: a subject label and a global label on one match are two labels.
type scopedKey struct {
	global bool
	claimsv1.Key
}

// Read reads one subject's labels from every source: the type files for its package types, its
// image.json, and global/matches/<type>.json for the same types. Files are read in no other place, so a
// gate's cost follows its subjects.
func (s *Set) Read(sub Subject) (*Labels, error) {
	out := &Labels{}
	byKey := map[scopedKey]int{}
	platforms := map[string]bool{}
	for _, src := range s.Sources {
		for _, p := range subjectFiles(sub) {
			f, err := src.readLabels(p)
			if err != nil {
				return nil, err
			}
			if f == nil {
				continue
			}
			if f.Subject != nil && f.Subject.Platform != "" {
				platforms[f.Subject.Platform] = true
			}
			if err := add(out, byKey, src, p, f); err != nil {
				return nil, err
			}
		}
	}
	for p := range platforms {
		out.Platforms = append(out.Platforms, p)
	}
	sort.Strings(out.Platforms)
	for _, l := range out.Labels {
		if l.Disagrees() {
			log.Debugf("claims sources disagree on %s in %s", l.Key(), sub.Name)
			out.Warnings = append(out.Warnings, disagreement(sub.Name, l))
		}
	}
	return out, nil
}

// subjectFiles are the files a subject's labels are in.
func subjectFiles(sub Subject) []string {
	types := append([]string(nil), sub.Types...)
	sort.Strings(types)
	log.Debugf("subject %s read package types %v", sub.Name, types)
	files := []string{corpus.NoPackagePath(sub.Dir)}
	for _, t := range types {
		if corpus.ValidType(t) {
			files = append(files, corpus.TypeFile(sub.Dir, t), corpus.GlobalFile(t))
		}
	}
	return files
}

func (s *Source) readLabels(p string) (*claimsv1.File, error) {
	data, err := s.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claims source %s: %w", s.Locator, err)
	}
	f, err := claimsv1.Parse(s.Locator+": "+p, data)
	if err == nil {
		log.Debugf("read %s from %s: %d labels", p, s.Locator, len(f.Labels))
	}
	return f, err
}

// add takes one file's labels into the union: a key new to the union is added, and a key already
// there takes this source's label, since sources are read in order and the last one wins, while
// recording its verdict beside the others. The same verdict twice counts once. A key listed twice
// in one file is refused, as claims validate refuses it, rather than letting the later one win.
func add(out *Labels, byKey map[scopedKey]int, src *Source, p string, f *claimsv1.File) error {
	global := strings.HasPrefix(p, "global/")
	inFile := map[claimsv1.Key]bool{}
	for _, l := range f.Labels {
		if inFile[l.Key()] {
			return fmt.Errorf("claims source %s: %s: %s is listed twice; a file holds one label per package and vulnerability", src.Locator, p, l.Key())
		}
		inFile[l.Key()] = true
		k := scopedKey{global: global, Key: l.Key()}
		held := SourceVerdict{Source: src.Locator, Verdict: l.Verdict}
		if i, seen := byKey[k]; seen {
			out.Labels[i].Label, out.Labels[i].File = l, p
			out.Labels[i].Held = append(out.Labels[i].Held, held)
			continue
		}
		byKey[k] = len(out.Labels)
		out.Labels = append(out.Labels, Label{Label: l, Global: global, File: p, Held: []SourceVerdict{held}})
	}
	return nil
}

func disagreement(subject string, l Label) string {
	parts := make([]string, len(l.Held))
	for i, d := range l.Held {
		parts[i] = d.Source + ": " + string(d.Verdict)
	}
	return fmt.Sprintf("claims sources disagree on %s in %s (%s); %s's verdict is used", l.Key(), subject, strings.Join(parts, ", "), l.Source())
}

// Vocabulary is the vocabulary labels are read and written by: every source's vocabulary.yaml
// merged; nil when none has one.
func (s *Set) Vocabulary() *claimsv1.Vocabulary {
	return s.vocab
}
