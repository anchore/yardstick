// Package v1 is version 1 of the claims corpus format: one JSON file per subject and package type,
// each label one person's call (tp, fp or unclear) on one vulnerability on one package, carrying
// the evidence it rests on. yardstick owns the format; the corpus owns the vocabulary.
//
// the v1 here is the format's MODEL and nothing else. A breaking change to yardstick leaves it
// alone, and a v2 format lands beside this package rather than in it.
package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Masterminds/semver/v3"
)

// Version is the label file format this package writes, as SchemaVer MODEL.REVISION.ADDITION
// (the same scheme syft's JSON schema follows). It is not yardstick's version.
//
//   - ADDITION: a change every existing file still satisfies, like a new optional field
//   - REVISION: a change some existing files may not satisfy
//   - MODEL: a change no existing file satisfies, such as what a label means or how it pairs
//
// a MODEL bump is a new package beside this one, not an edit to it. A new vocabulary value is
// no bump at all, since the vocabulary is the corpus's data.
const Version = "1.0.0"

// Major is Version's MODEL as the corpus names it: the format in its publish.yaml, and the
// claims/latest-<major>.json pointer a remote source reads.
const Major = "v1"

// Verdict is a call on a match.
type Verdict string

const (
	TP      Verdict = "tp"
	FP      Verdict = "fp"
	Unclear Verdict = "unclear"
)

// Verdicts are the three calls, in the order they are listed.
func Verdicts() []Verdict { return []Verdict{TP, FP, Unclear} }

// File is one label file.
type File struct {
	Schema  string   `json:"schema"`
	Subject *Subject `json:"subject,omitempty"` // absent in global/ files
	Labels  []Label  `json:"labels"`
}

// Subject says what a file's labels are about: an image, or an SBOM document by digest.
type Subject struct {
	Image    string `json:"image,omitempty"` // <registry>/<repository>[:tag]@sha256:<digest>
	SBOM     string `json:"sbom,omitempty"`  // sha256:<digest> of the document's bytes
	Platform string `json:"platform,omitempty"`
}

// Label is one call on one match.
type Label struct {
	Package       string     `json:"package,omitempty"` // a purl; a field it does not state matches anything
	Vulnerability string     `json:"vulnerability"`
	Verdict       Verdict    `json:"verdict"`
	Justification string     `json:"justification,omitempty"`
	Author        string     `json:"author"`
	Evidence      []Evidence `json:"evidence,omitempty"`
	Notes         []Note     `json:"notes,omitempty"`
	SeenIn        *SeenIn    `json:"seenIn,omitempty"`
	FirstIssued   string     `json:"firstIssued"`
	LastUpdated   string     `json:"lastUpdated"`
	// Extra holds fields this yardstick does not know, so rewriting a file written by a newer
	// one keeps them. ponytail: only a label's own fields; unknown fields nested in evidence or
	// seenIn are dropped on rewrite, add the same capture there when a format adds one.
	Extra map[string]json.RawMessage `json:"-"`
}

// Evidence is what a call rests on: the raw observations, the policy rule (vocabulary.yaml's
// rules) they satisfy when one does, and what they mean for this call.
type Evidence struct {
	Rule           string `json:"rule,omitempty"`
	Facts          []Fact `json:"facts"`
	Interpretation string `json:"interpretation,omitempty"`
}

// Fact is a raw observation someone can check again.
type Fact struct {
	Source     string            `json:"source"`
	URL        string            `json:"url,omitempty"`
	About      map[string]string `json:"about"`
	Field      string            `json:"field"`
	Value      string            `json:"value"`
	ObservedAt string            `json:"observedAt"`
}

// Note is something a person (or a migration on their behalf) said about a label, and when.
type Note struct {
	Text   string `json:"text"`
	Author string `json:"author"`
	At     string `json:"at"`
}

// SeenIn is what a label was written against: the SBOM scanned, and the tools that cataloged and
// matched it.
type SeenIn struct {
	SBOM  string `json:"sbom,omitempty"`
	Tools []Tool `json:"tools,omitempty"`
}

// Tool is one tool a label was written against, by name and version. The grype DB is a tool here
// too (grype-db), with its checksum as the version.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tool names yardstick itself records in seenIn.
const (
	ToolSyft    = "syft"
	ToolGrype   = "grype"
	ToolGrypeDB = "grype-db"
)

// Tool is the version of the named tool, empty when the label was not written against it.
func (s *SeenIn) Tool(name string) string {
	if s == nil {
		return ""
	}
	for _, t := range s.Tools {
		if t.Name == name {
			return t.Version
		}
	}
	return ""
}

// NotesOf is one note by author at a time, or none when text is empty: how a label written with
// a single note (claims add, the label UI, an accepted proposal) carries it.
func NotesOf(text, author, at string) []Note {
	if text == "" {
		return nil
	}
	return []Note{{Text: text, Author: author, At: at}}
}

// NoteTexts are a label's notes' texts in order, for places that show a label in one line.
func (l Label) NoteTexts() []string {
	out := make([]string, 0, len(l.Notes))
	for _, n := range l.Notes {
		out = append(out, n.Text)
	}
	return out
}

// Key identifies a label within one file: at most one label per key.
type Key struct {
	Package       string
	Vulnerability string
}

func (l Label) Key() Key {
	return Key{Package: l.Package, Vulnerability: l.Vulnerability}
}

// Less orders keys by package then vulnerability, package-less first.
func (k Key) Less(o Key) bool {
	if k.Package != o.Package {
		return k.Package < o.Package
	}
	return k.Vulnerability < o.Vulnerability
}

func (k Key) String() string {
	if k.Package == "" {
		return k.Vulnerability
	}
	return k.Vulnerability + " on " + k.Package
}

// labelFields is Label without its methods, for encoding/json.
type labelFields Label

var knownLabelKeys = []string{"package", "vulnerability", "verdict", "justification", "author", "evidence", "notes", "seenIn", "firstIssued", "lastUpdated"}

func (l *Label) UnmarshalJSON(data []byte) error {
	var f labelFields
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	for _, k := range knownLabelKeys {
		delete(all, k)
	}
	*l = Label(f)
	l.Extra = nil
	if len(all) > 0 {
		l.Extra = all
	}
	return nil
}

func (l Label) MarshalJSON() ([]byte, error) {
	b, err := marshal(labelFields(l))
	if err != nil || len(l.Extra) == 0 {
		return b, err
	}
	keys := make([]string, 0, len(l.Extra))
	for k := range l.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.Write(bytes.TrimSuffix(b, []byte("}")))
	for _, k := range keys {
		name, _ := marshal(k)
		buf.WriteByte(',')
		buf.Write(name)
		buf.WriteByte(':')
		buf.Write(l.Extra[k])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// marshal is json.Marshal without HTML escaping, so a purl's & stays an &.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Marshal encodes a file the one way the writer writes every file: two-space indent, fields in
// a fixed order, no HTML escaping, a trailing newline. The same labels give the same bytes.
func Marshal(f *File) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MajorOf is a schema value's MODEL as Major spells it, v1 for 1.0.0 and 1.2.0, or "" for a
// value that is not a version.
func MajorOf(schema string) string {
	v, err := semver.StrictNewVersion(schema)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("v%d", v.Major())
}

// newer reports whether schema is a later version than Version. Both are the same MODEL.
func newer(schema string) bool {
	v, err := semver.StrictNewVersion(schema)
	return err == nil && v.GreaterThan(semver.MustParse(Version))
}

// Parse reads a label file, refusing a format MODEL this yardstick does not read before
// anything else about it is trusted. Unlike syft, a later REVISION or ADDITION of the same MODEL
// is read: the corpus moves ahead of yardstick releases, and unknown fields are kept. name is
// used in errors.
func Parse(name string, data []byte) (*File, error) {
	var head struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if MajorOf(head.Schema) != Major {
		return nil, fmt.Errorf("%s: label format %q; this yardstick reads %s (%s), so another yardstick is needed", name, head.Schema, Major, Version)
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &f, nil
}
