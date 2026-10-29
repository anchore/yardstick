package labelserver

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
)

// A vulnerability whose namespace the gate's vocabulary lacks: research on it is refused before it
// runs, since proposing its call would be refused after, and the refusal says which list to add the
// namespace to, which the UI offers to do in the writable claims source's vocabulary.yaml.

// codeUnlistedNamespace marks a research refusal whose body is an UnlistedNamespace.
const codeUnlistedNamespace = "unlisted-namespace"

// UnlistedNamespace is a namespace a gate's vocabulary lacks and the list the gate's scan suggests
// for it: the body of a research refusal (with code and error) and an entry of a gate's state.
type UnlistedNamespace struct {
	// Code is "unlisted-namespace" on a refusal; Error is its text, as any refusal's is.
	Code  string `json:"code,omitempty" tstype:"\"unlisted-namespace\""`
	Error string `json:"error,omitempty"`
	Gate  string `json:"gate"`
	// ID is the refused vulnerability, or on a gate's state the first open row's in the namespace.
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
	// Suggest is the list the scan's ids suggest, absent when the scan has none in the namespace.
	Suggest string `json:"suggest,omitempty" tstype:"VocabularyList"`
	// Checked counts the scan's ids in the namespace; Example is one that shows the suggestion.
	Checked int               `json:"checked"`
	Example *NamespaceExample `json:"example,omitempty"`
	// File is the vocabulary.yaml an add writes, relative to the workspace when inside it; empty
	// when the gate has no writable claims source.
	File string `json:"file,omitempty"`
}

// NamespaceExample is one id of a namespace and the vulnerabilities it names.
type NamespaceExample struct {
	ID    string   `json:"id"`
	Names []string `json:"names"`
}

// AddNamespaceRequest is POST /api/gates/{gate}/vocabulary/namespace.
type AddNamespaceRequest struct {
	Namespace string `json:"namespace"`
	List      string `json:"list" tstype:"VocabularyList"`
}

// AddNamespaceResponse is the vocabulary.yaml written (as UnlistedNamespace.File names it), whether
// the write created it, and whether the namespace was added rather than already listed.
type AddNamespaceResponse struct {
	File    string `json:"file"`
	Created bool   `json:"created"`
	Added   bool   `json:"added"`
}

// unlistedOf is a refusal as the wire has it.
func unlistedOf(gate string, u *claimsv1.Unlisted) UnlistedNamespace {
	out := UnlistedNamespace{Gate: gate, ID: u.ID, Namespace: u.Namespace, Suggest: u.Suggest, Checked: u.Checked, File: workspacePath(u.File)}
	if u.Example != "" {
		out.Example = &NamespaceExample{ID: u.Example, Names: append([]string{}, u.Names...)}
	}
	return out
}

// workspacePath is a path relative to the server's working directory, the workspace, when inside it.
func workspacePath(p string) string {
	if p == "" || !filepath.IsAbs(p) {
		return p
	}
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	// a temp or home directory may be reached through a symlink on one side only
	for _, dir := range []string{wd, evalSymlinks(wd)} {
		if rel, err := filepath.Rel(dir, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return rel
		}
	}
	return p
}

func evalSymlinks(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// checkNamespaces refuses research on any of the requests whose vulnerability's namespace its
// gate's vocabulary lacks, answering with an UnlistedNamespace; views are the gates' by name.
func checkNamespaces(w http.ResponseWriter, views map[string]*view, reqs []research.Request) bool {
	for _, r := range reqs {
		v := views[r.Gate]
		if v == nil || v.vocab.CheckWritable() != nil {
			continue
		}
		err := v.vocab.CheckScanned(r.Vulnerability, v.set.VocabularyPath(), v.related())
		var u *claimsv1.Unlisted
		if errors.As(err, &u) {
			out := unlistedOf(r.Gate, u)
			// the text names the file as the body does
			u.File = out.File
			out.Code, out.Error = codeUnlistedNamespace, u.Error()
			writeJSONStatus(w, http.StatusBadRequest, out)
			return false
		}
	}
	return true
}

// unlisted is each namespace of the view's open rows its vocabulary lacks, with what the scan
// suggests, so the gate can say so before anyone starts research there.
func (v *view) unlisted(gate string) []UnlistedNamespace {
	if v.vocab.CheckWritable() != nil {
		return nil
	}
	file, related := v.set.VocabularyPath(), v.related()
	seen := map[string]bool{}
	var out []UnlistedNamespace
	for _, id := range slices.Sorted(maps.Keys(v.rows)) {
		r := v.rows[id]
		ns := claimsv1.Namespace(r.match.Vulnerability)
		if !r.open() || seen[ns] {
			continue
		}
		seen[ns] = true
		var u *claimsv1.Unlisted
		if errors.As(v.vocab.CheckScanned(r.match.Vulnerability, file, related), &u) {
			out = append(out, unlistedOf(gate, u))
		}
	}
	return out
}

// namespacePattern is what a namespace may be: what an id holds before its first '-'.
var namespacePattern = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)

// handleAddNamespace adds a namespace to a list of the vocabulary.yaml in the gate's writable claims
// source, the one labels are written to, creating the file when it has none and otherwise editing
// it in place. The next request's view reads it: a view is rebuilt when a local source's files change.
func (s *Server) handleAddNamespace(w http.ResponseWriter, req *http.Request) {
	var body AddNamespaceRequest
	if !decode(w, req, &body) {
		return
	}
	if !namespacePattern.MatchString(body.Namespace) {
		http.Error(w, fmt.Sprintf("namespace must be letters, digits, '_' or '.', got %q", body.Namespace), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	file := v.set.VocabularyPath()
	if file == "" {
		http.Error(w, fmt.Sprintf("gate %s has no local claims source to write %s to; add one with --claims <path>", e.name, claimsv1.VocabularyFile), http.StatusBadRequest)
		return
	}
	// a namespace written with no full vocabulary to add to would be a fragment alone, refusing every label
	if err := v.vocab.CheckWritable(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := AddNamespaceResponse{File: workspacePath(file)}
	already, err := v.vocab.CheckAdd(body.Namespace, body.List)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if already {
		writeJSON(w, out)
		return
	}
	data, err := os.ReadFile(file)
	out.Created = errors.Is(err, fs.ErrNotExist)
	if err != nil && !out.Created {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	edited, err := claimsv1.AddToList(data, body.Namespace, body.List)
	if err != nil {
		http.Error(w, fmt.Sprintf("%s: %v", out.File, err), http.StatusBadRequest)
		return
	}
	if err := corpus.WriteFile(filepath.Dir(file), claimsv1.VocabularyFile, edited); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out.Added = true
	log.Infof("added %s to %s in %s", body.Namespace, body.List, file)
	writeJSON(w, out)
}
