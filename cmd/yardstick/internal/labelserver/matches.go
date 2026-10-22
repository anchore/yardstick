package labelserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

// MatchesResponse is what each setup's grype said about a row, and the SBOM artifact matched,
// verbatim: the tile draws the match path from it and shows it as raw JSON.
type MatchesResponse struct {
	Candidate   []json.RawMessage `json:"candidate"`
	Reference   []json.RawMessage `json:"reference"`
	Artifact    json.RawMessage   `json:"artifact,omitempty"`
	SBOMMissing string            `json:"sbomMissing,omitempty"` // the SBOM's path, when it is gone (a cache file)
}

// ponytail: reads the scans and the SBOM on every request; cache by path if the tile feels slow
func (s *Server) handleMatches(w http.ResponseWriter, req *http.Request) {
	e, v := s.viewFor(w, req)
	if v == nil {
		return
	}
	r := v.rows[req.PathValue("id")]
	if r == nil {
		http.Error(w, "no such row", http.StatusNotFound)
		return
	}
	sub := e.rec.Subjects[r.si]
	resp := MatchesResponse{Candidate: []json.RawMessage{}, Reference: []json.RawMessage{}}
	for setup, out := range map[string]*[]json.RawMessage{gatefile.Candidate: &resp.Candidate, gatefile.Reference: &resp.Reference} {
		if len(r.pm.Rows[setup]) == 0 {
			continue
		}
		items, err := rawItems(filepath.Join(runrecord.Dir(s.opts.Run, e.name), sub.Scans[setup]), "matches")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// the pairing's indexes into this setup's grype matches
		for _, i := range r.pm.Rows[setup] {
			if i < len(items) {
				*out = append(*out, items[i])
			}
		}
	}
	artifacts, err := rawItems(sub.SBOM, "artifacts")
	switch {
	case errors.Is(err, os.ErrNotExist):
		resp.SBOMMissing = sub.SBOM
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, a := range artifacts {
		var head struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(a, &head) == nil && head.ID == r.pm.Package.ID {
			resp.Artifact = a
			break
		}
	}
	writeJSON(w, resp)
}

// rawItems is one array of a JSON document, its items left undecoded.
func rawItems(path, key string) ([]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, err
	}
	var items []json.RawMessage
	if top[key] != nil {
		err = json.Unmarshal(top[key], &items)
	}
	return items, err
}
