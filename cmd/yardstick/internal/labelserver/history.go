package labelserver

import (
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
)

// History is GET /api/history: one page of the labels in the writable claims sources (each gate's
// last source, where this server writes), newest first.
type History struct {
	Total   int            `json:"total"`
	Sources []string       `json:"sources"`
	Labels  []HistoryLabel `json:"labels"`
	// Started is when this server started (RFC 3339), which since=start means.
	Started string `json:"started"`
}

// LabelKey names one label in a writable claims source: what a write wrote, and what
// POST /api/history/revert takes back. Prior is the label the write replaced, absent when the key
// was new; revert puts it back, and removes the key when there is none.
type LabelKey struct {
	Source        string          `json:"source"`
	File          string          `json:"file"` // corpus-relative
	Package       string          `json:"package"`
	Vulnerability string          `json:"vulnerability"`
	Prior         *claimsv1.Label `json:"prior,omitempty"`
}

type RevertRequest struct {
	Labels []LabelKey `json:"labels"`
}

// RevertResponse counts the keys removed and the replaced labels put back.
type RevertResponse struct {
	Removed  int `json:"removed"`
	Restored int `json:"restored"`
}

// HistoryLabel is one label as its file holds it, and the rows it pairs in each gate.
type HistoryLabel struct {
	Label   claimsv1.Label `json:"label"`
	Package PackageInfo    `json:"package"`
	// Image is the file's subject (its image, else its SBOM digest), and ImageName what the UI
	// calls it; both empty for a global label.
	Image     string    `json:"image,omitempty"`
	ImageName string    `json:"imageName,omitempty"`
	Source    string    `json:"source"`
	File      string    `json:"file"` // corpus-relative
	Rows      []GateRow `json:"rows"`
}

type GateRow struct {
	Gate string `json:"gate"`
	Row  string `json:"row"`
}

// historyRows are the writable source of every gate, once each, and the rows each label in them
// pairs per gate, by source|file|key.
func (s *Server) historyRows() ([]*claims.Source, map[string][]GateRow, error) {
	all, err := s.entries()
	if err != nil {
		return nil, nil, err
	}
	var sources []*claims.Source
	rows := map[string][]GateRow{}
	for _, e := range all {
		v, err := s.view(e)
		if err != nil {
			continue
		}
		if _, err := v.set.Writer(); err != nil {
			continue // no writable source, so nothing this server wrote
		}
		src := v.set.Sources[len(v.set.Sources)-1]
		if !slices.ContainsFunc(sources, func(x *claims.Source) bool { return x.Locator == src.Locator }) {
			sources = append(sources, src)
		}
		for _, in := range v.paired.Inputs {
			for _, b := range in.Result.Labels {
				if !slices.ContainsFunc(b.Held, func(h claims.SourceVerdict) bool { return h.Source == src.Locator }) {
					continue
				}
				k := src.Locator + "|" + b.File + "|" + b.Key().String()
				for _, m := range b.Matches {
					if gr := (GateRow{e.name, pairing.RowID(in.Name, analysis.MatchID(m))}); !slices.Contains(rows[k], gr) {
						rows[k] = append(rows[k], gr)
					}
				}
			}
		}
	}
	return sources, rows, nil
}

// historyLabels are every label in a source's label files.
func historyLabels(src *claims.Source, rows map[string][]GateRow) ([]HistoryLabel, error) {
	var out []HistoryLabel
	err := fs.WalkDir(src.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if loc, ok := corpus.Locate(p); !ok || !loc.IsLabelFile() {
			return nil
		}
		data, err := fs.ReadFile(src.FS, p)
		if err != nil {
			return err
		}
		f, err := claimsv1.Parse(p, data)
		if err != nil {
			return err
		}
		for _, l := range f.Labels {
			hl := HistoryLabel{Label: l, Source: src.Locator, File: p, Rows: rows[src.Locator+"|"+p+"|"+l.Key().String()]}
			fields, _ := purl.Label(l.Package)
			hl.Package = PackageInfo{Name: fields.Name, Version: fields.Version, PURL: l.Package}
			if f.Subject != nil {
				hl.Image = f.Subject.Image + f.Subject.SBOM
				hl.ImageName = path.Base(digestSuffix.ReplaceAllString(hl.Image, ""))
			}
			out = append(out, hl)
		}
		return nil
	})
	return out, err
}

// historyText says a label holds the lowercase text in its vulnerability, package, image, reason,
// author or a note.
func historyText(l HistoryLabel, text string) bool {
	return containsText(text, l.Label.Notes, l.Label.Vulnerability, l.Package.PURL, l.ImageName, l.Label.Justification, l.Label.Author)
}

// handleHistory answers with the labels in the writable sources, newest first, filtered by
// verdict= and q= and paged by offset= and limit= as GET labels is. since= keeps the labels last
// updated at or after a time (RFC 3339, or start for the server's start).
func (s *Server) handleHistory(w http.ResponseWriter, req *http.Request) {
	lq, code, err := parseLabelQuery(req.URL.Query(), nil)
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	var since time.Time
	switch v := req.URL.Query().Get("since"); v {
	case "":
	case "start":
		since = s.started
	default:
		if since, err = time.Parse(time.RFC3339, v); err != nil {
			http.Error(w, "since must be start or an RFC 3339 time", http.StatusBadRequest)
			return
		}
	}
	sources, rows, err := s.historyRows()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := History{Sources: []string{}, Labels: []HistoryLabel{}, Started: s.started.Format(time.RFC3339)}
	var labels []HistoryLabel
	for _, src := range sources {
		out.Sources = append(out.Sources, src.Locator)
		ls, err := historyLabels(src, rows)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, l := range ls {
			// a label with no parsable time is older than any since
			at, _ := time.Parse(time.RFC3339, l.Label.LastUpdated)
			if (lq.verdict == "" || string(l.Label.Verdict) == lq.verdict) && (lq.text == "" || historyText(l, lq.text)) && !at.Before(since) {
				labels = append(labels, l)
			}
		}
	}
	slices.SortStableFunc(labels, func(a, b HistoryLabel) int { return strings.Compare(b.Label.LastUpdated, a.Label.LastUpdated) })
	out.Total = len(labels)
	if lq.offset < len(labels) {
		out.Labels = labels[lq.offset:min(len(labels), lq.offset+lq.limit)]
	}
	writeJSON(w, out)
}

// handleRevert undoes what a write wrote in the writable sources: a key with a prior gets that
// label back, and one without is removed, so a label held by an earlier source decides again.
// Nothing is reverted when any key names a source that is not writable or a label that is not
// there.
func (s *Server) handleRevert(w http.ResponseWriter, req *http.Request) {
	var body RevertRequest
	if !decode(w, req, &body) {
		return
	}
	if len(body.Labels) == 0 {
		http.Error(w, "no labels given", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sources, _, err := s.historyRows()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	bySource := map[string][]corpus.Written{}
	for _, k := range body.Labels {
		if !slices.ContainsFunc(sources, func(x *claims.Source) bool { return x.Locator == k.Source }) {
			http.Error(w, k.Source+" is not a writable claims source", http.StatusBadRequest)
			return
		}
		wt := corpus.Written{File: k.File, Key: claimsv1.Key{Package: k.Package, Vulnerability: k.Vulnerability}, Prior: k.Prior}
		if !slices.ContainsFunc(bySource[k.Source], func(x corpus.Written) bool { return x.File == wt.File && x.Key == wt.Key }) {
			bySource[k.Source] = append(bySource[k.Source], wt)
		}
	}
	// ponytail: checked per source, so a second source refusing leaves the first's reverts; one
	// writable source is the usual workspace
	var out RevertResponse
	for _, src := range sources {
		ws := bySource[src.Locator]
		if len(ws) == 0 {
			continue
		}
		if err := (corpus.Writer{Dir: src.Dir}).Revert(ws); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, wt := range ws {
			if wt.Prior != nil {
				out.Restored++
			} else {
				out.Removed++
			}
		}
	}
	log.Infof("reverted %d label(s): %d removed, %d restored", out.Removed+out.Restored, out.Removed, out.Restored)
	writeJSON(w, out)
}
