package labelserver

import (
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
)

// History is GET /api/history: one page of the labels in the writable claims sources (each gate's
// last source, where this server writes), newest first.
type History struct {
	Total   int            `json:"total"`
	Sources []string       `json:"sources"`
	Labels  []HistoryLabel `json:"labels"`
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
		if loc, ok := claimsv1.Locate(p); !ok || !loc.IsLabelFile() {
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
	for _, s := range []string{l.Label.Vulnerability, l.Package.PURL, l.ImageName, l.Label.Justification, l.Label.Author} {
		if strings.Contains(strings.ToLower(s), text) {
			return true
		}
	}
	return slices.ContainsFunc(l.Label.Notes, func(n claimsv1.Note) bool { return strings.Contains(strings.ToLower(n.Text), text) })
}

// handleHistory answers with the labels in the writable sources, newest first, filtered by
// verdict= and q= and paged by offset= and limit= as GET labels is.
func (s *Server) handleHistory(w http.ResponseWriter, req *http.Request) {
	lq, code, err := parseLabelQuery(req.URL.Query(), nil)
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	sources, rows, err := s.historyRows()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := History{Sources: []string{}, Labels: []HistoryLabel{}}
	var labels []HistoryLabel
	for _, src := range sources {
		out.Sources = append(out.Sources, src.Locator)
		ls, err := historyLabels(src, rows)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, l := range ls {
			if (lq.verdict == "" || string(l.Label.Verdict) == lq.verdict) && (lq.text == "" || historyText(l, lq.text)) {
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
