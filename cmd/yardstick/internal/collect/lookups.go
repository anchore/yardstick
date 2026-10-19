package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/lookup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
)

// lookups asks each setup's DB about the rows only the other setup reported, and stores the
// answers in the partial set as <setup>/lookups.json. A DB that cannot answer (a grype older than
// `db search vuln`) is a warning, and its rows score as unexplained.
func (m Scans) lookups(ctx context.Context, partial *runrecord.Partial, rec *runrecord.Record, isAdvisory func(string) bool) error {
	subjects := make([]pairing.Subject, len(rec.Subjects))
	for i, s := range rec.Subjects {
		subjects[i] = pairing.Subject{Name: s.Name, Packages: s.Packages, Scans: map[string]*models.Document{}}
		for name, rel := range s.Scans {
			data, err := os.ReadFile(filepath.Join(partial.Dir, rel))
			if err != nil {
				return err
			}
			doc, err := Decode(data)
			if err != nil {
				return err
			}
			subjects[i].Scans[name] = &doc
		}
	}
	var rows []lookup.Row
	for i, r := range pairing.Scanned(subjects, isAdvisory) {
		for _, match := range r.Matches {
			if match.In(Candidate) != match.In(Reference) {
				rows = append(rows, lookup.Row{ID: pairing.RowID(subjects[i].Name, analysis.MatchID(match)), Match: match})
			}
		}
	}
	if len(rows) == 0 {
		return nil
	}
	for _, name := range []string{Candidate, Reference} {
		f, err := lookup.Search(ctx, dbSearch(m.Run, rec.Setups[name]), name, rows)
		if err != nil {
			w := fmt.Sprintf("the %s DB could not be searched for the rows only one setup reported, so they score as unexplained: %v", name, err)
			log.Warnf("%s", w)
			rec.Warnings = append(rec.Warnings, w)
			continue
		}
		data, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			return err
		}
		rel := name + "/lookups.json"
		if err := partial.Write(rel, append(data, '\n')); err != nil {
			return err
		}
		if rec.Lookups == nil {
			rec.Lookups = map[string]string{}
		}
		rec.Lookups[name] = rel
	}
	return nil
}

// dbSearch runs a setup's grype as its scans do: its config, env and DB.
func dbSearch(run execute.Runner, p setup.Prepared) lookup.Grype {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		cfg, err := configPath(p.Config)
		if err != nil {
			return nil, err
		}
		out, _, err := run.Run(ctx, execute.Cmd{Bin: p.Grype.Bin, Args: append([]string{"-c", cfg}, args...), DBDir: p.DB.Dir, Env: p.Env})
		return out, err
	}
}
