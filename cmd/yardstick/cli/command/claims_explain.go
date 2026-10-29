package command

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

func ClaimsExplain(app clio.Application) *cobra.Command {
	cmd := app.SetupCommand(&cobra.Command{
		Use:   "explain",
		Short: "Record and list explanations of why a gate's two setups differ",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	})
	cmd.AddCommand(ClaimsExplainPropose(app), ClaimsExplainList(app))
	return cmd
}

func ClaimsExplainPropose(app clio.Application) *cobra.Command {
	cfg := &agentOptions{nameOption: newNameOption()}
	return app.SetupCommand(&cobra.Command{
		Use:   "propose [file] [--gate <gate>]",
		Short: "Record agent-written explanations of a gate's differences (JSON lines on stdin or in a file)",
		Long: `propose reads explanations as JSON lines and records them in .yardstick/explanations.jsonl,
where the label UI shows them in place of the computed reason for the rows they list. An
explanation carries no verdict and accepting it writes nothing: it says why the setups differ, not
whether a finding is real. Nothing is recorded unless every line is valid.

Each line's "gate" (default --gate) and "run" (default --name) name the scan it explains, and it is
checked against that scan:
  - every member row must be in the scan; a member may give just its "row", and its vulnerability
    and package are filled in
  - a row may be in only one explanation per gate and run; to move rows, supersede the explanation
    that has them by reusing its id
  - "reason", when given, must be a computed why key
  - each log excerpt must quote a grype log the scan kept, as the run record lists it under
    subjects[].logs, with that log's sha256, and its text must be exactly the lines it cites

schema, id and timestamp are filled in when missing, and author.kind defaults to agent. Each
recorded explanation prints as id, gate, member count and title, tab separated.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in, err := openInput(cmd, args)
			if err != nil {
				return err
			}
			defer in.Close()
			lines, err := readJSONL[agentstore.Explanation](in, "explanations")
			if err != nil {
				return err
			}
			store := agentstore.Open(agentstore.Dir)
			current, err := store.Explanations.Current()
			if err != nil {
				return err
			}
			opened := map[[2]string]*scanned{}
			now := time.Now().UTC()
			for i := range lines {
				e := &lines[i]
				if err := explanation(e, cfg, opened, current, now); err != nil {
					return fmt.Errorf("explanation %d: %w", i+1, err)
				}
				// later lines are checked against earlier ones, as if they were already recorded
				current = supersede(current, *e)
			}
			if err := store.Explanations.Add(lines...); err != nil {
				return err
			}
			for _, e := range lines {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%d members\t%s\n", e.ID, e.Gate, len(e.Members), e.Title)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "recorded %d explanation(s) in %s\n", len(lines), agentstore.Dir)
			return nil
		},
	}, cfg)
}

// explanation fills an explanation in from its scan's rows and checks it against the scan and the
// other current explanations. opened holds the scans read so far, by run and gate.
func explanation(e *agentstore.Explanation, cfg *agentOptions, opened map[[2]string]*scanned, current []agentstore.Explanation, now time.Time) error {
	gate := e.Gate
	if gate == "" {
		gate = cfg.Gate
	}
	if e.Run == "" {
		e.Run = cfg.Name
	}
	key := [2]string{e.Run, gate}
	s, ok := opened[key]
	if !ok {
		var err error
		if s, err = openScanned(e.Run, gate, cfg.Claims); err != nil {
			return err
		}
		opened[key] = s
	}
	e.Gate = s.gate.Name
	for i := range e.Members {
		m, _, err := s.member(e.Members[i])
		if err != nil {
			return fmt.Errorf("member %d: %w", i+1, err)
		}
		e.Members[i] = m
	}
	fillDefaults(&e.Schema, &e.ID, &e.Timestamp, &e.Author, cfg.Research.ID, now)
	if err := e.Validate(); err != nil {
		return err
	}
	if e.Reason != "" && !slices.Contains(report.WhyKeys, e.Reason) {
		return fmt.Errorf("reason %q is not a computed why key (one of %s)", e.Reason, strings.Join(report.WhyKeys, ", "))
	}
	for i, x := range e.LogExcerpts {
		if err := s.checkExcerpt(x); err != nil {
			return fmt.Errorf("log excerpt %d: %w", i+1, err)
		}
	}
	return overlap(current, *e)
}

// checkExcerpt makes sure an excerpt quotes, exactly, lines of a log the scan kept for its side.
func (s *scanned) checkExcerpt(x agentstore.LogExcerpt) error {
	var kept *runrecord.Log
	for _, sub := range s.rec.Subjects {
		if l, ok := sub.Logs[x.Side]; ok && l.Path == x.File {
			kept = &l
		}
	}
	switch {
	case kept == nil:
		return fmt.Errorf("gate %s's last scan under run %s kept no %s log %q", s.gate.Name, s.run, x.Side, x.File)
	case kept.SHA256 != x.SHA256:
		return fmt.Errorf("sha256 %s is not the log's, %s, in the run record", x.SHA256, kept.SHA256)
	}
	text, err := readLog(filepath.Join(runrecord.Dir(s.run, s.gate.Name), x.File))
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(text); hex.EncodeToString(sum[:]) != x.SHA256 {
		return fmt.Errorf("%s no longer matches the sha256 the run record holds for it", x.File)
	}
	lines := strings.Split(string(text), "\n")
	if x.Lines[1] > len(lines) {
		return fmt.Errorf("lines %v are past the end of %s (%d lines)", x.Lines, x.File, len(lines))
	}
	if want := strings.Join(lines[x.Lines[0]-1:x.Lines[1]], "\n"); strings.TrimRight(x.Text, "\n") != want {
		return fmt.Errorf("text is not lines %d-%d of %s; copy them exactly", x.Lines[0], x.Lines[1], x.File)
	}
	return nil
}

// readLog is a gzipped log's text.
func readLog(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return io.ReadAll(zr)
}

// overlap refuses an explanation sharing a row with another current one of its gate and run: a row
// belongs to one explanation, so taking it over means superseding the one that has it.
func overlap(current []agentstore.Explanation, e agentstore.Explanation) error {
	rows := map[string]bool{}
	for _, m := range e.Members {
		rows[m.Row] = true
	}
	for _, c := range current {
		if c.Gate != e.Gate || c.Run != e.Run || c.ID == e.ID {
			continue
		}
		for _, m := range c.Members {
			if rows[m.Row] {
				return fmt.Errorf("row %s is already in explanation %s of this gate and run; reuse that id to supersede it", m.Row, c.ID)
			}
		}
	}
	return nil
}

// supersede is current with e recorded: it replaces the explanation with its id, or is added.
func supersede(current []agentstore.Explanation, e agentstore.Explanation) []agentstore.Explanation {
	out := slices.Clone(current)
	for i := range out {
		if out[i].ID == e.ID {
			out[i] = e
			return out
		}
	}
	return append(out, e)
}

type explainListOptions struct {
	textOrJSON `yaml:",inline" mapstructure:",squash"`
	Gate       string `yaml:"gate" json:"gate" mapstructure:"gate"`
	// Name is empty unless given, so ls lists every run's explanations by default
	Name string `yaml:"name" json:"name" mapstructure:"name"`
}

func (o *explainListOptions) AddFlags(flags clio.FlagSet) {
	o.textOrJSON.AddFlags(flags)
	flags.StringVarP(&o.Gate, "gate", "", "only explanations of this gate, by name (env YARDSTICK_GATE)")
	flags.StringVarP(&o.Name, "name", "", "only explanations of this run name (env YARDSTICK_NAME)")
}

func ClaimsExplainList(app clio.Application) *cobra.Command {
	cfg := &explainListOptions{textOrJSON: newTextOrJSON()}
	return app.SetupCommand(&cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the current explanations (the newest line per id)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cfg.check(); err != nil {
				return err
			}
			all, err := agentstore.Open(agentstore.Dir).Explanations.Current()
			if err != nil {
				return err
			}
			out := []agentstore.Explanation{}
			for _, e := range all {
				if (cfg.Gate == "" || e.Gate == cfg.Gate) && (cfg.Name == "" || e.Run == cfg.Name) {
					out = append(out, e)
				}
			}
			if cfg.Output == outputJSON {
				return writeJSON(cmd.OutOrStdout(), out)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tGATE\tRUN\tREASON\tMEMBERS\tEVIDENCE\tTITLE")
			for _, e := range out {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d facts, %d log excerpts\t%s\n", e.ID, e.Gate, e.Run, e.Reason, len(e.Members), len(e.Facts), len(e.LogExcerpts), e.Title)
			}
			return tw.Flush()
		},
	}, cfg)
}
