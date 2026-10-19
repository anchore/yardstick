package command

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelwrite"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/score"
)

// researchJobEnv names the research job an agent runs in, set by the label server when it starts
// one, so a proposal can say a person asked for it.
const researchJobEnv = "YARDSTICK_RESEARCH_JOB"

// agentOptions are what the commands recording agent state take: the gate whose last scan row ids
// name, the run it was scanned under, and claims sources after the gate's own.
type agentOptions struct {
	claimsOption `yaml:",inline" mapstructure:",squash"`
	nameOption   `yaml:",inline" mapstructure:",squash"`
	Gate         string `yaml:"gate" json:"gate" mapstructure:"gate"`
}

func (o *agentOptions) AddFlags(flags clio.FlagSet) {
	o.claimsOption.AddFlags(flags)
	o.nameOption.AddFlags(flags)
	flags.StringVarP(&o.Gate, "gate", "", "the gate whose last scan row ids name: a gate file, or the name of a gate scanned under --name (env YARDSTICK_GATE)")
}

// scanned is a gate's last scan under a run name, its rows by id, and the vocabulary calls about it
// are checked against.
type scanned struct {
	run   string
	gate  *gatefile.Gate
	rec   *runrecord.Record
	rows  map[string]*score.Row
	vocab *claimsv1.Vocabulary
}

// gatePath is a gate file as given, else the file of the gate scanned under run by that name.
func gatePath(run, gate string) (string, error) {
	if info, err := os.Stat(gate); err == nil && !info.IsDir() {
		return gate, nil
	}
	rec, err := runrecord.Load(run, gate)
	if err != nil {
		return "", fmt.Errorf("%q is neither a gate file nor a gate scanned under run %s: %w", gate, run, err)
	}
	return rec.Gate.Path, nil
}

// openScanned reads a gate's last scan. gate is a gate file, or the name of a gate scanned under
// run, whose file the run record names.
func openScanned(run, gate string, extra []string) (*scanned, error) {
	if gate == "" {
		return nil, errors.New("no gate: pass --gate <gate file or name>, or set YARDSTICK_GATE")
	}
	if err := runrecord.CheckName(run); err != nil {
		return nil, err
	}
	path, err := gatePath(run, gate)
	if err != nil {
		return nil, err
	}
	gates, err := loadGates([]string{path}, extra, false)
	if err != nil {
		return nil, err
	}
	g := gates[0]
	rec, err := runrecord.Load(run, g.Name)
	if err != nil {
		return nil, fmt.Errorf("gate %s has no scan to read rows from (%w); run %s first", g.Name, err, runrecord.Rerun(run, path))
	}
	set, err := claims.OpenSet(g.Claims)
	if err != nil {
		return nil, fmt.Errorf("gate %s: %w", g.Name, err)
	}
	s := &scanned{run: run, gate: g, rec: rec, vocab: set.Vocabulary()}
	var isAdvisory func(string) bool
	if s.vocab != nil {
		isAdvisory = s.vocab.IsAdvisory
	}
	if s.rows, err = score.Rows(run, rec, isAdvisory); err != nil {
		return nil, fmt.Errorf("gate %s: %w", g.Name, err)
	}
	return s, nil
}

func (s *scanned) row(id string) (*score.Row, error) {
	if r, ok := s.rows[id]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("no row %q in gate %s's last scan under run %s", id, s.gate.Name, s.run)
}

// member fills a member's vulnerability and package from its row, and refuses one naming another
// row's.
func (s *scanned) member(m agentstore.Member) (agentstore.Member, *score.Row, error) {
	r, err := s.row(m.Row)
	if err != nil {
		return m, nil, err
	}
	if m.Vulnerability == "" {
		m.Vulnerability = r.Match.Vulnerability
	}
	if m.Package == "" {
		m.Package = r.Match.Package.PURL
	}
	if m.Vulnerability != r.Match.Vulnerability && !slices.Contains(r.Match.Aliases, m.Vulnerability) {
		return m, nil, fmt.Errorf("row %s is %s, not %s", m.Row, r.Match.Vulnerability, m.Vulnerability)
	}
	if m.Package != r.Match.Package.PURL {
		return m, nil, fmt.Errorf("row %s is on %s, not %s", m.Row, r.Match.Package.PURL, m.Package)
	}
	return m, r, nil
}

// checkGate refuses a record naming a gate other than the one its rows were resolved in.
func (s *scanned) checkGate(gate *string) error {
	if *gate == "" {
		*gate = s.gate.Name
	}
	if *gate != s.gate.Name {
		return fmt.Errorf("it is about gate %s, and its rows were read from gate %s", *gate, s.gate.Name)
	}
	return nil
}

// policy refuses a call with any vocabulary or policy problem, naming them all.
func policy(problems []string) error {
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// subjectOf is the label subject a run's subject is addressed by in the corpus.
func subjectOf(sub *runrecord.Subject) (claimsv1.Subject, error) {
	placed, err := labelwrite.Place(sub, claimsv1.Label{}, false)
	if err != nil {
		return claimsv1.Subject{}, err
	}
	return *placed.Subject, nil
}

func describeSubject(s claimsv1.Subject) string {
	if s.Image != "" {
		return s.Image
	}
	return s.SBOM
}

// fillDefaults fills what an agent may leave out of a record: schema, id, timestamp, the author
// kind (agent), and the research job it runs in.
func fillDefaults(schema, id *string, ts *time.Time, a *agentstore.Author, now time.Time) {
	if *schema == "" {
		*schema = agentstore.Schema
	}
	if *id == "" {
		*id = uuid.NewString()
	}
	if ts.IsZero() {
		*ts = now
	}
	if a.Kind == "" {
		a.Kind = agentstore.Agent
	}
	if a.Kind == agentstore.Agent && a.ResearchJob == "" {
		a.ResearchJob = os.Getenv(researchJobEnv)
	}
}

// openInput is the file argument, else stdin.
func openInput(cmd *cobra.Command, args []string) (io.ReadCloser, error) {
	if len(args) == 1 {
		return os.Open(args[0])
	}
	return io.NopCloser(cmd.InOrStdin()), nil
}

// readJSONL reads JSON lines, refusing unknown fields, so a skill that drifts from the format finds
// out instead of losing data.
func readJSONL[T any](r io.Reader, what string) ([]T, error) {
	var out []T
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for line := 1; scanner.Scan(); line++ {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var v T
		dec := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, v)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %s given", what)
	}
	return out, nil
}

// proposalInput is a proposal that may name its subject, package and vulnerability by row id.
type proposalInput struct {
	agentstore.Proposal
	Row string `json:"row,omitempty"`
}

func ClaimsPropose(app clio.Application) *cobra.Command {
	cfg := &agentOptions{nameOption: newNameOption()}
	return app.SetupCommand(&cobra.Command{
		Use:   "propose [file] --gate <gate>",
		Short: "Record agent calls as proposals for a person to accept (JSON lines on stdin or in a file)",
		Long: `propose reads proposals as JSON lines and records them in .yardstick/proposals.jsonl, where the
label UI shows them as hints. A proposal is never a label and never counts for scoring until a
person accepts it. Nothing is recorded unless every line is valid.

Each line is a label's fields (package, vulnerability, verdict, justification, evidence, note)
plus confidence (high, medium or low), openQuestions and author{name,kind,skill,model}. Unknown
fields are refused. For convenience:
  - "row": a row id from yardstick score -o json stands in for subject, package and vulnerability
  - schema, id, timestamp and gate are filled in, and author.kind defaults to agent
  - author.researchJob is filled from YARDSTICK_RESEARCH_JOB for an agent

A proposal is checked against the claims vocabulary and the labeling policy: a justification or
evidence rule that is not listed, a rule of the other verdict, a confidence above the rule's
ceiling, or a low-confidence tp or fp is refused. A proposal about the same match as an earlier
one supersedes it. Each recorded proposal prints as id, verdict, vulnerability, package and
subject, tab separated.`,
		Example: `  echo '{"row":"12f096fe9f1d02ba","verdict":"fp","justification":"fix-installed","confidence":"high",
    "author":{"skill":"triage-deltas","model":"claude-opus-5-5"}}' | yardstick claims agent propose --gate deb`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in, err := openInput(cmd, args)
			if err != nil {
				return err
			}
			defer in.Close()
			lines, err := readJSONL[proposalInput](in, "proposals")
			if err != nil {
				return err
			}
			s, err := openScanned(cfg.Name, cfg.Gate, cfg.Claims)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			out := make([]agentstore.Proposal, 0, len(lines))
			for i, in := range lines {
				p, err := s.proposal(in, now)
				if err != nil {
					return fmt.Errorf("proposal %d: %w", i+1, err)
				}
				out = append(out, p)
			}
			if err := agentstore.Open(agentstore.Dir).Proposals.Add(out...); err != nil {
				return err
			}
			for _, p := range out {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\n", p.ID, p.Verdict, p.Vulnerability, p.Package, describeSubject(p.Subject))
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "recorded %d proposal(s) in %s\n", len(out), agentstore.Dir)
			return nil
		},
	}, cfg)
}

func (s *scanned) proposal(in proposalInput, now time.Time) (agentstore.Proposal, error) {
	p := in.Proposal
	if in.Row != "" {
		r, err := s.row(in.Row)
		if err != nil {
			return p, err
		}
		if p.Subject == (claimsv1.Subject{}) {
			if p.Subject, err = subjectOf(r.Subject); err != nil {
				return p, err
			}
		}
		if p.Package == "" {
			p.Package = r.Match.Package.PURL
		}
		if p.Vulnerability == "" {
			p.Vulnerability = r.Match.Vulnerability
		}
	}
	if err := s.checkGate(&p.Gate); err != nil {
		return p, err
	}
	fillDefaults(&p.Schema, &p.ID, &p.Timestamp, &p.Author, now)
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, policy(p.Problems(s.vocab))
}

// causeInput is a cause that may list its members by row id.
type causeInput struct {
	agentstore.Cause
	Rows []string `json:"rows,omitempty"`
}

func ClaimsProposeCause(app clio.Application) *cobra.Command {
	cfg := &agentOptions{nameOption: newNameOption()}
	return app.SetupCommand(&cobra.Command{
		Use:   "propose-cause [file] --gate <gate>",
		Short: "Record agent-proposed root causes for sets of a gate's rows (JSON lines on stdin or in a file)",
		Long: `propose-cause reads causes as JSON lines and records them in .yardstick/causes.jsonl, where the
label UI shows them on their source package as package hints. Accepting one writes a label per
member. Nothing is recorded unless every line is valid.

A cause has a title, note, verdict, justification, confidence, evidence, openQuestions, author and
members. Unknown fields are refused. For convenience:
  - "rows": row ids from yardstick score -o json become members; a member may give just its "row",
    and every member's vulnerability and package are checked against its row
  - sourcePackage, direction (added or dropped) and subject are filled in from the rows when
    missing; every row must be in the cause's source package
  - schema, id, timestamp and gate are filled in, and author.kind defaults to agent; a line with
    an existing id supersedes it

A cause that breaks the claims vocabulary or the labeling policy is refused, as a proposal is.
Each recorded cause prints as id, verdict, source package, member count and title, tab separated.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in, err := openInput(cmd, args)
			if err != nil {
				return err
			}
			defer in.Close()
			lines, err := readJSONL[causeInput](in, "causes")
			if err != nil {
				return err
			}
			s, err := openScanned(cfg.Name, cfg.Gate, cfg.Claims)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			out := make([]agentstore.Cause, 0, len(lines))
			for i, in := range lines {
				c, err := s.cause(in, now)
				if err != nil {
					return fmt.Errorf("cause %d: %w", i+1, err)
				}
				out = append(out, c)
			}
			if err := agentstore.Open(agentstore.Dir).Causes.Add(out...); err != nil {
				return err
			}
			for _, c := range out {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%d members\t%s\n", c.ID, c.Verdict, c.SourcePackage, len(c.Members), c.Title)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "recorded %d cause(s) in %s\n", len(out), agentstore.Dir)
			return nil
		},
	}, cfg)
}

// cause resolves a cause's rows into members and fills in what they imply. Every row must be in
// the cause's source package, so a cause cannot quietly cover another package's findings.
func (s *scanned) cause(in causeInput, now time.Time) (agentstore.Cause, error) {
	c := in.Cause
	listed := slices.Clone(c.Members)
	for _, id := range in.Rows {
		listed = append(listed, agentstore.Member{Row: id})
	}
	c.Members = nil
	var subjects []*runrecord.Subject
	for _, m := range listed {
		m, r, err := s.member(m)
		if err != nil {
			return c, err
		}
		src := r.Match.SourcePackage()
		if c.SourcePackage == "" {
			c.SourcePackage = src
		}
		if src != c.SourcePackage {
			return c, fmt.Errorf("row %s is in %s, not %s", m.Row, src, c.SourcePackage)
		}
		if inCand := r.Match.In(pairing.Candidate); c.Direction == "" && inCand != r.Match.In(pairing.Reference) {
			c.Direction = map[bool]string{true: "added", false: "dropped"}[inCand]
		}
		if !slices.Contains(subjects, r.Subject) {
			subjects = append(subjects, r.Subject)
		}
		c.Members = append(c.Members, m)
	}
	// a cause names its subject only when every row is in one
	if c.Subject == nil && len(subjects) == 1 {
		sub, err := subjectOf(subjects[0])
		if err != nil {
			return c, err
		}
		c.Subject = &sub
	}
	if err := s.checkGate(&c.Gate); err != nil {
		return c, err
	}
	fillDefaults(&c.Schema, &c.ID, &c.Timestamp, &c.Author, now)
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, policy(c.Problems(s.vocab))
}
