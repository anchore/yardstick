package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/score"
)

// researchJob is the research job a command runs in, as the label server sets it in the job's
// environment (research.JobEnv and the rest), so a proposal can say a person asked for it and is
// held to the job's rows and gate. These are env only on purpose and must never get a flag: the
// agent runs propose with whatever arguments it likes, so a flag would let it choose its own job.
// Fields with no flag are read from YARDSTICK_<key> alone, as no config file is read either.
type researchJob struct {
	ID   string `yaml:"-" json:"-" mapstructure:"research-job"`     // YARDSTICK_RESEARCH_JOB
	Dir  string `yaml:"-" json:"-" mapstructure:"research-job-dir"` // YARDSTICK_RESEARCH_JOB_DIR
	Gate string `yaml:"-" json:"-" mapstructure:"research-gate"`    // YARDSTICK_RESEARCH_GATE
	Rows string `yaml:"-" json:"-" mapstructure:"rows"`             // YARDSTICK_ROWS, space separated
}

// holds refuses a proposal in a research job about anything but one of the job's rows, in the
// job's gate.
func (j researchJob) holds(gate, row string) error {
	switch {
	case gate != j.Gate:
		return fmt.Errorf("research job %s is about gate %s, not %s: leave --gate off", j.ID, j.Gate, gate)
	case row == "":
		return fmt.Errorf("a proposal in research job %s names its row, one of %s", j.ID, j.Rows)
	case !slices.Contains(strings.Fields(j.Rows), row):
		return fmt.Errorf("row %s is not one of research job %s's rows (%s)", row, j.ID, j.Rows)
	}
	return nil
}

// noteRefusal has a propose command run in a research job leave its refusal in the job's directory
// (research.ProposeErrorFile), so the job can say why it recorded nothing without reading the
// agent's log; a later success there clears it.
func noteRefusal(job *researchJob, c *cobra.Command) *cobra.Command {
	run := c.RunE
	c.RunE = func(cmd *cobra.Command, args []string) error {
		err := run(cmd, args)
		dir := job.Dir
		// only ever a job's own directory, as the label server sets it: the variable can't point
		// the write (or the removal) at another file
		if dir == "" || filepath.Base(filepath.Dir(dir)) != "jobs" || filepath.Base(filepath.Dir(filepath.Dir(dir))) != ".yardstick" {
			return err
		}
		p := filepath.Join(dir, research.ProposeErrorFile)
		if err == nil {
			_ = os.Remove(p)
		} else if werr := os.WriteFile(p, []byte(err.Error()+"\n"), 0o600); werr != nil {
			log.Warnf("unable to record the refusal in %s: %v", p, werr)
		}
		return err
	}
	return c
}

// agentOptions are what the commands recording agent state take: the gate whose last scan row ids
// name, the run it was scanned under, claims sources after the gate's own, and the research job
// they run in.
type agentOptions struct {
	claimsOption `yaml:",inline" mapstructure:",squash"`
	nameOption   `yaml:",inline" mapstructure:",squash"`
	Gate         string `yaml:"gate" json:"gate" mapstructure:"gate"`

	// env only, never a flag: see researchJob
	Research researchJob `yaml:"-" json:"-" mapstructure:",squash"`
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
	// vocabFile is the vocabulary.yaml an unlisted namespace would be added in: the writable claims
	// source's, else empty
	vocabFile string
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
	s := &scanned{run: run, gate: g, rec: rec, vocab: set.Vocabulary(), vocabFile: set.VocabularyPath()}
	var isAdvisory func(string) bool
	if s.vocab != nil {
		isAdvisory = s.vocab.IsAdvisory
	}
	if s.rows, err = score.Rows(run, rec, isAdvisory); err != nil {
		return nil, fmt.Errorf("gate %s: %w", g.Name, err)
	}
	return s, nil
}

// related is each id the scan reported, with the ids reported beside it.
func (s *scanned) related() map[string][]string {
	ms := make([]*pairing.Match, 0, len(s.rows))
	for _, r := range s.rows {
		ms = append(ms, r.Match)
	}
	return pairing.RelatedIDs(ms)
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

func describeSubject(s claimsv1.Subject) string {
	if s.Image != "" {
		return s.Image
	}
	return s.SBOM
}

// fillDefaults fills what an agent may leave out of a record: schema, id, timestamp and the author
// kind (agent); and stamps the research job it runs in, replacing any the record names. In a job
// the timestamp and kind are always now and agent, whatever the record says.
func fillDefaults(schema, id *string, ts *time.Time, a *agentstore.Author, job string, now time.Time) {
	if *schema == "" {
		*schema = agentstore.Schema
	}
	if *id == "" {
		*id = uuid.NewString()
	}
	// a job counts as recorded by a call stamped with it since the job started, so a call dated
	// ahead would mark every later run of the job recorded, and one dated back none
	if ts.IsZero() || job != "" {
		*ts = now
	}
	if a.Kind == "" || job != "" {
		a.Kind = agentstore.Agent
	}
	// the job is the one propose runs in, never what the record says: a job counts as having
	// recorded a call by this stamp, so a record naming another job would mark that one recorded
	a.ResearchJob = job
}

// openInput is the file arguments one after another, else stdin.
func openInput(cmd *cobra.Command, args []string) (io.ReadCloser, error) {
	if len(args) == 0 {
		return io.NopCloser(cmd.InOrStdin()), nil
	}
	var files []io.Reader
	var closers multiCloser
	for _, a := range args {
		f, err := os.Open(a)
		if err != nil {
			_ = closers.Close()
			return nil, err
		}
		files, closers = append(files, f), append(closers, f)
	}
	return struct {
		io.Reader
		io.Closer
	}{io.MultiReader(files...), closers}, nil
}

type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var errs []error
	for _, c := range m {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// readJSONL reads JSON values, one a line as the skills pipe them or pretty-printed as a skill
// writes a file, refusing unknown fields, so a skill that drifts from the format finds out instead
// of losing data.
func readJSONL[T any](r io.Reader, what string) ([]T, error) {
	var out []T
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	for i := 1; ; i++ {
		var v T
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s %d: %w", strings.TrimSuffix(what, "s"), i, err)
		}
		out = append(out, v)
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
	return noteRefusal(&cfg.Research, app.SetupCommand(&cobra.Command{
		Use:   "propose [file...] --gate <gate>",
		Short: "Record agent calls as proposals for a person to accept (JSON on stdin or in files)",
		Long: `propose reads proposals as JSON, one a line or one a file, and records them in .yardstick/proposals.jsonl, where the
label UI shows them as hints. A proposal is never a label and never counts for scoring until a
person accepts it. Nothing is recorded unless every line is valid.

Each line is a label's fields (package, vulnerability, verdict, justification, evidence, note)
plus confidence (high or medium, and none on an unclear), openQuestions and author{name,kind,skill,model}. Unknown
fields are refused. For convenience:
  - "row": a row id from yardstick score -o json stands in for subject, package and vulnerability
  - schema, id, timestamp and gate are filled in, and author.kind defaults to agent
  - in a research job (YARDSTICK_RESEARCH_JOB, set by yardstick claims serve), author.researchJob
    is that job, timestamp is now and author.kind is agent, whatever the line says; every line
    gives a "row" of the job's (YARDSTICK_ROWS) in the job's gate, and subject is the row's

A proposal is checked against the claims vocabulary and the labeling policy: a justification or
evidence rule that is not listed, a rule of the other verdict, a confidence above the rule's
ceiling, a low-confidence tp or fp, or an unclear with any confidence is refused. A proposal about the same match as an earlier
one supersedes it. Each recorded proposal prints as id, verdict, vulnerability, package and
subject, tab separated.`,
		Example: `  echo '{"row":"12f096fe9f1d02ba","verdict":"fp","justification":"fix-installed","confidence":"high",
    "author":{"skill":"triage-deltas","model":"claude-opus-5-5"}}' | yardstick claims agent propose --gate deb`,
		Args: cobra.ArbitraryArgs,
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
				p, err := s.proposal(in, cfg.Research, now)
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
	}, cfg))
}

func (s *scanned) proposal(in proposalInput, job researchJob, now time.Time) (agentstore.Proposal, error) {
	p := in.Proposal
	if job.ID != "" {
		if err := job.holds(s.gate.Name, in.Row); err != nil {
			return p, err
		}
	}
	if in.Row != "" {
		// a package or vulnerability given beside the row must be the row's, as a cause member's is:
		// a hint pairs its row by the exact purl, so a near miss would never show
		m, r, err := s.member(agentstore.Member{Row: in.Row, Package: p.Package, Vulnerability: p.Vulnerability})
		if err != nil {
			return p, err
		}
		p.Package, p.Vulnerability = m.Package, m.Vulnerability
		// in a research job the subject is always the row's: a proposal supersedes another by
		// subject, package and vulnerability, so another subject's would replace a hint off the job
		if p.Subject == (claimsv1.Subject{}) || job.ID != "" {
			sub, err := labelwrite.SubjectOf(r.Subject)
			if err != nil {
				return p, err
			}
			if p.Subject != (claimsv1.Subject{}) && p.Subject != sub {
				return p, fmt.Errorf("row %s is in %s, not %s: leave subject off", in.Row, describeSubject(sub), describeSubject(p.Subject))
			}
			p.Subject = sub
		}
	}
	if err := s.checkGate(&p.Gate); err != nil {
		return p, err
	}
	fillDefaults(&p.Schema, &p.ID, &p.Timestamp, &p.Author, job.ID, now)
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, policy(p.ProblemsIn(s.vocab, s.vocabFile, s.related()))
}

// causeInput is a cause that may list its members by row id.
type causeInput struct {
	agentstore.Cause
	Rows []string `json:"rows,omitempty"`
}

func ClaimsProposeCause(app clio.Application) *cobra.Command {
	cfg := &agentOptions{nameOption: newNameOption()}
	return noteRefusal(&cfg.Research, app.SetupCommand(&cobra.Command{
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
				c, err := s.cause(in, cfg.Research.ID, now)
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
	}, cfg))
}

// cause resolves a cause's rows into members and fills in what they imply. Every row must be in
// the cause's source package, so a cause cannot quietly cover another package's findings.
func (s *scanned) cause(in causeInput, job string, now time.Time) (agentstore.Cause, error) {
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
		if inCand := r.Match.In(gatefile.Candidate); c.Direction == "" && inCand != r.Match.In(gatefile.Reference) {
			c.Direction = map[bool]string{true: "added", false: "dropped"}[inCand]
		}
		if !slices.Contains(subjects, r.Subject) {
			subjects = append(subjects, r.Subject)
		}
		c.Members = append(c.Members, m)
	}
	// a cause names its subject only when every row is in one
	if c.Subject == nil && len(subjects) == 1 {
		sub, err := labelwrite.SubjectOf(subjects[0])
		if err != nil {
			return c, err
		}
		c.Subject = &sub
	}
	if err := s.checkGate(&c.Gate); err != nil {
		return c, err
	}
	fillDefaults(&c.Schema, &c.ID, &c.Timestamp, &c.Author, job, now)
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, policy(c.Problems(s.vocab))
}
