package agentstore

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
)

// Author is who wrote a record. An agent's names the skill and model, and the research job it
// ran in when there was one.
type Author struct {
	Name        string     `json:"name,omitempty"`
	Kind        AuthorKind `json:"kind"`
	Skill       string     `json:"skill,omitempty"`
	Model       string     `json:"model,omitempty"`
	ResearchJob string     `json:"researchJob,omitempty"`
}

type AuthorKind string

const (
	Human AuthorKind = "human"
	Agent AuthorKind = "agent"
)

// Proposal is an agent's call on one match that no person has vouched for: the label accepting it
// writes, plus how sure the agent is and what would settle it.
type Proposal struct {
	Schema        string              `json:"schema"`
	ID            string              `json:"id"`
	Gate          string              `json:"gate"`
	Subject       claimsv1.Subject    `json:"subject"`
	Package       string              `json:"package,omitempty"`
	Vulnerability string              `json:"vulnerability"`
	Verdict       claimsv1.Verdict    `json:"verdict"`
	Justification string              `json:"justification,omitempty"`
	Confidence    string              `json:"confidence,omitempty"` // high, medium or low
	Evidence      []claimsv1.Evidence `json:"evidence,omitempty"`
	Note          string              `json:"note,omitempty"`
	OpenQuestions []string            `json:"openQuestions,omitempty"` // what would settle an unclear verdict
	Author        Author              `json:"author"`
	Timestamp     time.Time           `json:"timestamp"`
}

// a proposal supersedes an earlier one about the same match, whatever its id
func (p Proposal) key() string {
	return p.Subject.Image + p.Subject.SBOM + "|" + p.Package + "|" + p.Vulnerability
}

func (p Proposal) schema() string { return p.Schema }

// Label is the label accepting the proposal writes, by the person accepting it. The confidence
// stays on the proposal: a label has none.
func (p Proposal) Label(author string, now time.Time) claimsv1.Label {
	ts := now.UTC().Format(time.RFC3339)
	return claimsv1.Label{Package: p.Package, Vulnerability: p.Vulnerability, Verdict: p.Verdict, Justification: p.Justification,
		Author: author, Evidence: p.Evidence, Notes: claimsv1.NotesOf(p.Note, author, ts), FirstIssued: ts, LastUpdated: ts}
}

// Validate checks the proposal's shape. Problems checks it against the vocabulary and the policy.
func (p Proposal) Validate() error {
	switch {
	case p.ID == "":
		return errors.New("proposal is missing an id")
	case p.Gate == "":
		return errors.New("proposal is missing its gate")
	case (p.Subject.Image == "") == (p.Subject.SBOM == ""):
		return errors.New("proposal subject needs an image or an sbom digest")
	}
	return checkCall(p.Label(p.Author.Name, p.Timestamp), p.Author, p.Confidence)
}

// Problems is how the proposal sits with the vocabulary and the labeling policy: everything a
// label would be refused for, and a confidence above its rule's ceiling.
func (p Proposal) Problems(v *claimsv1.Vocabulary) []string {
	var out []string
	if v == nil {
		return problems(v, claimsv1.Label{}, "")
	}
	if err := v.CheckVulnerability(p.Vulnerability); err != nil {
		out = append(out, err.Error())
	}
	return append(out, problems(v, p.Label(p.Author.Name, p.Timestamp), p.Confidence)...)
}

// Cause is one root cause an agent proposes for an explicit list of a gate's rows in one source
// package, such as "ESM-only fixes grype reports as wont-fix" for 46 openssl findings. Accepting it
// writes one label per member; it covers exactly its members, never more.
type Cause struct {
	Schema string `json:"schema"`
	ID     string `json:"id"`
	Gate   string `json:"gate"`
	Title  string `json:"title"` // one line
	Note   string `json:"note,omitempty"`
	// Subject is the subject the rows are in; nil when they span subjects.
	Subject       *claimsv1.Subject   `json:"subject,omitempty"`
	SourcePackage string              `json:"sourcePackage"`
	Direction     string              `json:"direction,omitempty"` // added (candidate only) or dropped (reference only)
	Members       []Member            `json:"members"`
	Verdict       claimsv1.Verdict    `json:"verdict"`
	Justification string              `json:"justification,omitempty"`
	Confidence    string              `json:"confidence,omitempty"`
	Evidence      []claimsv1.Evidence `json:"evidence,omitempty"`
	OpenQuestions []string            `json:"openQuestions,omitempty"`
	Author        Author              `json:"author"`
	Timestamp     time.Time           `json:"timestamp"`
}

// Member is one row a cause or an explanation covers: its row id, and the vulnerability and
// package purl so a reader can tell what it was without the run.
type Member struct {
	Row           string `json:"row"`
	Vulnerability string `json:"vulnerability"`
	Package       string `json:"package"`
}

func (c Cause) key() string    { return c.ID }
func (c Cause) schema() string { return c.Schema }

// Label is the label accepting the cause writes for one member.
func (c Cause) Label(m Member, author string, now time.Time) claimsv1.Label {
	ts := now.UTC().Format(time.RFC3339)
	return claimsv1.Label{Package: m.Package, Vulnerability: m.Vulnerability, Verdict: c.Verdict, Justification: c.Justification,
		Author: author, Evidence: c.Evidence, Notes: claimsv1.NotesOf(c.Note, author, ts), FirstIssued: ts, LastUpdated: ts}
}

func (c Cause) Validate() error {
	switch {
	case c.ID == "":
		return errors.New("cause is missing an id")
	case c.Gate == "":
		return errors.New("cause is missing its gate")
	case c.Title == "":
		return errors.New("cause is missing a title")
	case c.SourcePackage == "":
		return errors.New("cause is missing a sourcePackage")
	case c.Direction != "" && c.Direction != "added" && c.Direction != "dropped":
		return fmt.Errorf(`direction must be "added" or "dropped", got %q`, c.Direction)
	}
	if err := checkMembers(c.Members); err != nil {
		return err
	}
	return checkCall(c.Label(c.Members[0], c.Author.Name, c.Timestamp), c.Author, c.Confidence)
}

// Problems is how the cause sits with the vocabulary and the labeling policy.
func (c Cause) Problems(v *claimsv1.Vocabulary) []string {
	return problems(v, c.Label(Member{}, c.Author.Name, c.Timestamp), c.Confidence)
}

// MaxExcerptText caps one log excerpt's text: an excerpt cites the lines that show the reason, not
// the log.
const MaxExcerptText = 8 * 1024

// Explanation is an agent's account of why some of one run's differences happened, such as "Red
// Hat VEX now marks the whole source package affected" for 40 rows. It is about the difference,
// never about whether a finding is real: no verdict, accepting it writes nothing, and scoring never
// reads it.
type Explanation struct {
	Schema string `json:"schema"`
	ID     string `json:"id"`
	Gate   string `json:"gate"`
	Run    string `json:"run"` // the run name; row ids are about one run of the gate
	Title  string `json:"title"`
	Note   string `json:"note,omitempty"`
	// Reason is the computed why key the explanation refines; empty when it stands alone.
	Reason        string          `json:"reason,omitempty"`
	Members       []Member        `json:"members"`
	Facts         []claimsv1.Fact `json:"facts,omitempty"`
	LogExcerpts   []LogExcerpt    `json:"logExcerpts,omitempty"`
	OpenQuestions []string        `json:"openQuestions,omitempty"`
	Author        Author          `json:"author"`
	Timestamp     time.Time       `json:"timestamp"`
}

// LogExcerpt is lines copied from one side's grype log in the run. SHA256 is the log text's, as the
// run record holds it, so the excerpt can be checked against the run.
type LogExcerpt struct {
	Side   string `json:"side"` // candidate or reference
	File   string `json:"file"` // the log's path relative to the run's gate directory
	Lines  [2]int `json:"lines"`
	Text   string `json:"text"`
	SHA256 string `json:"sha256"`
}

func (e Explanation) key() string    { return e.ID }
func (e Explanation) schema() string { return e.Schema }

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate checks the explanation's shape. Checks against the run (its rows and logs) are the
// caller's, since they need the run.
func (e Explanation) Validate() error {
	switch {
	case e.ID == "":
		return errors.New("explanation is missing an id")
	case e.Gate == "" || e.Run == "":
		return errors.New("explanation is missing its gate and run name")
	case e.Title == "":
		return errors.New("explanation is missing a title")
	}
	if err := checkAuthor(e.Author); err != nil {
		return err
	}
	if err := checkMembers(e.Members); err != nil {
		return err
	}
	for i, f := range e.Facts {
		if f.Source == "" || f.Field == "" || len(f.About) == 0 {
			return fmt.Errorf("facts[%d] needs source, about and field", i)
		}
	}
	for i, x := range e.LogExcerpts {
		switch {
		case x.Side != "candidate" && x.Side != "reference":
			return fmt.Errorf("log excerpt %d: side must be candidate or reference, got %q", i+1, x.Side)
		case x.File == "" || !filepath.IsLocal(x.File):
			return fmt.Errorf("log excerpt %d: file must be a log's path inside the run, got %q", i+1, x.File)
		case x.Lines[0] < 1 || x.Lines[1] < x.Lines[0]:
			return fmt.Errorf("log excerpt %d: lines must be [first, last], 1-based, got %v", i+1, x.Lines)
		case x.Text == "":
			return fmt.Errorf("log excerpt %d: text is empty", i+1)
		case len(x.Text) > MaxExcerptText:
			return fmt.Errorf("log excerpt %d: text is %d bytes, more than the %d an excerpt may quote; cite fewer lines", i+1, len(x.Text), MaxExcerptText)
		case !sha256Hex.MatchString(x.SHA256):
			return fmt.Errorf("log excerpt %d: sha256 must be the log's hex sha256 from the run record, got %q", i+1, x.SHA256)
		}
	}
	return nil
}

// Override records a person's label that rejected an agent's proposal, with why when they said,
// so the rules and the policy behind the proposals can improve. The label stays clean of it.
type Override struct {
	Schema        string           `json:"schema"`
	Proposal      string           `json:"proposal"` // the overridden proposal's (or cause's) id
	Gate          string           `json:"gate"`
	Subject       claimsv1.Subject `json:"subject"`
	Package       string           `json:"package,omitempty"`
	Vulnerability string           `json:"vulnerability"`
	Verdict       claimsv1.Verdict `json:"verdict"` // the person's
	Justification string           `json:"justification,omitempty"`
	Reason        *Reason          `json:"reason,omitempty"`
	Note          string           `json:"note,omitempty"`
	Author        string           `json:"author"`
	Timestamp     time.Time        `json:"timestamp"`
}

// Reason is why a person overrode a proposal: one of ReasonKinds, and free text.
type Reason struct {
	Kind string `json:"kind"`
	Text string `json:"text,omitempty"`
}

// ReasonKinds are the reasons a person can give for overriding a proposal, each pointing at what
// to fix.
var ReasonKinds = []string{
	"stale-fact",      // the agent's fact is stale or wrong: fix the fact source or recheck
	"wrong-rule",      // the rule doesn't fit this case: fix the triage rule
	"missed-evidence", // the agent missed evidence: add a source or a check
	"policy",          // the person disagrees with the labeling policy: revisit the decision
	"other",
}

// an override supersedes an earlier override of the same proposal on the same match
func (o Override) key() string {
	return o.Proposal + "|" + o.Subject.Image + o.Subject.SBOM + "|" + o.Package + "|" + o.Vulnerability
}

func (o Override) schema() string { return o.Schema }

func (o Override) Validate() error {
	switch {
	case o.Proposal == "":
		return errors.New("override is missing the proposal it overrides")
	case o.Vulnerability == "":
		return errors.New("override is missing a vulnerability")
	case !slices.Contains(claimsv1.Verdicts, o.Verdict):
		return fmt.Errorf("verdict must be tp, fp or unclear, got %q", o.Verdict)
	case o.Author == "":
		return errors.New("override is missing its author")
	case o.Reason != nil && !slices.Contains(ReasonKinds, o.Reason.Kind):
		return fmt.Errorf("reason kind must be one of %s, got %q", strings.Join(ReasonKinds, ", "), o.Reason.Kind)
	}
	return nil
}

func checkAuthor(a Author) error {
	if a.Kind != Human && a.Kind != Agent {
		return fmt.Errorf("author kind must be %q or %q, got %q", Human, Agent, a.Kind)
	}
	return nil
}

// checkCall checks a call as the label it would write, and its author and confidence.
func checkCall(l claimsv1.Label, a Author, confidence string) error {
	if err := checkAuthor(a); err != nil {
		return err
	}
	if confidence != "" && confidence != "high" && confidence != "medium" && confidence != "low" {
		return fmt.Errorf("confidence must be high, medium or low, got %q", confidence)
	}
	// a proposal's author is in Author, which may carry no name; the label's is the acceptor's
	l.Author = string(a.Kind)
	for i := range l.Notes {
		l.Notes[i].Author = l.Author
	}
	return claimsv1.CheckRequired(l, nil)
}

func checkMembers(members []Member) error {
	if len(members) == 0 {
		return errors.New("no members")
	}
	seen := map[string]bool{}
	for i, m := range members {
		if m.Row == "" || m.Vulnerability == "" || m.Package == "" {
			return fmt.Errorf("member %d needs a row, a vulnerability and a package purl", i+1)
		}
		if seen[m.Row] {
			return fmt.Errorf("member %d (row %s) is listed twice", i+1, m.Row)
		}
		seen[m.Row] = true
	}
	return nil
}

// problems is a call's vocabulary and policy problems, a low-confidence tp or fp, which the policy
// does not allow (that is an unclear, saying what would settle it), and an unclear with a confidence.
func problems(v *claimsv1.Vocabulary, l claimsv1.Label, confidence string) []string {
	if v == nil {
		return []string{"no " + claimsv1.VocabularyFile + " to check the call against"}
	}
	out := v.Problems(l, confidence)
	switch {
	case confidence == "low" && l.Verdict != claimsv1.Unclear:
		out = append(out, fmt.Sprintf("a low-confidence %s is not allowed; propose unclear and say what would settle it in openQuestions", l.Verdict))
	case confidence != "" && l.Verdict == claimsv1.Unclear:
		out = append(out, "an unclear carries no confidence, since it claims nothing to be sure of; drop it and say what would settle it in openQuestions")
	}
	return out
}

// dropUnclearConfidence clears the confidence an unclear call was recorded with before the policy
// refused one, so a store written then reads as one written now.
func dropUnclearConfidence(v claimsv1.Verdict, confidence *string) {
	if v == claimsv1.Unclear {
		*confidence = ""
	}
}

func (p *Proposal) normalize() { dropUnclearConfidence(p.Verdict, &p.Confidence) }
func (c *Cause) normalize()    { dropUnclearConfidence(c.Verdict, &c.Confidence) }
