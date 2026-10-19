package command

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
)

// textOrJSON is -o for the commands that print a list: a table, or json.
type textOrJSON struct {
	Output string `yaml:"output" json:"output" mapstructure:"output"`
}

func newTextOrJSON() textOrJSON { return textOrJSON{Output: outputText} }

func (o *textOrJSON) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Output, "output", "o", "format to display results (available=[text, json])")
}

func (o *textOrJSON) check() error {
	if o.Output != outputText && o.Output != outputJSON {
		return fmt.Errorf("unknown output %q: use one of text, json", o.Output)
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// openClaims opens the claims sources a command that reads no gate uses: the app config's, then
// --claims.
func openClaims(extra []string) (*claims.Set, error) {
	app, err := gatefile.LoadAppConfig(".")
	if err != nil {
		return nil, err
	}
	sources, err := gatefile.Sources(app, extra)
	if err != nil {
		return nil, err
	}
	return claims.OpenSet(sources)
}

type claimsListOptions struct {
	claimsOption  `yaml:",inline" mapstructure:",squash"`
	textOrJSON    `yaml:",inline" mapstructure:",squash"`
	Subject       string `yaml:"subject" json:"subject" mapstructure:"subject"`
	Vulnerability string `yaml:"vulnerability" json:"vulnerability" mapstructure:"vulnerability"`
}

func (o *claimsListOptions) AddFlags(flags clio.FlagSet) {
	o.claimsOption.AddFlags(flags)
	o.textOrJSON.AddFlags(flags)
	flags.StringVarP(&o.Subject, "subject", "s", "only labels about this: an image reference prefix, an SBOM digest, a package purl prefix (pkg:...) or a package name")
	flags.StringVarP(&o.Vulnerability, "vulnerability", "V", "only labels about this vulnerability id")
}

// listedLabel is one label in a claims source, with where it is.
type listedLabel struct {
	Source  string          `json:"source"`
	File    string          `json:"file"`
	Subject *labels.Subject `json:"subject,omitempty"` // nil for a global label
	Label   labels.Label    `json:"label"`
}

func ClaimsList(app clio.Application) *cobra.Command {
	cfg := &claimsListOptions{textOrJSON: newTextOrJSON()}
	return app.SetupCommand(&cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List the labels in the claims sources",
		Long: `ls lists every label in the app config's claims sources and --claims, in source order, each with
its source, file and subject. Each source's labels are listed as written: when two sources
disagree both show, and scoring reads that match as unlabeled. A label's history is the claims
repository's git history.`,
		Example: `  yardstick claims ls -s pkg:deb/debian/tar -o json
  yardstick claims ls -V CVE-2005-2541`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cfg.check(); err != nil {
				return err
			}
			set, err := openClaims(cfg.Claims)
			if err != nil {
				return err
			}
			out := []listedLabel{}
			for _, src := range set.Sources {
				found, err := sourceLabels(src)
				if err != nil {
					return err
				}
				for _, l := range found {
					if cfg.keeps(l) {
						out = append(out, l)
					}
				}
			}
			if cfg.Output == outputJSON {
				return writeJSON(cmd.OutOrStdout(), out)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "VERDICT\tJUSTIFICATION\tVULNERABILITY\tPACKAGE\tSUBJECT\tAUTHOR\tUPDATED")
			for _, l := range out {
				sub := "(global)"
				if l.Subject != nil {
					sub = describeSubject(*l.Subject)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", l.Label.Verdict, l.Label.Justification, l.Label.Vulnerability, l.Label.Package, sub, l.Label.Author, l.Label.LastUpdated)
			}
			return tw.Flush()
		},
	}, cfg)
}

// sourceLabels is every label in one claims source, in path order.
func sourceLabels(src *claims.Source) ([]listedLabel, error) {
	var out []listedLabel
	err := fs.WalkDir(src.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if loc, ok := labels.Locate(p); !ok || !loc.IsLabelFile() {
			return nil
		}
		data, err := fs.ReadFile(src.FS, p)
		if err != nil {
			return err
		}
		f, err := labels.Parse(p, data)
		if err != nil {
			return fmt.Errorf("claims source %s: %w", src.Locator, err)
		}
		for _, l := range f.Labels {
			out = append(out, listedLabel{Source: src.Locator, File: p, Subject: f.Subject, Label: l})
		}
		return nil
	})
	return out, err
}

func (o *claimsListOptions) keeps(l listedLabel) bool {
	if o.Vulnerability != "" && l.Label.Vulnerability != o.Vulnerability {
		return false
	}
	if s := o.Subject; s != "" {
		pkg := l.Label.Package
		onPackage := pkg != "" && ((strings.HasPrefix(s, "pkg:") && strings.HasPrefix(pkg, s)) || purl.Package(pkg, "").Name == s)
		onSubject := l.Subject != nil && ((l.Subject.Image != "" && strings.HasPrefix(l.Subject.Image, s)) || l.Subject.SBOM == s)
		return onPackage || onSubject
	}
	return true
}

// override is a person's label rejecting an agent's proposal, with the proposal (the hint) it
// rejected; delta's claim overrides shape, less the claim id a label does not have.
type override struct {
	HintID        string               `json:"hintId"`
	Gate          string               `json:"gate"`
	Subject       labels.Subject       `json:"subject"`
	Package       string               `json:"package,omitempty"`
	Vulnerability string               `json:"vulnerability"`
	Verdict       labels.Verdict       `json:"verdict"` // the person's
	Justification string               `json:"justification,omitempty"`
	Reason        *agentstore.Reason   `json:"reason,omitempty"`
	Note          string               `json:"note,omitempty"`
	Author        string               `json:"author"`
	Timestamp     time.Time            `json:"timestamp"`
	Hint          *agentstore.Proposal `json:"hint,omitempty"` // nil when it is no longer recorded
}

// overrideGroup is the overrides of the hints one rule produced.
type overrideGroup struct {
	Rule      string     `json:"rule"` // the hints' first evidence rule; "" for hints without one
	Count     int        `json:"count"`
	Overrides []override `json:"overrides"`
}

func ClaimsOverrides(app clio.Application) *cobra.Command {
	cfg := &textOrJSON{Output: outputText}
	return app.SetupCommand(&cobra.Command{
		Use:   "overrides",
		Short: "List where people overrode agent proposals, grouped by the proposal's rule, with their reasons",
		Long: `overrides lists the override records in .yardstick/overrides.jsonl: labels a person wrote that
reject an agent's proposal or cause. They are grouped by the rule the proposal cited, most
overridden first, with the person's reason when they gave one. Use it to find triage rules, fact
sources and labeling-policy decisions that need fixing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cfg.check(); err != nil {
				return err
			}
			groups, err := readOverrides(agentstore.Open(agentstore.Dir))
			if err != nil {
				return err
			}
			if cfg.Output == outputJSON {
				return writeJSON(cmd.OutOrStdout(), groups)
			}
			return writeOverrides(cmd.OutOrStdout(), groups)
		},
	}, cfg)
}

// readOverrides groups the current override records by their hint's rule, most overridden rule
// first.
func readOverrides(store *agentstore.Store) ([]overrideGroup, error) {
	records, err := store.Overrides.Current()
	if err != nil {
		return nil, err
	}
	proposals, err := store.Proposals.Current()
	if err != nil {
		return nil, err
	}
	causes, err := store.Causes.Current()
	if err != nil {
		return nil, err
	}
	hints := map[string]agentstore.Proposal{}
	for _, p := range proposals {
		hints[p.ID] = p
	}
	byID := map[string]agentstore.Cause{}
	for _, c := range causes {
		byID[c.ID] = c
	}
	groups := map[string]*overrideGroup{}
	for _, r := range records {
		o := override{HintID: r.Proposal, Gate: r.Gate, Subject: r.Subject, Package: r.Package, Vulnerability: r.Vulnerability, Verdict: r.Verdict,
			Justification: r.Justification, Reason: r.Reason, Note: r.Note, Author: r.Author, Timestamp: r.Timestamp}
		if p, ok := hints[r.Proposal]; ok {
			o.Hint = &p
		} else if c, ok := byID[r.Proposal]; ok {
			// a cause is overridden one member at a time: the hint is the cause's call on that member
			o.Hint = &agentstore.Proposal{Schema: c.Schema, ID: c.ID, Gate: c.Gate, Subject: r.Subject, Package: r.Package, Vulnerability: r.Vulnerability,
				Verdict: c.Verdict, Justification: c.Justification, Confidence: c.Confidence, Evidence: c.Evidence, Note: c.Note,
				OpenQuestions: c.OpenQuestions, Author: c.Author, Timestamp: c.Timestamp}
		}
		rule := ""
		if o.Hint != nil {
			for _, e := range o.Hint.Evidence {
				if e.Rule != "" {
					rule = e.Rule
					break
				}
			}
		}
		g := groups[rule]
		if g == nil {
			g = &overrideGroup{Rule: rule}
			groups[rule] = g
		}
		g.Overrides = append(g.Overrides, o)
		g.Count++
	}
	out := make([]overrideGroup, 0, len(groups))
	for _, g := range groups {
		slices.SortFunc(g.Overrides, func(a, b override) int {
			return cmp.Or(cmp.Compare(a.Vulnerability, b.Vulnerability), cmp.Compare(a.Package, b.Package))
		})
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b overrideGroup) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Rule, b.Rule))
	})
	return out, nil
}

// writeOverrides prints each rule with its count, then one line per override: vulnerability,
// package, the hint's verdict and confidence, the person's verdict, and the reason.
func writeOverrides(w io.Writer, groups []overrideGroup) error {
	if len(groups) == 0 {
		_, err := fmt.Fprintln(w, "no overridden proposals")
		return err
	}
	for _, g := range groups {
		rule := g.Rule
		if rule == "" {
			rule = "(no rule, or the proposal is gone)"
		}
		fmt.Fprintf(w, "%s  %d override(s)\n", rule, g.Count)
		for _, o := range g.Overrides {
			hint := "proposal " + o.HintID + " (no longer recorded)"
			if o.Hint != nil {
				hint = strings.TrimSpace(fmt.Sprintf("agent %s %s", o.Hint.Verdict, o.Hint.Confidence))
			}
			reason := "no reason given"
			if r := o.Reason; r != nil {
				reason = r.Kind
				if r.Text != "" {
					reason += ": " + r.Text
				}
			}
			fmt.Fprintf(w, "  %s  %s  %s -> %s  %s\n", o.Vulnerability, o.Package, hint, o.Verdict, reason)
		}
	}
	return nil
}

// policyView is the labeling policy as the claims vocabulary holds it, for the skills to read
// rather than parse markdown.
type policyView struct {
	Justifications map[labels.Verdict]map[string]string `json:"justifications"`
	Rules          map[string]labels.Rule               `json:"rules"`
	FactSources    []string                             `json:"factSources"`
	AdvisoryIDs    []string                             `json:"advisoryIds"`
	Namespaces     []string                             `json:"vulnerabilityNamespaces"`
}

type claimsPolicyOptions struct {
	claimsOption `yaml:",inline" mapstructure:",squash"`
	textOrJSON   `yaml:",inline" mapstructure:",squash"`
}

func (o *claimsPolicyOptions) AddFlags(flags clio.FlagSet) {
	o.claimsOption.AddFlags(flags)
	o.textOrJSON.AddFlags(flags)
}

func ClaimsPolicy(app clio.Application) *cobra.Command {
	cfg := &claimsPolicyOptions{textOrJSON: newTextOrJSON()}
	return app.SetupCommand(&cobra.Command{
		Use:   "policy",
		Short: "Show the labeling policy's rules and justifications from the claims vocabulary",
		Long: `policy prints the vocabulary.yaml of the first claims source that has one (the app config's, then
--claims): each rule's verdict, justification, confidence ceiling, decision, basis and title, the
justifications allowed under each verdict, the fact sources, and the vulnerability namespaces.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cfg.check(); err != nil {
				return err
			}
			set, err := openClaims(cfg.Claims)
			if err != nil {
				return err
			}
			v := set.Vocabulary()
			if v == nil {
				return fmt.Errorf("no claims source has a %s", labels.VocabularyFile)
			}
			if cfg.Output == outputJSON {
				return writeJSON(cmd.OutOrStdout(), policyView{Justifications: v.Justifications, Rules: v.Rules, FactSources: v.FactSources, AdvisoryIDs: v.AdvisoryIDs, Namespaces: v.Namespaces})
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "RULE\tVERDICT\tJUSTIFICATION\tCEILING\tDECISION\tTITLE")
			for _, name := range slices.Sorted(maps.Keys(v.Rules)) {
				r := v.Rules[name]
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", name, r.Verdict, r.Justification, r.Ceiling, r.Decision, r.Title)
			}
			fmt.Fprintln(tw)
			fmt.Fprintln(tw, "VERDICT\tJUSTIFICATION\tDESCRIPTION")
			for _, verdict := range labels.Verdicts {
				for _, j := range v.Allowed(verdict) {
					fmt.Fprintf(tw, "%s\t%s\t%s\n", verdict, j, v.Justifications[verdict][j])
				}
			}
			return tw.Flush()
		},
	}, cfg)
}
