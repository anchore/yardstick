package command

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
)

// override is a person's label rejecting an agent's proposal, with the proposal (the hint) it
// rejected; delta's claim overrides shape, less the claim id a label does not have.
type override struct {
	HintID        string               `json:"hintId"`
	Gate          string               `json:"gate"`
	Subject       claimsv1.Subject     `json:"subject"`
	Package       string               `json:"package,omitempty"`
	Vulnerability string               `json:"vulnerability"`
	Verdict       claimsv1.Verdict     `json:"verdict"` // the person's
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
