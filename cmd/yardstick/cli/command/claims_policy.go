package command

import (
	"fmt"
	"maps"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
)

// policyView is the labeling policy as the claims vocabulary holds it, for the skills to read
// rather than parse markdown.
type policyView struct {
	Justifications map[claimsv1.Verdict]map[string]string `json:"justifications"`
	Rules          map[string]claimsv1.Rule               `json:"rules"`
	FactSources    []string                               `json:"factSources"`
	AdvisoryIDs    []string                               `json:"advisoryIds"`
	Namespaces     []string                               `json:"vulnerabilityNamespaces"`
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
		Long: `policy prints the vocabulary.yaml of every claims source that has one (the app config's, then
--claims), merged: each rule's verdict, justification, confidence ceiling, decision, basis and title, the
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
				return fmt.Errorf("no claims source has a %s", claimsv1.VocabularyFile)
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
			for _, verdict := range claimsv1.Verdicts() {
				for _, j := range v.Allowed(verdict) {
					fmt.Fprintf(tw, "%s\t%s\t%s\n", verdict, j, v.Justifications[verdict][j])
				}
			}
			return tw.Flush()
		},
	}, cfg)
}
