package command

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

type claimsPromoteConfig struct {
	To string `yaml:"to" json:"to" mapstructure:"to"`
}

func (c *claimsPromoteConfig) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&c.To, "to", "", "the corpus checkout to write the labels into")
}

func ClaimsPromote(app clio.Application) *cobra.Command {
	cfg := &claimsPromoteConfig{}
	return app.SetupCommand(&cobra.Command{
		Use:   "promote <claims dir> --to <corpus checkout>",
		Short: "Write a local claims directory's labels into a corpus checkout, ready for a pull request",
		Long: `promote writes every label in a local claims directory into a corpus checkout through the
label writer, replacing a label with the same key, and copies in the SBOM each label's seenIn
names when the checkout holds none for that subject. It writes nothing when any label is
refused or any such SBOM is in neither the directory nor the cache. It does not commit or push:
review the diff and open the pull request yourself.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.To == "" {
				return errors.New("promote needs --to <corpus checkout>")
			}
			log.Debugf("options: to=%s", cfg.To)
			log.Infof("promoting %s into %s", args[0], cfg.To)
			out, err := claims.Promote(args[0], cfg.To)
			if err != nil {
				return err
			}
			p := newPrinter(cmd.OutOrStdout())
			p.row(p.done(), fmt.Sprintf("promoted %d labels", out.Labels), p.dim("into "+cfg.To))
			for _, s := range out.SBOMs {
				p.row(p.done(), "copied SBOM", p.dim(s))
			}
			return p.flush()
		},
	}, cfg)
}
