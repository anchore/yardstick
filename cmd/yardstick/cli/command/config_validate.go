package command

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

func ConfigValidate(app clio.Application) *cobra.Command {
	cfg := &claimsOption{}

	return app.SetupCommand(&cobra.Command{
		Use:   "validate <gate.yaml>...",
		Short: "Check gate files without scanning: no syft, no grype, no fetch of a published snapshot",
		Long: `validate loads the app config (./.yardstick.yaml or ./config/yardstick.yaml), when there is
one, and each gate file, and applies every rule a run would apply before scanning. It
runs no tool and fetches nothing: a published claims source is checked for its form only. It
checks every file rather than stopping at the first error, and exits 0 when all are valid and 2
when any is not.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Debugf("options: claims=%v", cfg.Claims)
			log.Infof("validating %d gate files", len(args))
			gates, err := loadGates(args, cfg.Claims, false)
			if err != nil {
				return err
			}
			for i, g := range gates {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: valid, gate %s\n", args[i], g.Name)
			}
			return nil
		},
	}, cfg)
}
