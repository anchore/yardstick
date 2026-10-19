package command

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
)

func ClaimsPull(app clio.Application) *cobra.Command {
	return app.SetupCommand(&cobra.Command{
		Use:   "pull [<owner/repo reference>...]",
		Short: "Download and verify published claims snapshots into the cache",
		Long: `pull resolves each published claims source to its snapshot, downloads it into the cache when it is
not there and checks its digest, the same as any command that reads the source would on first
use. With no arguments it pulls the app config's remote sources; local directories are skipped.
Snapshots are read from YARDSTICK_CLAIMS_URL, or ` + claims.DefaultURL + ` when it is unset.`,
		Example: `  yardstick claims pull
  yardstick claims pull github.com/anchore/match-claims@main
  yardstick claims pull github.com/anchore/match-claims@sha256:<hex>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// arguments replace the app config's sources rather than adding to them
			var app *gatefile.AppConfig
			if len(args) == 0 {
				var err error
				if app, err = gatefile.LoadAppConfig("."); err != nil {
					return err
				}
			}
			sources, err := gatefile.Sources(app, args)
			if err != nil {
				return err
			}
			pulled := 0
			for _, gs := range sources {
				if gs.Remote == nil {
					continue
				}
				s, err := claims.Open(gs)
				if err != nil {
					return err
				}
				pulled++
				if s.Commit != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "%s at %s (commit %s)\n", s.Locator, s.Digest, s.Commit)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "%s at %s\n", s.Locator, s.Digest)
				}
			}
			if pulled == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no published claims sources to pull")
			}
			return nil
		},
	})
}
