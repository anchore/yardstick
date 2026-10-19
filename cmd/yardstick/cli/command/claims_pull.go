package command

import (
	"errors"

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
			out := newPrinter(cmd.OutOrStdout())
			pulled := 0
			for _, gs := range sources {
				if gs.Remote == nil {
					continue
				}
				s, err := claims.Open(gs)
				if err != nil {
					out.row(out.failed(), gs.Locator)
					return errors.Join(err, out.flush())
				}
				pulled++
				commit := ""
				if s.Commit != "" {
					commit = "commit " + s.Commit
				}
				out.row(out.done(), s.Locator, out.dim(s.Digest), out.dim(commit))
			}
			if pulled == 0 {
				out.row(out.skipped(), out.dim("no published claims sources to pull"))
			}
			return out.flush()
		},
	})
}
