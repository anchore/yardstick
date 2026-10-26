package command

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

// Collect holds the two steps of a gate run before scoring, each run alone: building SBOMs and
// scanning them.
func Collect(app clio.Application) *cobra.Command {
	cmd := app.SetupCommand(&cobra.Command{
		Use:   "collect",
		Short: "Build SBOMs and run scans without scoring them",
		// no alias for the old collect <oci-subject>: an argument here is an unknown command
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	})
	cmd.AddCommand(
		CollectSBOMs(app),
		CollectScans(app),
	)
	return cmd
}
