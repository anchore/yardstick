package command

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

// Config holds the commands over yardstick's configuration: the gate files, and the app config
// (./.yardstick.yaml or ./config/yardstick.yaml) holding the claims sources they share.
func Config(app clio.Application) *cobra.Command {
	cmd := app.SetupCommand(&cobra.Command{
		Use:   "config",
		Short: "Check gate files and the app config without running them",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	})
	cmd.AddCommand(
		ConfigValidate(app),
	)
	return cmd
}
