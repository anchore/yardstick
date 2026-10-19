package command

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
)

func ClaimsSchema(app clio.Application) *cobra.Command {
	return app.SetupCommand(&cobra.Command{
		Use:   "schema <dir>",
		Short: "Write the label file JSON schema this yardstick enforces",
		Long: `schema writes the JSON schema of the label file format this yardstick reads and writes into
<dir> as schema-<version>.json. An identical file already there is left alone, and a different
one is an error rather than replaced: a published schema is never edited, so a change to it
needs a new format version.`,
		Example: `  yardstick claims schema schema/`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, wrote, err := claimsv1.WriteSchema(args[0])
			if err != nil {
				return err
			}
			if wrote {
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "%s is unchanged\n", path)
			}
			return nil
		},
	})
}
