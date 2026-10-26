package command

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
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
			path, wrote, err := corpus.WriteSchema(args[0])
			if err != nil {
				return err
			}
			out := newPrinter(cmd.OutOrStdout())
			if wrote {
				out.row(out.done(), "wrote "+path)
			} else {
				out.row(out.skipped(), out.dim(path+" is unchanged"))
			}
			return out.flush()
		},
	})
}
