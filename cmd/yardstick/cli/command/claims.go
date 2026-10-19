package command

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func Claims(app clio.Application) *cobra.Command {
	cmd := app.SetupCommand(&cobra.Command{
		Use:   "claims",
		Short: "Write, move and check labels in a claims corpus",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	})
	cmd.AddCommand(
		ClaimsAdd(app),
		ClaimsPromote(app),
		ClaimsValidate(app),
		ClaimsImport(app),
		ClaimsExport(app),
		ClaimsPropose(app),
		ClaimsProposeCause(app),
		ClaimsExplain(app),
		ClaimsList(app),
		ClaimsOverrides(app),
		ClaimsPolicy(app),
		ClaimsServe(app),
	)
	return cmd
}
