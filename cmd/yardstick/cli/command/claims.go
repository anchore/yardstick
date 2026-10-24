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
		ClaimsValidate(app),
		ClaimsSchema(app),
		ClaimsImport(app),
		ClaimsExport(app),
		ClaimsList(app),
		ClaimsPull(app),
		ClaimsPolicy(app),
		ClaimsServe(app),
		ClaimsAgent(app),
	)
	return cmd
}

// ClaimsAgent holds what agents record for a person to review (proposals, causes, explanations)
// and the record of where people overrode them.
func ClaimsAgent(app clio.Application) *cobra.Command {
	cmd := app.SetupCommand(&cobra.Command{
		Use:   "agent",
		Short: "Record and review what agents propose: labels, causes and explanations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	})
	cmd.AddCommand(
		ClaimsPropose(app),
		ClaimsProposeCause(app),
		ClaimsExplain(app),
		ClaimsOverrides(app),
	)
	return cmd
}
