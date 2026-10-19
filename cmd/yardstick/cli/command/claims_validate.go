package command

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

func ClaimsValidate(app clio.Application) *cobra.Command {
	return app.SetupCommand(&cobra.Command{
		Use:   "validate <corpus>",
		Short: "Check a claims corpus the way its CI does",
		Long: `validate checks every file of a corpus: the layout, each label file against the format
schema, labels sorted with one per package and vulnerability, justifications and fact sources
listed in vocabulary.yaml, no advisory-only vulnerability ids and no unknown namespaces, and each
SBOM's descriptor against catalog.yaml. It prints every problem with its file and label, and
exits 2 when there is any. Labels whose purl no package of their image's SBOM has, as after an
SBOM rebuild, are listed on stdout and fail nothing.`,
		Example: `  yardstick claims validate claims/`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Infof("validating the claims corpus %s", args[0])
			problems, err := labels.ValidateCorpus(args[0])
			if err != nil {
				return err
			}
			for _, p := range problems {
				fmt.Fprintln(cmd.ErrOrStderr(), p)
			}
			// labels an SBOM rebuild left behind are listed for review, and fail nothing
			unpaired, err := labels.NoLongerPairing(args[0])
			if err != nil {
				return err
			}
			for _, p := range unpaired {
				fmt.Fprintln(cmd.OutOrStdout(), p)
			}
			if len(problems) > 0 {
				return fmt.Errorf("%s: %d problem(s)", args[0], len(problems))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: valid\n", args[0])
			return nil
		},
	})
}
