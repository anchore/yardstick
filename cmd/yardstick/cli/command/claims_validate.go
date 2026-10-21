package command

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

func ClaimsValidate(app clio.Application) *cobra.Command {
	return app.SetupCommand(&cobra.Command{
		Use:   "validate <corpus>",
		Short: "Check a claims corpus the way its CI does",
		Long: `validate checks every file of a corpus: the layout, each label file against the format
schema, labels sorted with one per package and vulnerability, justifications and fact sources
listed in vocabulary.yaml, every vulnerability id in a listed or advisory namespace, and each
SBOM's descriptor against catalog.yaml. It prints every problem with its file and label, and
exits 2 when there is any. Labels whose purl no package of their image's SBOM has, as after an
SBOM rebuild, are listed on stdout and fail nothing.`,
		Example: `  yardstick claims validate claims/`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Infof("validating the claims corpus %s", args[0])
			problems, err := claimsv1.ValidateCorpus(args[0])
			if err != nil {
				return err
			}
			// labels an SBOM rebuild left behind are listed for review, and fail nothing
			unpaired, err := claimsv1.NoLongerPairing(args[0])
			if err != nil {
				return err
			}
			out := newPrinter(cmd.OutOrStdout())
			for _, p := range problems {
				out.row(out.failed(), p.File, out.dim(labelOf(p)), p.Rule)
			}
			for _, p := range unpaired {
				out.row(out.notice(), p.File, out.dim(labelOf(p)), p.Rule)
			}
			if len(problems) == 0 {
				out.row(out.done(), args[0]+" is valid")
			}
			if err := out.flush(); err != nil {
				return err
			}
			if len(problems) > 0 {
				return fmt.Errorf("%s: %d problem(s)", args[0], len(problems))
			}
			return nil
		},
	})
}

func labelOf(p claimsv1.Problem) string {
	if p.Label == "" {
		return ""
	}
	return "label " + p.Label
}
