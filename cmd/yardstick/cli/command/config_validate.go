package command

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

func ConfigValidate(app clio.Application) *cobra.Command {
	cfg := &claimsOption{}

	return app.SetupCommand(&cobra.Command{
		Use:   "validate <gate.yaml>...",
		Short: "Check gate files without scanning: no syft, no grype, no fetch of a published snapshot",
		Long: `validate loads the app config (./.yardstick.yaml or ./config/yardstick.yaml), when there is
one, and each gate file, and applies every rule a run would apply before scanning. It
runs no tool and fetches nothing: a published claims source is checked for its form only. It
checks every file rather than stopping at the first error, and exits 0 when all are valid and 2
when any is not.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Debugf("options: claims=%v", cfg.Claims)
			log.Infof("validating %d gate files", len(args))
			app, err := gatefile.LoadAppConfig(".")
			if err != nil {
				return err
			}
			// a row per file, its problems under it, rather than loadGates' one joined error
			out := newPrinter(cmd.OutOrStdout())
			var gates []*gatefile.Gate
			for _, p := range args {
				g, err := gatefile.Load(p, gatefile.Options{Checks: analysis.Definitions(), App: app, Claims: cfg.Claims})
				if err == nil {
					gates = append(gates, g)
					out.row(out.done(), p, "gate "+out.bold(g.Name))
					continue
				}
				problems := strings.Split(err.Error(), "\n")
				if le := (*gatefile.LoadError)(nil); errors.As(err, &le) {
					problems = le.Problems
				}
				out.row(out.failed(), p, problems[0])
				for _, pr := range problems[1:] {
					out.row("", "", pr)
				}
			}
			if err := out.flush(); err != nil {
				return err
			}
			if invalid := len(args) - len(gates); invalid > 0 {
				return fmt.Errorf("%d of %d gate files are invalid", invalid, len(args))
			}
			return gatefile.UniqueNames(gates)
		},
	}, cfg)
}
