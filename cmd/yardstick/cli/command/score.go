package command

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/score"
)

// scoreOptions are what re-scoring takes: no tool runs, so no flag about one.
type scoreOptions struct {
	claimsOption  `yaml:",inline" mapstructure:",squash"`
	nameOption    `yaml:",inline" mapstructure:",squash"`
	outputOptions `yaml:",inline" mapstructure:",squash"`
}

func (o *scoreOptions) AddFlags(flags clio.FlagSet) {
	o.claimsOption.AddFlags(flags)
	o.nameOption.AddFlags(flags)
	o.outputOptions.AddFlags(flags)
}

func Score(app clio.Application, exit *int) *cobra.Command {
	cfg := &scoreOptions{nameOption: newNameOption(), outputOptions: newOutputOptions()}

	return app.SetupCommand(&cobra.Command{
		Use:   "score <gate.yaml or gate name>...",
		Short: "Re-score each gate's last scans against the current labels, without running grype or syft",
		Long: `score reads each gate's last scans from .yardstick/runs/<name>/<gate>/ and scores them against
the labels its claims sources hold now, so a label just written counts without scanning again. It
never runs grype or syft. Claims sources may change freely, --claims included. A gate whose
setups or subjects changed, or with a subject that no longer resolves to the SBOM it was scanned
from without a build, is reported undecided until it is run again with yardstick <gate.yaml>. It
reads no grype binary or DB, and compares a setup's paths relative to the gate file, so a gate file
and its .yardstick/runs copied to another checkout score there. A gate is a gate file, or the name
of a gate scanned under --name.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.check(); err != nil {
				return err
			}
			err := runrecord.CheckName(cfg.Name)
			if err != nil {
				return err
			}
			log.Debugf("options: name=%s output=%v details=%q quiet=%v claims=%v vulnerability=%v package=%v", cfg.Name, cfg.Output, cfg.Details, quiet, cfg.Claims, cfg.Vulnerabilities, cfg.Packages)
			for i, a := range args {
				if args[i], err = gatePath(cfg.Name, a); err != nil {
					return err
				}
			}
			gates, err := loadGates(args, cfg.Claims, false)
			if err != nil {
				return err
			}
			log.Infof("scoring %d gates against the current labels", len(gates))
			var verdicts []report.Gate
			for i, g := range gates {
				rec, err := runrecord.Load(cfg.Name, g.Name)
				if errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("gate %s has no scans in %s; run %s first", g.Name, runrecord.Dir(cfg.Name, g.Name), runrecord.Rerun(cfg.Name, args[i]))
				}
				if err != nil {
					return err
				}
				set, err := claims.OpenSet(g.Claims)
				if err != nil {
					return fmt.Errorf("gate %s: %w", g.Name, err)
				}
				if v := score.Stale(cmd.Context(), cfg.Name, g, rec, set); v != nil {
					verdicts = append(verdicts, *v)
					continue
				}
				v, err := score.Gate(cfg.Name, g, rec, set, cfg.focus())
				if err != nil {
					return fmt.Errorf("gate %s: %w", g.Name, err)
				}
				verdicts = append(verdicts, v)
			}
			return render(cmd, verdicts, cfg.outputOptions, exit)
		},
	}, cfg)
}
