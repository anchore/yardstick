package command

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func CollectScans(app clio.Application) *cobra.Command {
	cfg := new(newScanOptions())

	return app.SetupCommand(&cobra.Command{
		Use:   "scans <gate.yaml>...",
		Short: "Scan each gate's subjects with its setups and keep the scans, without scoring them",
		Long: `collect scans does everything a gate run does before scoring: it loads every gate, finds or
builds each subject's SBOM, and scans it with each setup into .yardstick/runs/<name>/<gate>/,
reusing stored scans as a gate run does. It prints no report and exits 0 once every gate's scans
are written, whatever they would score, and 2 on a load or scan failure. yardstick score then
scores them, so yardstick <gate.yaml>... is collect scans followed by score.`,
		Example: `  yardstick collect scans gates/*.yaml && yardstick score gates/*.yaml`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := runGates(cmd, args, cfg, toScans, nil)
			return err
		},
	}, cfg)
}
