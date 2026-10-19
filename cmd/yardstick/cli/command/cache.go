package command

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
)

// kindList names the kinds for help text.
var kindList = strings.Join(cache.Kinds, ", ")

func Cache(app clio.Application) *cobra.Command {
	cmd := app.SetupCommand(&cobra.Command{
		Use:   "cache",
		Short: "Show what yardstick's cache holds, and clean it up",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	})
	cmd.AddCommand(
		CacheStatus(app),
		CacheDelete(app),
	)
	return cmd
}
