package command

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
)

type cacheDeleteOptions struct {
	OlderThan string `yaml:"older-than" json:"older-than" mapstructure:"older-than"`
}

func (o *cacheDeleteOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.OlderThan, "older-than", "", "only delete entries last used longer ago than this, such as 30d or 12h")
}

func CacheDelete(app clio.Application) *cobra.Command {
	cfg := &cacheDeleteOptions{}
	return app.SetupCommand(&cobra.Command{
		Use:   "delete [<kind>...] [--older-than <duration>]",
		Short: "Delete cache entries by kind and by how long ago they were last used",
		Long: `delete removes the entries of the kinds named (` + kindList + `), or of every kind when none
is. With --older-than only entries last used longer ago than the duration go; a day count works
(30d, 1d12h) as well as a Go duration (12h). An entry's last use is its modification time, which
every reuse of it updates. It prints each entry it removed and how much space that freed.

Nothing is deleted on a schedule: the cache only shrinks when this runs. An import or install in
progress is left alone, and a temporary entry is removed only once a day old.`,
		Example: `  yardstick cache delete dbs --older-than 30d
  yardstick cache delete scans sboms
  yardstick cache delete`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			kinds, err := cache.ParseKinds(args)
			if err != nil {
				return err
			}
			var olderThan time.Duration
			if cfg.OlderThan != "" {
				if olderThan, err = cache.ParseAge(cfg.OlderThan); err != nil {
					return err
				}
			}
			out := newPrinter(cmd.OutOrStdout())
			var count int
			var freed int64
			for _, kind := range kinds {
				removed, err := cache.Delete(kind, olderThan)
				for _, e := range removed {
					rel, _ := filepath.Rel(cache.Dir(), e.Path)
					out.row(out.done(), "removed "+rel, out.dim(humanize.Bytes(uint64(e.Size))))
					count++
					freed += e.Size
				}
				if err != nil {
					return errors.Join(out.flush(), fmt.Errorf("unable to delete from the %s cache: %w", kind, err))
				}
			}
			noun := "entries"
			if count == 1 {
				noun = "entry"
			}
			// the total is no row of the table, so it never widens a column
			if err := out.flush(); err != nil {
				return err
			}
			out.row(out.bold(fmt.Sprintf("removed %d %s, freed %s", count, noun, humanize.Bytes(uint64(freed)))))
			return out.flush()
		},
	}, cfg)
}
