package command

import (
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
)

// kindStatus is one row of the status: what a kind holds.
type kindStatus struct {
	Kind      string     `json:"kind"`
	Entries   int        `json:"entries"`
	Size      int64      `json:"size"`
	OldestUse *time.Time `json:"oldestUse"`
}

type cacheStatus struct {
	Root  string       `json:"root"`
	Kinds []kindStatus `json:"kinds"`
	Total kindStatus   `json:"total"`
}

func CacheStatus(app clio.Application) *cobra.Command {
	cfg := newTextOrJSON()
	return app.SetupCommand(&cobra.Command{
		Use:   "status",
		Short: "Show the cache's location, and the size and last use of each kind of entry",
		Long: `status prints the cache directory, then for each kind of entry (` + kindList + `) how many
entries it holds, their size, and the oldest last use, followed by the total. An entry's last use
is its modification time, which every reuse of it updates. status runs no tool and changes
nothing.`,
		Example: `  yardstick cache status
  yardstick cache status -o json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cfg.check(); err != nil {
				return err
			}
			st, err := readCacheStatus()
			if err != nil {
				return err
			}
			return presentCacheStatus(cmd.OutOrStdout(), cfg.Output, st)
		},
	}, &cfg)
}

func readCacheStatus() (cacheStatus, error) {
	st := cacheStatus{Root: cache.Dir(), Total: kindStatus{Kind: "total"}}
	for _, kind := range cache.Kinds {
		entries, err := cache.List(kind)
		if err != nil {
			return st, fmt.Errorf("unable to read the %s cache: %w", kind, err)
		}
		row := kindStatus{Kind: kind, Entries: len(entries)}
		for _, e := range entries {
			row.Size += e.Size
			if row.OldestUse == nil || e.LastUse.Before(*row.OldestUse) {
				t := e.LastUse
				row.OldestUse = &t
			}
		}
		st.Kinds = append(st.Kinds, row)
		st.Total.Entries += row.Entries
		st.Total.Size += row.Size
		if row.OldestUse != nil && (st.Total.OldestUse == nil || row.OldestUse.Before(*st.Total.OldestUse)) {
			st.Total.OldestUse = row.OldestUse
		}
	}
	return st, nil
}

func presentCacheStatus(w io.Writer, format string, st cacheStatus) error {
	if format == outputJSON {
		return writeJSON(w, st)
	}
	out := newPrinter(w)
	out.row(out.dim("Path:"), st.Root)
	out.row()
	if err := out.flush(); err != nil {
		return err
	}
	out.row(out.dim("KIND"), out.dim("ENTRIES"), out.dim("SIZE"), out.dim("OLDEST USE"))
	for _, row := range append(st.Kinds, st.Total) {
		oldest := "-"
		if row.OldestUse != nil {
			oldest = row.OldestUse.Format(time.RFC3339)
		}
		cells := []string{row.Kind, strconv.Itoa(row.Entries), humanize.Bytes(uint64(row.Size)), oldest}
		if row.Kind == st.Total.Kind {
			for i := range cells {
				cells[i] = out.bold(cells[i])
			}
		}
		out.row(cells...)
	}
	return out.flush()
}
