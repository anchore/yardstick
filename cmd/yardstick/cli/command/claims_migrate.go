package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/migrate"
	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
)

type claimsMigrateConfig struct {
	To     string `yaml:"to" json:"to" mapstructure:"to"`
	Report string `yaml:"report" json:"report" mapstructure:"report"`
	Grype  string `yaml:"grype" json:"grype" mapstructure:"grype"`
	DB     string `yaml:"db" json:"db" mapstructure:"db"`
}

func (c *claimsMigrateConfig) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&c.To, "to", "", "the claims directory to write labels into; it holds vocabulary.yaml and each image's sbom.syft.json")
	flags.StringVarP(&c.Report, "report", "", "a directory outside the corpus for report.json (every input label) and unknown.json (those not converted)")
	flags.StringVarP(&c.Grype, "grype", "", "the grype whose DB says which CVEs an advisory names")
	flags.StringVarP(&c.DB, "db", "", "that grype's DB: latest, an archive path or URL, or dir:<path>")
}

func ClaimsMigrate(app clio.Application) *cobra.Command {
	cfg := &claimsMigrateConfig{Grype: "grype@latest", DB: "latest"}
	return app.SetupCommand(&cobra.Command{
		Use:   "migrate <vulnerability-match-labels labels dir> --to <claims dir> --report <dir>",
		Short: "Convert vulnerability-match-labels into a claims corpus",
		Long: `migrate reads labels/<image>/<uuid>.json from a vulnerability-match-labels checkout and writes
each label into the corpus. A label's package type comes from the image's sbom.syft.json, which
must already be in the corpus; labels it cannot place are listed in unknown.json and not written.

An advisory id (by vocabulary.yaml's advisory-ids) becomes the CVEs grype's DB says it names: a
label on an advisory naming one CVE moves to that CVE with its verdict, and one naming several
becomes an unclear label with not-assessed on each. vulnerability-match-labels recorded no
reasons, so fp and unclear labels get not-recorded, and labels in one image that disagree on a
match become one unclear label with labelers-disagree. Rerunning over its own output changes
nothing.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.To == "" || cfg.Report == "" {
				return errors.New("migrate needs --to <claims dir> and --report <dir>")
			}
			if inside(cfg.Report, cfg.To) {
				return fmt.Errorf("--report %s is inside the corpus, where only label files and SBOMs belong", cfg.Report)
			}
			log.Debugf("options: to=%s report=%s grype=%q db=%q", cfg.To, cfg.Report, cfg.Grype, cfg.DB)
			log.Infof("migrating %s into %s", args[0], cfg.To)
			used := ""
			lookup := func(ctx context.Context, ids []string) (map[string][]string, error) {
				out, desc, err := grypeSearch(ctx, cfg.Grype, cfg.DB, ids)
				used = desc
				return out, err
			}
			res, err := migrate.Run(cmd.Context(), args[0], cfg.To, lookup)
			if err != nil {
				return err
			}
			vocab, err := labels.FindVocabulary(os.DirFS(cfg.To))
			if err != nil {
				return err
			}
			if err := (labels.Writer{Dir: cfg.To, Vocab: vocab}).Write(res.Placed); err != nil {
				return err
			}
			if err := res.WriteReport(cfg.Report); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if used != "" {
				fmt.Fprintf(out, "advisories resolved with %s\n", used)
			}
			counts := res.Counts()
			outcomes := make([]string, 0, len(counts))
			for o := range counts {
				outcomes = append(outcomes, string(o))
			}
			sort.Strings(outcomes)
			fmt.Fprintf(out, "%d input labels:\n", len(res.Entries))
			for _, o := range outcomes {
				fmt.Fprintf(out, "  %-22s %d\n", o, counts[migrate.Outcome(o)])
			}
			fmt.Fprintf(out, "wrote %d labels into %s; report in %s\n", len(res.Placed), cfg.To, cfg.Report)
			return nil
		},
	}, cfg)
}

// grypeSearch asks a grype setup's DB about ids: `grype db search vuln <id>... -o json`, with the
// grype and DB prepared the way a gate's setup is.
func grypeSearch(ctx context.Context, grype, db string, ids []string) (map[string][]string, string, error) {
	run := execute.Runner{}
	p, err := setup.NewPreparer(install.NewResolver(), run).Prepare(ctx, "migrate", &gatefile.Setup{Grype: grype, DB: db})
	if err != nil {
		return nil, "", err
	}
	desc := fmt.Sprintf("grype %s, DB %s %s", p.Grype.Spec, p.DB.Source, p.DB.Checksum)
	args := append([]string{"db", "search", "vuln", "--limit", "0", "-o", "json", "-q"}, ids...)
	stdout, _, err := run.Run(ctx, execute.Cmd{Bin: p.Grype.Bin, Args: args, DBDir: p.DB.Dir})
	if err != nil {
		return nil, desc, err
	}
	out, err := migrate.ParseGrypeSearch(stdout)
	return out, desc, err
}

// inside says whether path is dir or under it.
func inside(path, dir string) bool {
	p, err1 := filepath.Abs(path)
	d, err2 := filepath.Abs(dir)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(d, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
