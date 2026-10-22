package command

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/vex"
)

type claimsImportConfig struct {
	To     string `yaml:"to" json:"to" mapstructure:"to"`
	Author string `yaml:"author" json:"author" mapstructure:"author"`
	Source string `yaml:"source" json:"source" mapstructure:"source"`
}

func (c *claimsImportConfig) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&c.To, "to", "", "the claims directory to write labels into")
	flags.StringVarP(&c.Author, "author", "", "the person the labels are by: importing makes a vendor's statement your call")
	flags.StringVarP(&c.Source, "source", "", "the fact source the evidence names (default: openvex or osv), as listed in vocabulary.yaml")
}

func ClaimsImport(app clio.Application) *cobra.Command {
	cfg := &claimsImportConfig{}
	return app.SetupCommand(&cobra.Command{
		Use:   "import <openvex or osv file>... --to <claims dir> --author <name>",
		Short: "Write labels from vendor OpenVEX documents and OSV records",
		Long: `import reads vendor statements into labels, each citing the statement it came from as
evidence. An OpenVEX statement about an image (pkg:oci/...@sha256:...) labels its
subcomponents in that image's files, or its image.json when it names none; a statement about a
package is a global label. An OSV record's listed and last-affected versions become tp labels,
and its fixed versions fp, all global. Statements that name nothing a label can be about are
skipped and listed.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.To == "" || cfg.Author == "" {
				return errors.New("import needs --to <claims dir> and --author <name>")
			}
			log.Debugf("options: to=%s author=%s source=%s", cfg.To, cfg.Author, cfg.Source)
			log.Infof("importing %d VEX documents into %s", len(args), cfg.To)
			vocab, err := claimsv1.FindVocabulary(os.DirFS(cfg.To))
			if err != nil {
				return err
			}
			var placed []claimsv1.Placed
			var skipped []string
			for _, a := range args {
				data, err := os.ReadFile(a)
				if err != nil {
					return err
				}
				got, err := vex.Import(a, data, vex.Options{Author: cfg.Author, Source: cfg.Source, Now: time.Now()})
				if err != nil {
					return err
				}
				placed, skipped = append(placed, got.Placed...), append(skipped, got.Skipped...)
			}
			written, err := (claimsv1.Writer{Dir: cfg.To, Vocab: vocab}).Write(placed)
			if err != nil {
				return err
			}
			out := newPrinter(cmd.OutOrStdout())
			out.row(out.done(), fmt.Sprintf("imported %d labels", len(placed)), out.dim("into "+cfg.To))
			// a vendor statement replacing someone's call is worth a look, since it is now theirs
			for _, w := range written {
				if p := w.Prior; p != nil {
					out.row(out.notice(), fmt.Sprintf("replaced %s's %s label on %s", p.Author, p.Verdict, w.Key), out.dim(w.File))
				}
			}
			if len(skipped) > 0 {
				out.row(out.notice(), fmt.Sprintf("skipped %d statements", len(skipped)), out.dim("they name no image or package a label can be about"))
				for _, s := range skipped {
					out.row("", out.dim(s))
				}
			}
			return out.flush()
		},
	}, cfg)
}

type claimsExportConfig struct {
	VEX    bool   `yaml:"vex" json:"vex" mapstructure:"vex"`
	Output string `yaml:"output" json:"output" mapstructure:"output"`
	Author string `yaml:"author" json:"author" mapstructure:"author"`
}

func (c *claimsExportConfig) AddFlags(flags clio.FlagSet) {
	flags.BoolVarP(&c.VEX, "vex", "", "write OpenVEX (the one export format)")
	flags.StringVarP(&c.Output, "output", "o", "the file to write (default: stdout)")
	flags.StringVarP(&c.Author, "author", "", "the document's author")
}

func ClaimsExport(app clio.Application) *cobra.Command {
	cfg := &claimsExportConfig{Author: "anchore claims corpus"}
	return app.SetupCommand(&cobra.Command{
		Use:   "export --vex <claims dir> [-o <file>]",
		Short: "Write a corpus's labels as one OpenVEX document",
		Long: `export writes every label as an OpenVEX 0.2.0 statement: tp is affected, fp with
fix-installed is fixed, any other fp is not_affected (a justification OpenVEX has no name for is
written as vulnerable_code_not_present, with the label's justification and note in the impact
statement), and unclear is under_investigation. Evidence and seenIn are not exported.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cfg.VEX {
				return errors.New("export needs a format: --vex")
			}
			log.Debugf("options: output=%q author=%s", cfg.Output, cfg.Author)
			log.Infof("exporting %s as VEX", args[0])
			data, err := vex.Export(os.DirFS(args[0]), cfg.Author)
			if err != nil {
				return err
			}
			if cfg.Output == "" {
				_, err = cmd.OutOrStdout().Write(data)
				return err
			}
			return os.WriteFile(cfg.Output, data, 0o600)
		},
	}, cfg)
}
