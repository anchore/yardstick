package command

import (
	"fmt"
	"io/fs"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/purl"
)

type claimsListOptions struct {
	claimsOption  `yaml:",inline" mapstructure:",squash"`
	textOrJSON    `yaml:",inline" mapstructure:",squash"`
	Subject       string `yaml:"subject" json:"subject" mapstructure:"subject"`
	Vulnerability string `yaml:"vulnerability" json:"vulnerability" mapstructure:"vulnerability"`
}

func (o *claimsListOptions) AddFlags(flags clio.FlagSet) {
	o.claimsOption.AddFlags(flags)
	o.textOrJSON.AddFlags(flags)
	flags.StringVarP(&o.Subject, "subject", "s", "only labels about this: an image reference prefix, an SBOM digest, a package purl prefix (pkg:...) or a package name")
	flags.StringVarP(&o.Vulnerability, "vulnerability", "V", "only labels about this vulnerability id")
}

// listedLabel is one label in a claims source, with where it is.
type listedLabel struct {
	Source  string            `json:"source"`
	File    string            `json:"file"`
	Subject *claimsv1.Subject `json:"subject,omitempty"` // nil for a global label
	Label   claimsv1.Label    `json:"label"`
}

func ClaimsList(app clio.Application) *cobra.Command {
	cfg := &claimsListOptions{textOrJSON: newTextOrJSON()}
	return app.SetupCommand(&cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the labels in the claims sources",
		Long: `list lists every label in the app config's claims sources and --claims, in source order, each with
its source, file and subject. Each source's labels are listed as written: when two sources
disagree both show, and scoring uses the last source's verdict. A label's history is the claims
repository's git history.`,
		Example: `  yardstick claims list -s pkg:deb/debian/tar -o json
  yardstick claims list -V CVE-2005-2541`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cfg.check(); err != nil {
				return err
			}
			set, err := openClaims(cfg.Claims)
			if err != nil {
				return err
			}
			out := []listedLabel{}
			for _, src := range set.Sources {
				found, err := sourceLabels(src)
				if err != nil {
					return err
				}
				for _, l := range found {
					if cfg.keeps(l) {
						out = append(out, l)
					}
				}
			}
			if cfg.Output == outputJSON {
				return writeJSON(cmd.OutOrStdout(), out)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "VERDICT\tJUSTIFICATION\tVULNERABILITY\tPACKAGE\tSUBJECT\tAUTHOR\tUPDATED")
			for _, l := range out {
				sub := "(global)"
				if l.Subject != nil {
					sub = describeSubject(*l.Subject)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", l.Label.Verdict, l.Label.Justification, l.Label.Vulnerability, l.Label.Package, sub, l.Label.Author, l.Label.LastUpdated)
			}
			return tw.Flush()
		},
	}, cfg)
}

// sourceLabels is every label in one claims source, in path order.
func sourceLabels(src *claims.Source) ([]listedLabel, error) {
	var out []listedLabel
	err := fs.WalkDir(src.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if loc, ok := claimsv1.Locate(p); !ok || !loc.IsLabelFile() {
			return nil
		}
		data, err := fs.ReadFile(src.FS, p)
		if err != nil {
			return err
		}
		f, err := claimsv1.Parse(p, data)
		if err != nil {
			return fmt.Errorf("claims source %s: %w", src.Locator, err)
		}
		for _, l := range f.Labels {
			out = append(out, listedLabel{Source: src.Locator, File: p, Subject: f.Subject, Label: l})
		}
		return nil
	})
	return out, err
}

func (o *claimsListOptions) keeps(l listedLabel) bool {
	if o.Vulnerability != "" && l.Label.Vulnerability != o.Vulnerability {
		return false
	}
	if s := o.Subject; s != "" {
		pkg := l.Label.Package
		onPackage := pkg != "" && ((strings.HasPrefix(s, "pkg:") && strings.HasPrefix(pkg, s)) || purl.Package(pkg, "").Name == s)
		onSubject := l.Subject != nil && ((l.Subject.Image != "" && strings.HasPrefix(l.Subject.Image, s)) || l.Subject.SBOM == s)
		return onPackage || onSubject
	}
	return true
}
