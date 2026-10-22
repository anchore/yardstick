package command

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/collect"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

// collectSBOMsOptions are the two forms of collect sboms: an image with the catalog to build it
// with, or the gates whose missing SBOMs to build.
type collectSBOMsOptions struct {
	claimsOption `yaml:",inline" mapstructure:",squash"`
	Catalog      string   `yaml:"catalog" json:"catalog" mapstructure:"catalog"`
	Out          string   `yaml:"out" json:"out" mapstructure:"out"`
	Gates        []string `yaml:"gate" json:"gate" mapstructure:"gate"`
	RebuildSBOMs bool     `yaml:"rebuild-sboms" json:"rebuild-sboms" mapstructure:"rebuild-sboms"`
}

func (c *collectSBOMsOptions) AddFlags(flags clio.FlagSet) {
	c.claimsOption.AddFlags(flags)
	flags.StringVarP(&c.Catalog, "catalog", "", "the catalog.yaml naming the syft setup (default: ./catalog.yaml)")
	flags.StringVarP(&c.Out, "out", "", "where to write the SBOM (default: the image's directory when run in a corpus, else the cache)")
	flags.StringArrayVarP(&c.Gates, "gate", "", "a gate file whose image SBOMs no claims source and no cache holds are built, instead of one image (repeatable)")
	flags.BoolVarP(&c.RebuildSBOMs, "rebuild-sboms", "", rebuildSBOMsUsage+" (with --gate)")
}

func CollectSBOMs(app clio.Application) *cobra.Command {
	cfg := &collectSBOMsOptions{}
	return app.SetupCommand(&cobra.Command{
		Use:   "sboms <oci-subject> [--catalog <catalog.yaml>] [--out <file>] | --gate <gate.yaml>...",
		Short: "Build image SBOMs with exactly the syft setup a catalog names: one image, or every one a gate is missing",
		Long: `collect sboms runs the syft version a catalog pins, with its config, platform and env, over an
image pinned by digest, and writes syft-json. In a corpus checkout (a directory holding
catalog.yaml) it writes pkg/oci/<registry>/<repository>/sha256-<hex>/sbom.syft.json there;
elsewhere it writes the SBOM into yardstick's cache, where a gate run finds it. --out writes it
to a file of your choosing instead. Either way the cache holds a copy.

With --gate it builds, into the cache, every image SBOM those gates need that no claims source
and no cache holds, found the way a gate run finds them and built with each gate's catalog. It
never runs grype, and exits 0 when every SBOM is held or built and 2 when one cannot be. The image
form and --gate are exclusive.`,
		Example: `  yardstick collect sboms oci:docker.io/library/postgres:16@sha256:9a3c... --catalog claims/catalog.yaml
  yardstick collect sboms --gate gates/deb-matching.yaml`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(cfg.Gates) == 0 {
				return collectImage(cmd, cfg, args)
			}
			if len(args) > 0 || cfg.Catalog != "" || cfg.Out != "" {
				return errors.New("the image form (<oci-subject>, --catalog, --out) and --gate are exclusive")
			}
			// only the SBOM stage runs, so no scan option but these applies
			_, err := runGates(cmd, cfg.Gates, &scanOptions{claimsOption: cfg.claimsOption, RebuildSBOMs: cfg.RebuildSBOMs}, toSBOMs, nil)
			return err
		},
	}, cfg)
}

// collectImage is the image form: one image's SBOM, built with a catalog file.
func collectImage(cmd *cobra.Command, cfg *collectSBOMsOptions, args []string) error {
	if len(args) == 0 {
		return errors.New("collect sboms needs an <oci-subject>, or --gate <gate.yaml>")
	}
	if len(cfg.Claims) > 0 || cfg.RebuildSBOMs {
		return errors.New("--claims and --rebuild-sboms apply only with --gate")
	}
	image, err := ref.Parse(args[0])
	if err != nil {
		return err
	}
	if image.Kind != ref.Image {
		return fmt.Errorf("%s: collect sboms builds an image's SBOM; an sbom: subject is already one", args[0])
	}
	catPath, inCorpus := cfg.Catalog, false
	if catPath == "" {
		if _, err := os.Stat(claimsv1.CatalogFile); err != nil {
			return errors.New("collect sboms needs --catalog <catalog.yaml>, or to run in a corpus holding one")
		}
		catPath, inCorpus = claimsv1.CatalogFile, true
	}
	cat, err := readCatalog(catPath)
	if err != nil {
		return err
	}
	log.Debugf("options: catalog=%s in-corpus=%t platform=%s", catPath, inCorpus, cat.Platform)
	log.Infof("collecting the SBOM for %s", args[0])
	tools := install.NewResolver()
	run := execute.Runner{}
	data, err := (&collect.SBOMs{Tools: tools, Run: run}).Build(cmd.Context(), image, cat.Platform, cat)
	if err != nil {
		return err
	}
	out := subject.CachePath(image, cat, cat.Platform)
	if err := subject.WriteFile(out, data); err != nil {
		return err
	}
	switch {
	case cfg.Out != "":
		out = cfg.Out
	case inCorpus:
		out = filepath.Join(filepath.FromSlash(claimsv1.ImageDir(image)), claimsv1.ImageSBOMFile)
	}
	if err := subject.WriteFile(out, data); err != nil {
		return err
	}
	p := newPrinter(cmd.OutOrStdout())
	p.row(p.done(), "wrote "+out)
	return p.flush()
}

// readCatalog reads a corpus catalog file, and the config it names through the corpus root, so
// nothing outside the corpus is handed to syft.
func readCatalog(path string) (*subject.Catalog, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	// a catalog collect sboms reads is a corpus's, often a contributor's clone holding a pull request's
	// edits: it is data, held to what a claims source's catalog may set. Its paths stay relative to
	// the corpus root.
	parsed, err := gatefile.ParseCatalog(data, "")
	if err == nil {
		err = parsed.CheckData()
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cat := &subject.Catalog{Catalog: *parsed, Origin: path}
	if cat.Config == "" {
		return cat, nil
	}
	root, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if cat.ConfigData, err = claimsv1.ReadCatalogConfig(root.FS(), cat.Config); err == nil {
		err = gatefile.CheckDataConfig(cat.ConfigData)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// syft reads the bytes read through the root, from a file of yardstick's own
	sum := sha256.Sum256(cat.ConfigData)
	cat.Config = cache.Dir("catalog-config", hex.EncodeToString(sum[:])+".yaml")
	return cat, subject.WriteFile(cat.Config, cat.ConfigData)
}
