package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/collect"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/score"
	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

// ExitCode maps an error to the process's exit code. Every error a command returns is a load or
// input error (2); a gate that fails or is undecided is not an error, and sets 1 itself.
func ExitCode(error) int {
	return 2
}

// claimsOption is --claims, local claims sources appended after a gate file's own.
type claimsOption struct {
	Claims []string `yaml:"claims" json:"claims" mapstructure:"claims"`
}

func (o *claimsOption) AddFlags(flags clio.FlagSet) {
	flags.StringArrayVarP(&o.Claims, "claims", "", "a local claims directory read after the gate file's claims sources, and written to (repeatable)")
}

// nameOption is --name, the run whose scans a command writes or reads: .yardstick/runs/<name>/.
// Its key is name, so clio also reads it from YARDSTICK_NAME, and the flag wins over the env.
type nameOption struct {
	Name string `yaml:"name" json:"name" mapstructure:"name"`
}

func newNameOption() nameOption {
	return nameOption{Name: runrecord.DefaultName}
}

func (o *nameOption) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Name, "name", "", "the run's name, keeping its scans apart in .yardstick/runs/<name>/ (env YARDSTICK_NAME)")
}

// outputOptions are how a verdict set is shown; none changes it. A focus narrows the rows shown,
// and every count, value and outcome stays the whole gate's.
type outputOptions struct {
	Output          []string `yaml:"output" json:"output" mapstructure:"output"`
	Details         string   `yaml:"details" json:"details" mapstructure:"details"`
	Vulnerabilities []string `yaml:"vulnerability" json:"vulnerability" mapstructure:"vulnerability"`
	Packages        []string `yaml:"package" json:"package" mapstructure:"package"`
}

// quiet is the global -q, which clio owns: it silences the logs, and the report prints only
// failing and undecided gates and their checks, and the summary line.
var quiet bool

// SetQuiet records the global -q once clio has loaded it.
func SetQuiet(q bool) { quiet = q }

func (o *outputOptions) AddFlags(flags clio.FlagSet) {
	flags.StringArrayVarP(&o.Output, "output", "o", fmt.Sprintf("report format (<format>=<file> to write to a file, repeatable, at most one to stdout), formats=%s; json is the whole verdict set at any details level, its rows narrowed only by --vulnerability and --package", strings.Join(report.Formats, ", ")))
	flags.StringVarP(&o.Details, "details", "", fmt.Sprintf("what the cause, check and subject layouts add, one of %s: passing adds passing checks and their values, rows also the rows behind them", strings.Join(report.DetailsLevels, ", ")))
	flags.StringArrayVarP(&o.Vulnerabilities, "vulnerability", "", "show only the rows of this vulnerability or any alias of it (repeatable); counts, values and the outcome stay the whole gate's")
	flags.StringArrayVarP(&o.Packages, "package", "", "show only the rows on this package, a purl prefix (pkg:...) or a purl name (repeatable); with --vulnerability, rows must match both")
}

func (o *outputOptions) options() report.Options {
	return report.Options{Details: o.Details, Quiet: quiet}
}

// focus is what --vulnerability and --package narrow the rows to, nil when neither is given.
func (o *outputOptions) focus() *report.Focus {
	return report.NewFocus(o.Vulnerabilities, o.Packages)
}

// check fails on an output or details value that does not exist, before anything is scanned.
func (o *outputOptions) check() error {
	if _, err := report.ParseOutputs(o.Output); err != nil {
		return err
	}
	return report.CheckDetails(o.Details)
}

func newOutputOptions() outputOptions {
	return outputOptions{Output: []string{report.Formats[0]}}
}

// rebuildSBOMsUsage is --rebuild-sboms, which a gate run and collect sboms --gate both take.
const rebuildSBOMsUsage = "build every image SBOM with the catalog, even where a claims source holds one"

// scanOptions are what collecting a gate's scans takes: everything a gate run takes but how the
// verdicts are shown.
type scanOptions struct {
	claimsOption `yaml:",inline" mapstructure:",squash"`
	nameOption   `yaml:",inline" mapstructure:",squash"`
	RebuildSBOMs bool `yaml:"rebuild-sboms" json:"rebuild-sboms" mapstructure:"rebuild-sboms"`
	InheritEnv   bool `yaml:"inherit-env" json:"inherit-env" mapstructure:"inherit-env"`
	Rescan       bool `yaml:"rescan" json:"rescan" mapstructure:"rescan"`
	Parallelism  int  `yaml:"parallelism" json:"parallelism" mapstructure:"parallelism"`
}

func newScanOptions() scanOptions {
	return scanOptions{nameOption: newNameOption(), Parallelism: runtime.GOMAXPROCS(0)}
}

func (o *scanOptions) AddFlags(flags clio.FlagSet) {
	o.claimsOption.AddFlags(flags)
	o.nameOption.AddFlags(flags)
	flags.BoolVarP(&o.RebuildSBOMs, "rebuild-sboms", "", rebuildSBOMsUsage)
	flags.BoolVarP(&o.InheritEnv, "inherit-env", "", "pass your GRYPE_* and SYFT_* variables on to grype and syft (each is named in a warning)")
	flags.BoolVarP(&o.Rescan, "rescan", "", "run every scan and replace the stored one, instead of reusing a scan stored for the same inputs")
	flags.IntVarP(&o.Parallelism, "parallelism", "", "how many grype scans run at once (at least 1)")
}

// runOptions are what running gates takes: the scan options and how the verdicts are shown.
type runOptions struct {
	scanOptions   `yaml:",inline" mapstructure:",squash"`
	outputOptions `yaml:",inline" mapstructure:",squash"`
}

func (o *runOptions) AddFlags(flags clio.FlagSet) {
	o.scanOptions.AddFlags(flags)
	o.outputOptions.AddFlags(flags)
}

func Root(app clio.Application, exit *int) *cobra.Command {
	cfg := &runOptions{scanOptions: newScanOptions(), outputOptions: newOutputOptions()}

	return app.SetupRootCommand(&cobra.Command{
		Use:   "yardstick <gate.yaml>...",
		Short: "Run quality gates: scan subjects with two grype setups and check both against labels",
		Long: `yardstick runs gates. A gate is one YAML file naming a candidate grype setup, an optional
reference setup, the subjects to scan, the claims sources to read labels from, and the checks
that decide whether the candidate is as good as the reference.

yardstick <gate.yaml>... finds or builds each subject's SBOM, scans it with each setup, and
scores the scans against the labels. The last line is the verdict, and the exit code is 0 when
every gate passes, 1 when one fails, and 2 on a load or input error.

Each step also runs alone: yardstick collect sboms --gate builds the SBOMs nobody holds,
yardstick collect scans writes the scans, and yardstick score scores them.`,
		Example: `  yardstick gates/*.yaml
  yardstick gates/deb-matching.yaml --claims ./.claims`,
		// Args turns off cobra's "unknown command" handling: anything that is not a subcommand
		// arrives here as a gate file path
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				_ = cmd.Help()
				return errors.New("no gate files given")
			}
			if err := cfg.check(); err != nil {
				return err
			}
			log.Debugf("options: output=%v details=%q quiet=%v vulnerability=%v package=%v", cfg.Output, cfg.Details, quiet, cfg.Vulnerabilities, cfg.Packages)
			verdicts, err := runGates(cmd, args, &cfg.scanOptions, toScores, cfg.focus())
			if err != nil {
				return err
			}
			return render(cmd, verdicts, cfg.outputOptions, exit)
		},
	}, cfg)
}

// stage is how far a run over gate files goes.
type stage int

const (
	// toSBOMs stops once every subject's SBOM is found or built: collect sboms --gate.
	toSBOMs stage = iota
	// toScans stops once every gate's scans are written: collect scans.
	toScans
	// toScores scores the scans too: the root.
	toScores
)

// runGates is the one run over gate files that the root, collect sboms --gate and collect scans
// share, each stopping at its own stage. Every gate loads before any is run, and each gate's claims
// sources are opened once. The verdicts are returned only when it scores, narrowed to focus.
func runGates(cmd *cobra.Command, args []string, cfg *scanOptions, until stage, focus *report.Focus) ([]report.Gate, error) {
	if err := gateFilesExist(args); err != nil {
		return nil, err
	}
	if until > toSBOMs {
		if err := collect.CheckParallelism(cfg.Parallelism); err != nil {
			return nil, err
		}
		if err := runrecord.CheckName(cfg.Name); err != nil {
			return nil, err
		}
	}
	log.Debugf("options: name=%s parallelism=%d claims=%v rebuild-sboms=%v inherit-env=%v rescan=%v",
		cfg.Name, cfg.Parallelism, cfg.Claims, cfg.RebuildSBOMs, cfg.InheritEnv, cfg.Rescan)
	gates, err := loadGates(args, cfg.Claims, false)
	if err != nil {
		return nil, err
	}
	log.Infof("running %d gates", len(gates))
	scan := scanner(cfg)
	var verdicts []report.Gate
	for _, g := range gates {
		v, err := runGate(cmd, scan, g, cfg.Name, until, focus)
		if err != nil {
			return nil, fmt.Errorf("gate %s: %w", g.Name, err)
		}
		if v != nil {
			verdicts = append(verdicts, *v)
		}
	}
	return verdicts, nil
}

// runGate takes one gate as far as until. A stage that prints no report logs the warnings the
// report would have carried.
func runGate(cmd *cobra.Command, scan collect.Scans, g *gatefile.Gate, name string, until stage, focus *report.Focus) (*report.Gate, error) {
	set, err := claims.OpenSet(g.Claims)
	if err != nil {
		return nil, err
	}
	if until == toSBOMs {
		// a gate run scans the held SBOM of an image it cannot build (a frozen subject), but
		// collect sboms was asked for the build, so a failed one fails the command
		var failed []error
		build := scan.Build
		scan.Build = func(ctx context.Context, image ref.Ref, platform string, cat *subject.Catalog) ([]byte, error) {
			data, err := build(ctx, image, platform, cat)
			if err != nil {
				failed = append(failed, err)
			}
			return data, err
		}
		resolved, err := scan.Resolve(cmd.Context(), g, set)
		if err == nil {
			err = errors.Join(failed...)
		}
		if err != nil {
			return nil, err
		}
		out := newPrinter(cmd.OutOrStdout())
		for _, res := range resolved {
			for _, w := range res.Warnings {
				log.Warnf("%s", w)
			}
			if res.From == subject.FromBuilt {
				out.row(out.done(), "wrote "+res.SBOM)
			}
		}
		return nil, out.flush()
	}
	rec, err := scan.Gate(cmd.Context(), g, set)
	if err != nil {
		return nil, err
	}
	if until == toScans {
		for _, w := range rec.Warnings {
			log.Warnf("%s", w)
		}
		return nil, nil
	}
	v, err := score.Gate(name, g, rec, set, focus)
	return &v, err
}

// gateFilesExist fails on an argument that is no file. A mistyped subcommand reaches the root
// command as a path, so the error says it is neither.
func gateFilesExist(args []string) error {
	for _, a := range args {
		if info, err := os.Stat(a); err != nil || info.IsDir() {
			return fmt.Errorf("%q is not a gate file or a command", a)
		}
	}
	return nil
}

// loadGates loads the app config and every gate file, reporting every file's problems rather
// than stopping at the first, then checks that no two resolve to one name.
func loadGates(paths, claims []string, writes bool) ([]*gatefile.Gate, error) {
	app, err := gatefile.LoadAppConfig(".")
	if err != nil {
		return nil, err
	}
	var errs []error
	var gates []*gatefile.Gate
	for _, p := range paths {
		g, err := gatefile.Load(p, gatefile.Options{Checks: analysis.Definitions(), App: app, Claims: claims, Writes: writes})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		gates = append(gates, g)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	if err := gatefile.UniqueNames(gates); err != nil {
		return nil, err
	}
	return gates, nil
}

// scanner scans gates for one invocation: one tool resolver and one setup preparer, so latest
// means one version and one DB across every gate.
func scanner(cfg *scanOptions) collect.Scans {
	run := execute.Runner{InheritEnv: cfg.InheritEnv}
	if cfg.InheritEnv {
		inherited := execute.Inherited()
		names := make([]string, 0, len(inherited))
		for k := range inherited {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			log.Warnf("--inherit-env passes %s from your environment to grype and syft", k)
		}
	}
	tools := install.NewResolver()
	return collect.Scans{
		Run:      run,
		Preparer: setup.NewPreparer(tools, run),
		Build:    (&collect.SBOMs{Tools: tools, Run: run}).Build,
		Rebuild:  cfg.RebuildSBOMs,
		Rescan:   cfg.Rescan,

		Parallelism: cfg.Parallelism,
		RunName:     cfg.Name,
	}
}

// render writes the verdict set and sets the exit code from it: 0 when every gate passes under
// its policy, 1 otherwise.
func render(cmd *cobra.Command, verdicts []report.Gate, o outputOptions, exit *int) error {
	set := report.Summarize(verdicts)
	set.Focus = o.focus()
	log.Infof("rendering %d gates as %s", len(verdicts), strings.Join(o.Output, ", "))
	outs, err := report.ParseOutputs(o.Output)
	if err != nil {
		return err
	}
	opts := o.options()
	opts.Color = report.Colorable(cmd.OutOrStdout())
	if err := report.WriteOutputs(cmd.OutOrStdout(), set, outs, opts); err != nil {
		return err
	}
	*exit = set.Summary.ExitCode
	return nil
}
