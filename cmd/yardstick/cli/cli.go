package cli

import (
	"os"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/redact"
	"github.com/anchore/yardstick/cmd/yardstick/cli/command"
	"github.com/anchore/yardstick/cmd/yardstick/internal/bus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ui"
)

// quietKeepsErrors builds clio's default logger, except that -q keeps error-level logs. clio
// maps -q to a disabled logger, which would also swallow the error that explains a failed run.
func quietKeepsErrors(cfg clio.Config, store redact.Store) (logger.Logger, error) {
	if cfg.Log != nil && cfg.Log.Quiet {
		quiet := *cfg.Log
		quiet.Quiet, quiet.Level = false, logger.ErrorLevel
		cfg.Log = &quiet
	}
	return clio.DefaultLogger(cfg, store)
}

// New constructs the yardstick application: the root command runs gates, and each subcommand is
// one piece of a run done alone. The returned code is what to exit with once Run returns without
// an error.
func New(id clio.Identification) (clio.Application, *int) {
	live := ui.New()
	clioCfg := clio.NewSetupConfig(id).
		// -v info, -vv debug, -vvv trace; the default logs warnings and errors. The logger writes
		// to stderr, so stdout stays the report. -q is clio's and is read for the report too.
		WithLoggingConfig(clio.LoggingConfig{Level: logger.WarnLevel}).
		WithGlobalLoggingFlags().
		WithLoggerConstructor(quietKeepsErrors).
		WithUIConstructor(live.Select).
		WithMapExitCode(command.ExitCode).
		WithInitializers(
			func(state *clio.State) error {
				// hoist the clio-configured logger into the internal package for global use
				log.Set(state.Logger)
				command.SetQuiet(state.Config.Log != nil && state.Config.Log.Quiet)
				bus.Set(state.Bus)
				return nil
			},
		)
	// options come from flags only. The app config is read by gatefile.LoadAppConfig instead, since
	// fangs would let --claims replace its claims: rather than append to them, and would half-read
	// the Python yardstick's .yardstick.yaml rather than refuse it.
	clioCfg.FangsConfig.Finders = []fangs.Finder{func(fangs.Config) []string { return nil }}

	app := clio.New(*clioCfg)
	exit := 0

	root := command.Root(app, &exit)
	root.SetOut(live.Stdout(os.Stdout))
	root.AddCommand(
		clio.VersionCommand(id),
		command.Score(app, &exit),
		command.Config(app),
		command.Collect(app),
		command.Claims(app),
		command.Cache(app),
	)

	return app, &exit
}
