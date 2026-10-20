package command

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

type claimsServeConfig struct {
	claimsOption `yaml:",inline" mapstructure:",squash"`
	nameOption   `yaml:",inline" mapstructure:",squash"`
	Author       string `yaml:"author" json:"author" mapstructure:"author"`
	// ResearchModel is the model research jobs run on (research.DefaultModel when empty).
	ResearchModel string `yaml:"research-model" json:"research-model" mapstructure:"research-model"`
	Addr          string `yaml:"-" json:"-" mapstructure:"-"`
	Open          bool   `yaml:"-" json:"-" mapstructure:"-"`
}

func (c *claimsServeConfig) AddFlags(flags clio.FlagSet) {
	c.claimsOption.AddFlags(flags)
	c.nameOption.AddFlags(flags)
	flags.StringVarP(&c.Author, "author", "", "who makes the calls (default: git config user.name)")
	flags.StringVarP(&c.Addr, "addr", "", "address to listen on; keep it on localhost, since a per-start token is the only authentication")
	flags.BoolVarP(&c.Open, "open", "", "open the UI in a browser")
	flags.StringVarP(&c.ResearchModel, "research-model", "", "model research jobs run on")
}

func ClaimsServe(app clio.Application) *cobra.Command {
	cfg := &claimsServeConfig{nameOption: newNameOption(), Addr: "127.0.0.1:7655"}
	return app.SetupCommand(&cobra.Command{
		Use:   "serve [gate]",
		Short: "Label a run's gates in a local web UI (opens the gate given, or the list of gates)",
		Long: `serve is a local web UI over every gate scanned under the run (.yardstick/runs/<name>/): the
gate's checks, the findings each one counts, a scan map of its changes, and one finding at a time
to label. It opens the gate given (a name, or a gate file), else the list of gates. Labels are written into each
gate's last claims source, which must be local, the same as yardstick claims add, and gates are
re-scored whenever a label, claims file or agent record changes, so labels written elsewhere
show up when the page regains focus, without scanning again. Agent proposals, causes and
explanations under .yardstick/ show as hints; none counts until a person accepts it.`,
		Example: `  yardstick claims serve gates/deb.yaml --claims ./.claims --open`,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !labelserver.HasUI() {
				return errors.New("this yardstick was built without the label UI, as go install builds are: install a release (curl -sSfL https://get.anchore.io/yardstick | sh), or run make generate in a clone before building")
			}
			if err := runrecord.CheckName(cfg.Name); err != nil {
				return err
			}
			open := ""
			if len(args) == 1 {
				open = args[0]
				// a gate file is opened by the name it declares
				if info, err := os.Stat(open); err == nil && !info.IsDir() {
					gates, err := loadGates([]string{open}, cfg.Claims, false)
					if err != nil {
						return err
					}
					open = gates[0].Name
				}
				if _, err := runrecord.Load(cfg.Name, open); err != nil {
					return fmt.Errorf("gate %s has no scans under run %s (%w)", open, cfg.Name, err)
				}
			}
			author := cfg.Author
			if author == "" {
				author = gitUser()
			}
			if author == "" {
				return errors.New("no author: give --author, or set git config user.name")
			}
			runner, avail, err := newResearch(cmd, app.ID().Version, cfg.Name, cfg.ResearchModel)
			if err != nil {
				return err
			}
			srv, err := labelserver.New(cmd.Context(), labelserver.Options{
				Run: cfg.Name, Open: open, Author: author, Store: agentstore.Open(agentstore.Dir),
				Research: runner, ResearchAvailability: avail,
				Load: func(path string) (*gatefile.Gate, error) {
					gates, err := loadGates([]string{path}, cfg.Claims, false)
					if err != nil {
						return nil, err
					}
					return gates[0], nil
				},
			})
			if err != nil {
				return err
			}
			err = serve(cmd.Context(), cmd, cfg.Addr, cfg.Open, srv.Handler())
			runner.Wait() // jobs stop with the server and record it
			return err
		},
	}, cfg)
}

// newResearch is the runner research jobs start from, in the working directory, and whether the
// yardstick plugin they need is installed at this binary's version. yardstick never installs it.
func newResearch(cmd *cobra.Command, version, run, model string) (*research.Runner, research.Availability, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, research.Availability{}, err
	}
	bin, err := os.Executable()
	if err != nil {
		return nil, research.Availability{}, err
	}
	avail := research.CheckPlugin(cmd.Context(), version)
	if !avail.Available {
		out := newPrinter(cmd.ErrOrStderr())
		out.row(out.notice(), "research is disabled: "+avail.Reason)
		if avail.Command != "" {
			out.row("", out.dim("to enable it, run: "+avail.Command))
		}
		if err := out.flush(); err != nil {
			return nil, research.Availability{}, err
		}
	}
	return research.NewRunner(research.Config{Model: model, Dir: dir, Run: run, Concurrency: 2, Timeout: 20 * time.Minute, Bin: bin}), avail, nil
}

func serve(ctx context.Context, cmd *cobra.Command, addr string, open bool, h http.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	h = labelserver.LocalOnly(ln.Addr().(*net.TCPAddr).Port, h)
	url := "http://" + ln.Addr().String() + "/"
	out := newPrinter(cmd.OutOrStdout())
	out.row(out.done(), "labeling at "+out.bold(url), out.dim("ctrl-c to stop"))
	if err := out.flush(); err != nil {
		return err
	}
	if open {
		openBrowser(url)
	}
	server := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		// give in-flight requests a moment, without inheriting the cancellation
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func openBrowser(url string) {
	name, args := "xdg-open", []string{url}
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	}
	_ = exec.Command(name, args...).Start()
}
