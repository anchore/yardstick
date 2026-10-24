package collect

import (
	"context"
	"fmt"

	"github.com/anchore/yardstick/cmd/yardstick/internal/bus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/event"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/install"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

// SBOMs builds image SBOMs with exactly the syft setup a catalog names.
type SBOMs struct {
	Tools *install.Resolver
	Run   execute.Runner
}

// Build runs the catalog's syft over an image, with its config, platform and env, and returns
// syft-json. It is the subject resolver's builder and what yardstick collect sboms runs.
func (c *SBOMs) Build(ctx context.Context, image ref.Ref, platform string, cat *subject.Catalog) ([]byte, error) {
	if image.Kind != ref.Image {
		return nil, fmt.Errorf("%s is not an image; only an oci: subject is built", image)
	}
	spec, err := install.ParseSpec("syft", cat.Syft)
	if err != nil {
		return nil, err
	}
	task := bus.StartTask(event.Install, "%s", spec)
	syft, err := c.Tools.Install(ctx, spec)
	task.Done(err)
	if err != nil {
		return nil, err
	}
	log.Infof("building the SBOM of %s with %s", image.Image(), syft.Spec)
	args := []string{image.Image(), "-o", "syft-json", "-q"}
	if platform != "" {
		args = append(args, "--platform", platform)
	}
	cfg := cat.Config
	if cfg == "" {
		if cfg, err = execute.EmptyConfig(); err != nil {
			return nil, err
		}
	}
	args = append(args, "-c", cfg)
	out, _, err := c.Run.Run(ctx, execute.Cmd{Bin: syft.Bin, Args: args, Env: cat.Env})
	if err != nil {
		return nil, fmt.Errorf("building the SBOM of %s with %s: %w", image.Image(), syft.Spec, err)
	}
	return out, nil
}
