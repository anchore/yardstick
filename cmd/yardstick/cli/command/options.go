package command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
)

const (
	outputJSON = "json"
	outputText = "text"
)

// textOrJSON is -o for the commands that print a list: a table, or json.
type textOrJSON struct {
	Output string `yaml:"output" json:"output" mapstructure:"output"`
}

func newTextOrJSON() textOrJSON { return textOrJSON{Output: outputText} }

func (o *textOrJSON) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Output, "output", "o", "format to display results (available=[text, json])")
}

func (o *textOrJSON) check() error {
	if o.Output != outputText && o.Output != outputJSON {
		return fmt.Errorf("unknown output %q: use one of text, json", o.Output)
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// openClaims opens the claims sources a command that reads no gate uses: the app config's, then
// --claims.
func openClaims(extra []string) (*claims.Set, error) {
	app, err := gatefile.LoadAppConfig(".")
	if err != nil {
		return nil, err
	}
	sources, err := gatefile.Sources(app, extra)
	if err != nil {
		return nil, err
	}
	return claims.OpenSet(sources)
}
