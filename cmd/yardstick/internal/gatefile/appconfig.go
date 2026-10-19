package gatefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// AppConfigPaths are where yardstick looks for its own config, relative to the working directory.
// Nowhere else is read: not home, XDG or a parent directory, so a personal file never changes
// what a CI gate reads.
var AppConfigPaths = []string{".yardstick.yaml", filepath.Join("config", "yardstick.yaml")}

// AppConfig is yardstick's own config: the claims sources every gate without its own claims: reads.
type AppConfig struct {
	// Path is the file it was read from.
	Path string
	// Claims are the sources as written; local ones resolve against Path's directory.
	Claims []string
}

// LoadAppConfig reads the app config from dir, the working directory. No config is nil and no
// error.
func LoadAppConfig(dir string) (*AppConfig, error) {
	var found []string
	for _, p := range AppConfigPaths {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			found = append(found, p)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	switch len(found) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, fmt.Errorf("both %s and %s exist; yardstick reads one app config, so remove one", found[0], found[1])
	}
	path, err := canonical(filepath.Join(dir, found[0]))
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, &LoadError{Path: found[0], Problems: []string{err.Error()}}
	}
	if len(doc.Content) == 0 {
		return &AppConfig{Path: path}, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, &LoadError{Path: found[0], Problems: []string{"an app config is a YAML mapping"}}
	}
	var errs problems
	for i := 0; i < len(root.Content); i += 2 {
		k := root.Content[i].Value
		switch k {
		case "claims":
		case "result-sets":
			// every Python yardstick config has result-sets:, and the two tools share the file name
			return nil, &LoadError{Path: found[0], Problems: []string{"this is a Python yardstick configuration (it has result-sets:), which this yardstick does not read; move it, or run from another directory"}}
		default:
			errs.addf("unknown key %q (line %d); an app config takes: claims", k, root.Content[i].Line)
		}
	}
	var raw struct {
		Claims []string `yaml:"claims"`
	}
	if len(errs) == 0 {
		if err := root.Decode(&raw); err != nil {
			errs.addf("%v", err)
		}
	}
	if len(errs) > 0 {
		return nil, &LoadError{Path: found[0], Problems: errs}
	}
	log.Debugf("loaded app config %s: claims sources %v", path, raw.Claims)
	return &AppConfig{Path: path, Claims: raw.Claims}, nil
}

// Sources are the claims sources a command that reads no gate file uses: the app config's, then
// the CLI's --claims.
func Sources(app *AppConfig, cli []string) ([]Source, error) {
	var errs problems
	out := claims(nil, Options{App: app, Claims: cli}, "", &errs)
	if len(errs) > 0 {
		return nil, &LoadError{Path: "claims sources", Problems: errs}
	}
	return out, nil
}
