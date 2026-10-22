package corpus

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
)

// SyftDocument is the part of a syft-json SBOM that says how it was built, from what, and which
// packages it holds.
type SyftDocument struct {
	Artifacts []struct {
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"artifacts"`
	Descriptor struct {
		Name          string         `json:"name"`
		Version       string         `json:"version"`
		Configuration map[string]any `json:"configuration"`
	} `json:"descriptor"`
	Source struct {
		Metadata struct {
			UserInput      string `json:"userInput"`
			ManifestDigest string `json:"manifestDigest"`
		} `json:"metadata"`
	} `json:"source"`
}

// ReadSyftDocument reads a syft-json SBOM's descriptor and source.
func ReadSyftDocument(data []byte) (*SyftDocument, error) {
	var d SyftDocument
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	if d.Descriptor.Name != "syft" {
		return nil, fmt.Errorf("not a syft-json SBOM (descriptor.name %q)", d.Descriptor.Name)
	}
	return &d, nil
}

// DescriptorDrift lists how an SBOM's descriptor disagrees with a catalog: the syft version, and
// every value the catalog's syft config file sets that descriptor.configuration holds otherwise.
// catConfig is that file's bytes, nil when the catalog names none.
//
// ponytail: syft records only its cataloging options in the descriptor, so keys outside those
// (output, parallelism) are not compared, and neither is env, which syft does not record.
func DescriptorDrift(d *SyftDocument, cat *gatefile.Catalog, catConfig []byte) ([]string, error) {
	var drift []string
	if v := cat.SyftVersion(); v != "" && v != d.Descriptor.Version {
		drift = append(drift, fmt.Sprintf("syft %s, where the catalog pins %s", d.Descriptor.Version, v))
	}
	if len(catConfig) == 0 {
		return drift, nil
	}
	var want map[string]any
	if err := yaml.Unmarshal(catConfig, &want); err != nil {
		return nil, fmt.Errorf("syft config %s: %w", cat.Config, err)
	}
	// round trip through JSON so numbers and maps compare as the descriptor's do
	data, _ := json.Marshal(want)
	_ = json.Unmarshal(data, &want)
	for k, v := range want {
		if _, ok := d.Descriptor.Configuration[k]; ok {
			drift = append(drift, compareConfig(k, v, d.Descriptor.Configuration[k])...)
		}
	}
	sort.Strings(drift)
	return drift, nil
}

func compareConfig(at string, want, got any) []string {
	if w, ok := want.(map[string]any); ok {
		g, _ := got.(map[string]any)
		var out []string
		for k, v := range w {
			out = append(out, compareConfig(at+"."+k, v, g[k])...)
		}
		return out
	}
	if !reflect.DeepEqual(want, got) {
		return []string{fmt.Sprintf("configuration %s is %v, where the catalog's config sets %v", at, render(got), render(want))}
	}
	return nil
}

func render(v any) string {
	data, _ := json.Marshal(v)
	return strings.TrimSpace(string(data))
}
