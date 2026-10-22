package v1

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schema is the JSON Schema of a label file at Version. Like syft's, a published schema file is
// never edited: a new version is a new schema-<version>.json beside it.
//
//go:embed schema/schema-1.0.0.json
var schema []byte

var compiled = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(SchemaFile, doc); err != nil {
		return nil, err
	}
	return c.Compile(SchemaFile)
})

// ValidateSchema checks a label file's bytes against the schema.
func ValidateSchema(data []byte) error {
	sch, err := compiled()
	if err != nil {
		return fmt.Errorf("the embedded label schema does not compile: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return sch.Validate(inst)
}

// SchemaFile is the name the schema is published under, as syft names its own: schema-<version>.json.
const SchemaFile = "schema-" + Version + ".json"

// WriteSchema writes the schema into dir as SchemaFile, for a corpus to publish beside its labels.
// Like syft's generator it leaves an identical file alone and refuses to replace a different
// one, since a published schema is never edited and a change to it needs a new Version. wrote
// says whether the file is new.
func WriteSchema(dir string) (path string, wrote bool, err error) {
	path = filepath.Join(dir, SchemaFile)
	existing, err := os.ReadFile(path)
	switch {
	case err == nil && bytes.Equal(existing, schema):
		return path, false, nil
	case err == nil:
		return path, false, fmt.Errorf("%s differs from the schema this yardstick embeds; a published schema is never edited, so a change to it needs a new format version", path)
	case !errors.Is(err, os.ErrNotExist):
		return path, false, err
	}
	return path, true, WriteFile(dir, SchemaFile, schema)
}
