package v1

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schema is the JSON Schema of a label file at Version. Like syft's, a published schema file is
// never edited: a new version is a new schema-<version>.json beside it.
//
//go:embed schema/schema-1.0.1.json
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

// SchemaJSON is the schema's bytes, a copy each call, for a corpus to publish beside its labels.
func SchemaJSON() []byte { return bytes.Clone(schema) }
