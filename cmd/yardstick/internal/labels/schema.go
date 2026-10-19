package labels

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaV1 is the JSON Schema of a v1 label file. Once a corpus is published under v1 it only
// gains optional fields; a change of meaning or pairing is v2.
//
//go:embed schema/v1.json
var SchemaV1 []byte

var compiled = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(SchemaV1))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("v1.json", doc); err != nil {
		return nil, err
	}
	return c.Compile("v1.json")
})

// ValidateSchema checks a label file's bytes against the v1 schema.
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
