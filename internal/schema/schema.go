// Package schema declares what a collection may hold and how each field looks
// when revealed masked. Collections without a declaration accept any JSON
// object, and every field in them is treated as type "string".
package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Schema maps a collection name to its declaration.
type Schema map[string]Collection

// Collection lists the fields an object may have. Every field is optional;
// undeclared ones are rejected.
type Collection struct {
	Fields map[string]Field `json:"fields"`
}

// Field is one declared field. Type is one of the names in types.
type Field struct {
	Type string `json:"type"`
}

// Load reads a schema file. An empty path yields an empty schema.
func Load(path string) (Schema, error) {
	if path == "" {
		return Schema{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes a schema document and rejects unknown keys and types.
func Parse(data []byte) (Schema, error) {
	var s Schema
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	for cname, c := range s {
		for fname, f := range c.Fields {
			if _, ok := types[f.Type]; !ok {
				return nil, fmt.Errorf("schema: %s.%s: unknown type %q", cname, fname, f.Type)
			}
		}
	}
	return s, nil
}

// Validate checks an object against its collection's declaration. Error
// messages name fields, never values.
func (s Schema) Validate(collection string, object map[string]json.RawMessage) error {
	c, declared := s[collection]
	if !declared {
		return nil
	}
	for name, raw := range object {
		f, ok := c.Fields[name]
		if !ok {
			return fmt.Errorf("unknown field %q", name)
		}
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("field %q must be a string", name)
		}
		if err := types[f.Type].validate(v); err != nil {
			return fmt.Errorf("field %q: %w", name, err)
		}
	}
	return nil
}

// Mask returns the object with every value replaced by its masked form.
// Values that are not strings, and fields of undeclared collections, are
// hidden entirely.
func (s Schema) Mask(collection string, object map[string]json.RawMessage) map[string]string {
	out := make(map[string]string, len(object))
	for name, raw := range object {
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			out[name] = hidden
			continue
		}
		t := "string"
		if f, ok := s[collection].Fields[name]; ok {
			t = f.Type
		}
		out[name] = types[t].mask(v)
	}
	return out
}
