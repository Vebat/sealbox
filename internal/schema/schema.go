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

// Field is one declared field. Type is one of the names in types. Index
// enables exact-match search on the field; only types with a normal form
// (email, phone, card) can be indexed.
type Field struct {
	Type  string `json:"type"`
	Index bool   `json:"index"`
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
			t, ok := types[f.Type]
			if !ok {
				return nil, fmt.Errorf("schema: %s.%s: unknown type %q", cname, fname, f.Type)
			}
			if f.Index && t.normalize == nil {
				return nil, fmt.Errorf("schema: %s.%s: type %q cannot be indexed", cname, fname, f.Type)
			}
		}
	}
	return s, nil
}

// Indexed returns the normalized values of the object's indexed fields, keyed
// by field name, ready for the blind index. The object must have passed
// Validate.
func (s Schema) Indexed(collection string, object map[string]json.RawMessage) map[string]string {
	var out map[string]string
	for name, f := range s[collection].Fields {
		raw, present := object[name]
		if !f.Index || !present {
			continue
		}
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[name] = types[f.Type].normalize(v)
	}
	return out
}

// Normalize prepares a search value for an indexed field. The error names
// the field, never the value.
func (s Schema) Normalize(collection, field, value string) (string, error) {
	f, ok := s[collection].Fields[field]
	if !ok || !f.Index {
		return "", fmt.Errorf("field %q is not indexed", field)
	}
	return types[f.Type].normalize(value), nil
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
