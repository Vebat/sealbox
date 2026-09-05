// Package schema declares what a collection may hold and how each field looks
// when revealed masked. Collections without a declaration accept any JSON
// object, and every field in them is treated as type "string".
package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

// Schema maps a collection name to its declaration.
type Schema map[string]Collection

// Collection lists the fields an object may have. Every field is optional;
// undeclared ones are rejected.
type Collection struct {
	Fields map[string]Field `json:"fields"`
}

// Field is one declared field. Type is one of the names in types. Index
// enables exact-match search on the whole value; only types with a normal
// form (email, phone, card) can be indexed. Fragments lists parts of the
// value that are searchable on their own; the only fragment so far is
// "last4", the last four digits of a phone or card.
type Field struct {
	Type      string   `json:"type"`
	Index     bool     `json:"index"`
	Fragments []string `json:"fragments"`
}

// fragmentLast4 indexes the last four digits under "<field>#last4".
const fragmentLast4 = "last4"

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
			for _, fr := range f.Fragments {
				if fr != fragmentLast4 {
					return nil, fmt.Errorf("schema: %s.%s: unknown fragment %q", cname, fname, fr)
				}
				if f.Type != "phone" && f.Type != "card" {
					return nil, fmt.Errorf("schema: %s.%s: fragment %q needs a phone or card field", cname, fname, fr)
				}
			}
		}
	}
	return s, nil
}

// Indexed returns the normalized values to put in the blind index, keyed by
// index name: the field name for a whole value, "<field>#last4" for a
// fragment. The object must have passed Validate.
func (s Schema) Indexed(collection string, object map[string]json.RawMessage) map[string]string {
	var out map[string]string
	for name, f := range s[collection].Fields {
		raw, present := object[name]
		if !present || (!f.Index && len(f.Fragments) == 0) {
			continue
		}
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}
		normalized := types[f.Type].normalize(v)
		if out == nil {
			out = map[string]string{}
		}
		if f.Index {
			out[name] = normalized
		}
		if slices.Contains(f.Fragments, fragmentLast4) && len(normalized) >= 4 {
			out[name+"#"+fragmentLast4] = normalized[len(normalized)-4:]
		}
	}
	return out
}

// Normalize prepares a search value for a field and says which index to
// look in. Exactly four digits on a field with the last4 fragment search
// that fragment; anything else searches the whole value. The error names
// the field, never the value.
func (s Schema) Normalize(collection, field, value string) (index, normalized string, err error) {
	f, ok := s[collection].Fields[field]
	if !ok || (!f.Index && len(f.Fragments) == 0) {
		return "", "", fmt.Errorf("field %q is not indexed", field)
	}
	normalized = types[f.Type].normalize(value)
	if len(normalized) == 4 && slices.Contains(f.Fragments, fragmentLast4) {
		return field + "#" + fragmentLast4, normalized, nil
	}
	if !f.Index {
		return "", "", fmt.Errorf("field %q is searchable by its last four digits only", field)
	}
	return field, normalized, nil
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
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &v) != nil {
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
