package schema

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const example = `{
  "customers": {"fields": {
    "email":    {"type": "email"},
    "phone":    {"type": "phone"},
    "card":     {"type": "card"},
    "passport": {"type": "string"}
  }}
}`

func mustParse(t *testing.T, doc string) Schema {
	t.Helper()
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func obj(t *testing.T, doc string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParse(t *testing.T) {
	s := mustParse(t, example)
	if s["customers"].Fields["email"].Type != "email" {
		t.Fatalf("parsed: %+v", s)
	}
	for name, doc := range map[string]string{
		"unknown type": `{"c": {"fields": {"x": {"type": "ssn"}}}}`,
		"unknown key":  `{"c": {"fields": {"x": {"type": "string", "mask": "x"}}}}`,
		"not json":     `nope`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadEmptyPath(t *testing.T) {
	s, err := Load("")
	if err != nil || len(s) != 0 {
		t.Fatalf("got %v, %v", s, err)
	}
}

func TestValidate(t *testing.T) {
	s := mustParse(t, example)
	for _, tc := range []struct {
		name, collection, doc string
		ok                    bool
	}{
		{"undeclared collection accepts anything", "logs", `{"anything": 1, "nested": {"a": 1}}`, true},
		{"valid", "customers", `{"email":"ivan@example.com","phone":"+7 921 123-45-67","card":"4111 1111 1111 1111","passport":"4510 123456"}`, true},
		{"subset of fields", "customers", `{"email":"ivan@example.com"}`, true},
		{"unknown field", "customers", `{"ssn":"1"}`, false},
		{"non-string value", "customers", `{"email": 5}`, false},
		{"email without domain", "customers", `{"email":"ivan"}`, false},
		{"email with space", "customers", `{"email":"iv an@example.com"}`, false},
		{"phone too short", "customers", `{"phone":"12"}`, false},
		{"phone with letters", "customers", `{"phone":"+7 921 ABC"}`, false},
		{"card fails luhn", "customers", `{"card":"4111 1111 1111 1112"}`, false},
		{"card with letters", "customers", `{"card":"4111x1111x1111x1111"}`, false},
	} {
		err := s.Validate(tc.collection, obj(t, tc.doc))
		if (err == nil) != tc.ok {
			t.Errorf("%s: ok=%v, err=%v", tc.name, tc.ok, err)
		}
	}
}

func TestValidateErrorNamesFieldNotValue(t *testing.T) {
	s := mustParse(t, example)
	err := s.Validate("customers", obj(t, `{"email":"not-an-address"}`))
	if err == nil || strings.Contains(err.Error(), "not-an-address") || !strings.Contains(err.Error(), "email") {
		t.Fatalf("error must name the field and never the value: %v", err)
	}
}

func TestMask(t *testing.T) {
	s := mustParse(t, example)
	got := s.Mask("customers", obj(t, `{"email":"ivan@example.com","phone":"+7 921 123-45-67","card":"4111 1111 1111 1111","passport":"4510 123456"}`))
	want := map[string]string{
		"email":    "i***@example.com",
		"phone":    "***4567",
		"card":     "**** **** **** 1111",
		"passport": "***",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestMaskHidesEverythingElse(t *testing.T) {
	s := mustParse(t, example)
	// Undeclared collection: every value hidden, whatever its JSON type.
	got := s.Mask("logs", obj(t, `{"a":"a long secret value","n":42,"o":{"x":1},"z":null}`))
	for k, v := range got {
		if v != hidden {
			t.Errorf("%s: got %q", k, v)
		}
	}
	// Declared types on values that never passed validation must not panic.
	got = s.Mask("customers", obj(t, `{"email":"","phone":"x","card":"12"}`))
	for k, v := range got {
		if v != hidden {
			t.Errorf("%s: got %q", k, v)
		}
	}
}

func TestLuhn(t *testing.T) {
	for d, want := range map[string]bool{
		"4111111111111111": true,
		"4111111111111112": false,
		"79927398713":      true,
	} {
		if got := luhn(d); got != want {
			t.Errorf("luhn(%s) = %v", d, got)
		}
	}
}
