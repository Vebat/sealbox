package api

import "testing"

func TestParseClients(t *testing.T) {
	clients, err := ParseClients([]byte(`{
		"support":  {"key": "0123456789abcdef", "roles": ["read_masked"]},
		"checkout": {"key": "fedcba9876543210", "roles": ["write"]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 || clients[0].Name != "checkout" || clients[1].Name != "support" {
		t.Fatalf("got %+v", clients)
	}
	if !clients[1].has(RoleReadMasked) || clients[1].has(RoleReadFull) {
		t.Fatalf("support roles: %v", clients[1].Roles)
	}

	for name, doc := range map[string]string{
		"short key":     `{"a": {"key": "short", "roles": ["write"]}}`,
		"unknown role":  `{"a": {"key": "0123456789abcdef", "roles": ["admin"]}}`,
		"no roles":      `{"a": {"key": "0123456789abcdef", "roles": []}}`,
		"duplicate key": `{"a": {"key": "0123456789abcdef", "roles": ["write"]}, "b": {"key": "0123456789abcdef", "roles": ["write"]}}`,
		"unknown field": `{"a": {"key": "0123456789abcdef", "roles": ["write"], "admin": true}}`,
		"not json":      `nope`,
	} {
		if _, err := ParseClients([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestAuthenticate(t *testing.T) {
	clients := []Client{
		{Name: "a", Key: "0123456789abcdef", Roles: AllRoles},
		{Name: "b", Key: "fedcba9876543210", Roles: []string{RoleWrite}},
	}
	for header, want := range map[string]string{
		"Bearer 0123456789abcdef": "a",
		"Bearer fedcba9876543210": "b",
		"Bearer 0123456789abcdeF": "",
		"Bearer 0123456789abcde":  "",
		"Basic 0123456789abcdef":  "",
		"":                        "",
	} {
		c, ok := authenticate(clients, header)
		if ok != (want != "") || c.Name != want {
			t.Errorf("%q: got %q ok=%v, want %q", header, c.Name, ok, want)
		}
	}
}
