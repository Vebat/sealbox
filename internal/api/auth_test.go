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
	byName := map[string]Client{}
	for _, c := range clients {
		byName[c.Name] = c
	}
	if len(byName) != 2 || !byName["support"].has(RoleReadMasked) || byName["support"].has(RoleReadFull) || !byName["checkout"].has(RoleWrite) {
		t.Fatalf("got %+v", clients)
	}

	for name, doc := range map[string]string{
		"short key":     `{"a": {"key": "short", "roles": ["write"]}}`,
		"unknown role":  `{"a": {"key": "0123456789abcdef", "roles": ["admin"]}}`,
		"no roles":      `{"a": {"key": "0123456789abcdef", "roles": []}}`,
		"duplicate key": `{"a": {"key": "0123456789abcdef", "roles": ["write"]}, "b": {"key": "0123456789abcdef", "roles": ["write"]}}`,
		"unknown field": `{"a": {"key": "0123456789abcdef", "roles": ["write"], "admin": true}}`,
		"negative rate": `{"a": {"key": "0123456789abcdef", "roles": ["write"], "reveal_per_second": -1}}`,
		"not json":      `nope`,
	} {
		if _, err := ParseClients([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestValidateClientsRejectsDuplicateNames(t *testing.T) {
	// The development key becomes a client named "default"; a keys file must
	// not be able to shadow it, or audit rows become unattributable.
	err := ValidateClients([]Client{
		{Name: "default", Key: "0123456789abcdef", Roles: []string{RoleReadMasked}},
		{Name: "default", Key: "fedcba9876543210", Roles: AllRoles},
	})
	if err == nil {
		t.Fatal("expected error")
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
