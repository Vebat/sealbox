package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
)

// Roles are the things a client may be allowed to do. A client that only
// needs masked reads never holds a key that can reveal plaintext.
const (
	RoleWrite      = "write"       // create objects
	RoleDelete     = "delete"      // shred objects
	RoleReadMasked = "read_masked" // read with masks applied
	RoleReadFull   = "read_full"   // read plaintext
	RoleSearch     = "search"      // look up ids by an indexed value
)

// AllRoles is every role, for the development key.
var AllRoles = []string{RoleWrite, RoleDelete, RoleReadMasked, RoleReadFull, RoleSearch}

const minKeyLen = 16

// Client is one holder of an API key.
type Client struct {
	Name  string   `json:"-"`
	Key   string   `json:"key"`
	Roles []string `json:"roles"`
}

func (c Client) has(role string) bool { return slices.Contains(c.Roles, role) }

// LoadClients reads a keys file of the form
//
//	{"checkout": {"key": "...", "roles": ["write"]}, ...}
//
// An empty path yields no clients.
func LoadClients(path string) ([]Client, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseClients(data)
}

// ParseClients decodes a keys document.
func ParseClients(data []byte) ([]Client, error) {
	var byName map[string]Client
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&byName); err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	clients := make([]Client, 0, len(byName))
	for name, c := range byName {
		c.Name = name
		clients = append(clients, c)
	}
	return clients, ValidateClients(clients)
}

// ValidateClients rejects nameless or duplicate names, short or shared keys,
// and unknown roles. Names must be unique because the audit log attributes
// actions by name.
func ValidateClients(clients []Client) error {
	names := map[string]bool{}
	owner := map[string]string{}
	for _, c := range clients {
		if c.Name == "" {
			return errors.New("keys: client without a name")
		}
		if names[c.Name] {
			return fmt.Errorf("keys: two clients named %s", c.Name)
		}
		names[c.Name] = true
		if len(c.Key) < minKeyLen {
			return fmt.Errorf("keys: %s: key must be at least %d characters", c.Name, minKeyLen)
		}
		if other, dup := owner[c.Key]; dup {
			return fmt.Errorf("keys: %s and %s share a key", other, c.Name)
		}
		owner[c.Key] = c.Name
		if len(c.Roles) == 0 {
			return fmt.Errorf("keys: %s: no roles", c.Name)
		}
		for _, r := range c.Roles {
			if !slices.Contains(AllRoles, r) {
				return fmt.Errorf("keys: %s: unknown role %q", c.Name, r)
			}
		}
	}
	return nil
}

// authenticate finds the client presenting the bearer key. Both sides are
// hashed first, so the constant-time comparison does not depend on the
// key's length, and every client is compared, so timing does not say which
// key was close or where it sits in the list.
func authenticate(clients []Client, header string) (Client, bool) {
	key, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return Client{}, false
	}
	got := sha256.Sum256([]byte(key))
	var found Client
	matched := false
	for _, c := range clients {
		want := sha256.Sum256([]byte(c.Key))
		if subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
			found, matched = c, true
		}
	}
	return found, matched
}

type clientKey struct{}

func requireKey(clients []Client, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := authenticate(clients, r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientKey{}, c)))
	})
}

// clientFrom returns the authenticated client stored by requireKey.
func clientFrom(r *http.Request) Client {
	c, _ := r.Context().Value(clientKey{}).(Client)
	return c
}

// require answers 403 and returns false when the caller lacks role.
func require(w http.ResponseWriter, r *http.Request, role string) bool {
	if clientFrom(r).has(role) {
		return true
	}
	writeError(w, http.StatusForbidden, "role "+role+" required")
	return false
}
