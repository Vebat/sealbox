package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Vebat/sealbox/internal/schema"
	"github.com/Vebat/sealbox/internal/store"
)

// fakeVault keeps plaintext in a map. The real store is tested against
// Postgres in internal/store; here only the HTTP layer is under test.
type fakeVault struct{ objects map[string][]byte }

func (f *fakeVault) Put(_ context.Context, collection string, plaintext []byte) (string, error) {
	id := "tok_" + strconv.Itoa(len(f.objects)+1)
	f.objects[collection+"/"+id] = plaintext
	return id, nil
}

func (f *fakeVault) Get(_ context.Context, collection, id string) ([]byte, error) {
	p, ok := f.objects[collection+"/"+id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return p, nil
}

func (f *fakeVault) Delete(_ context.Context, collection, id string) error {
	k := collection + "/" + id
	if _, ok := f.objects[k]; !ok {
		return store.ErrNotFound
	}
	delete(f.objects, k)
	return nil
}

const (
	adminKey   = "admin-key-0123456789abcdef"
	writerKey  = "writer-key-0123456789abcdef"
	supportKey = "support-key-0123456789abcdef"
	privacyKey = "privacy-key-0123456789abcdef"
)

var testClients = []Client{
	{Name: "admin", Key: adminKey, Roles: AllRoles},
	{Name: "checkout", Key: writerKey, Roles: []string{RoleWrite}},
	{Name: "support", Key: supportKey, Roles: []string{RoleReadMasked}},
	{Name: "privacy", Key: privacyKey, Roles: []string{RoleReadFull, RoleDelete}},
}

const testSchema = `{"customers": {"fields": {
	"email":    {"type": "email"},
	"card":     {"type": "card"},
	"passport": {"type": "string"}
}}}`

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	s, err := schema.Parse([]byte(testSchema))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateClients(testClients); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(&fakeVault{objects: map[string][]byte{}}, s, testClients))
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, srv *httptest.Server, method, path, body, key string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func create(t *testing.T, srv *httptest.Server, collection, object string) string {
	t.Helper()
	status, body := do(t, srv, "POST", "/v1/collections/"+collection+"/objects", object, adminKey)
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil || !strings.HasPrefix(created.ID, "tok_") {
		t.Fatalf("create: bad response %q", body)
	}
	return "/v1/collections/" + collection + "/objects/" + created.ID
}

func TestLifecycle(t *testing.T) {
	srv := newServer(t)
	const object = `{"email":"ivan@example.com","passport":"4510 123456"}`
	path := create(t, srv, "customers", object)

	// Reads are masked unless the caller asks for everything.
	status, body := do(t, srv, "GET", path, "", adminKey)
	if status != http.StatusOK {
		t.Fatalf("get masked: %d %s", status, body)
	}
	var masked map[string]string
	json.Unmarshal([]byte(body), &masked)
	if want := map[string]string{"email": "i***@example.com", "passport": "***"}; !reflect.DeepEqual(masked, want) {
		t.Fatalf("get masked: got %v, want %v", masked, want)
	}

	status, body = do(t, srv, "GET", path+"?reveal=full", "", adminKey)
	if status != http.StatusOK || body != object {
		t.Fatalf("get full: %d %s", status, body)
	}

	if status, body = do(t, srv, "DELETE", path, "", adminKey); status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", status, body)
	}
	if status, _ = do(t, srv, "GET", path, "", adminKey); status != http.StatusNotFound {
		t.Fatalf("get after delete: %d", status)
	}
	if status, _ = do(t, srv, "DELETE", path, "", adminKey); status != http.StatusNotFound {
		t.Fatalf("second delete: %d", status)
	}
}

func TestRoles(t *testing.T) {
	srv := newServer(t)
	const object = `{"email":"ivan@example.com"}`
	path := create(t, srv, "customers", object)

	for _, tc := range []struct {
		who, key, method, path string
		want                   int
	}{
		{"checkout", writerKey, "POST", "/v1/collections/customers/objects", http.StatusCreated},
		{"checkout", writerKey, "GET", path, http.StatusForbidden},
		{"checkout", writerKey, "GET", path + "?reveal=full", http.StatusForbidden},
		{"checkout", writerKey, "DELETE", path, http.StatusForbidden},

		{"support", supportKey, "POST", "/v1/collections/customers/objects", http.StatusForbidden},
		{"support", supportKey, "GET", path, http.StatusOK},
		{"support", supportKey, "GET", path + "?reveal=full", http.StatusForbidden},
		{"support", supportKey, "DELETE", path, http.StatusForbidden},
		// Role is checked before existence: no 404 oracle for the unprivileged.
		{"support", supportKey, "GET", "/v1/collections/customers/objects/tok_nope?reveal=full", http.StatusForbidden},

		{"privacy", privacyKey, "POST", "/v1/collections/customers/objects", http.StatusForbidden},
		{"privacy", privacyKey, "GET", path, http.StatusForbidden},
		{"privacy", privacyKey, "GET", path + "?reveal=full", http.StatusOK},
		{"privacy", privacyKey, "DELETE", path, http.StatusNoContent},
	} {
		status, body := do(t, srv, tc.method, tc.path, object, tc.key)
		if status != tc.want {
			t.Errorf("%s %s %s: expected %d, got %d %s", tc.who, tc.method, tc.path, tc.want, status, body)
		}
	}
}

func TestRevealParam(t *testing.T) {
	srv := newServer(t)
	path := create(t, srv, "customers", `{"card":"4111 1111 1111 1111"}`)
	if status, _ := do(t, srv, "GET", path+"?reveal=everything", "", adminKey); status != http.StatusBadRequest {
		t.Errorf("bad reveal value: expected 400, got %d", status)
	}
	_, body := do(t, srv, "GET", path+"?reveal=masked", "", adminKey)
	if !strings.Contains(body, `"**** **** **** 1111"`) {
		t.Errorf("masked card: got %s", body)
	}
	// Undeclared collections are free-form and fully hidden when masked.
	path = create(t, srv, "logs", `{"note":"anything goes","n":1}`)
	_, body = do(t, srv, "GET", path, "", adminKey)
	if body != `{"n":"***","note":"***"}` {
		t.Errorf("undeclared collection masked: got %s", body)
	}
}

func TestAuth(t *testing.T) {
	srv := newServer(t)
	const path = "/v1/collections/customers/objects/tok_nope"
	for name, key := range map[string]string{
		"missing":  "",
		"wrong":    "wrong-key-0123456789abcdef",
		"prefixed": adminKey + "x",
	} {
		if status, _ := do(t, srv, "GET", path, "", key); status != http.StatusUnauthorized {
			t.Errorf("%s key: expected 401, got %d", name, status)
		}
	}
	// The right key gets past auth and reaches the vault.
	if status, _ := do(t, srv, "GET", path, "", adminKey); status != http.StatusNotFound {
		t.Errorf("valid key: expected 404, got %d", status)
	}
}

func TestCreateValidation(t *testing.T) {
	srv := newServer(t)
	for _, tc := range []struct {
		name, collection, body string
		want                   int
	}{
		{"not json", "customers", `not json`, http.StatusBadRequest},
		{"array", "customers", `[1,2]`, http.StatusBadRequest},
		{"null", "customers", `null`, http.StatusBadRequest},
		{"string", "customers", `"x"`, http.StatusBadRequest},
		{"bad collection", "Customers!", `{}`, http.StatusBadRequest},
		{"too big", "customers", `{"x":"` + strings.Repeat("x", maxBody) + `"}`, http.StatusRequestEntityTooLarge},
		{"unknown field", "customers", `{"ssn":"123"}`, http.StatusBadRequest},
		{"invalid email", "customers", `{"email":"nope"}`, http.StatusBadRequest},
		{"non-string field", "customers", `{"passport":123}`, http.StatusBadRequest},
		{"empty object", "customers", `{}`, http.StatusCreated},
		{"undeclared collection, any shape", "logs", `{"n":1,"o":{"x":[1]}}`, http.StatusCreated},
	} {
		status, body := do(t, srv, "POST", "/v1/collections/"+tc.collection+"/objects", tc.body, adminKey)
		if status != tc.want {
			t.Errorf("%s: expected %d, got %d %s", tc.name, tc.want, status, body)
		}
		if strings.Contains(body, "nope") || strings.Contains(body, "123") {
			t.Errorf("%s: response echoes submitted data: %s", tc.name, body)
		}
	}
}
