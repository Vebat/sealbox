package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

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

const apiKey = "test-key-0123456789abcdef"

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(New(&fakeVault{objects: map[string][]byte{}}, []byte(apiKey)))
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

func TestLifecycle(t *testing.T) {
	srv := newServer(t)
	const object = `{"email":"ivan@example.com","passport":"4510 123456"}`

	status, body := do(t, srv, "POST", "/v1/collections/customers/objects", object, apiKey)
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil || !strings.HasPrefix(created.ID, "tok_") {
		t.Fatalf("create: bad response %q", body)
	}
	path := "/v1/collections/customers/objects/" + created.ID

	status, body = do(t, srv, "GET", path, "", apiKey)
	if status != http.StatusOK || body != object {
		t.Fatalf("get: %d %s", status, body)
	}

	if status, body = do(t, srv, "DELETE", path, "", apiKey); status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", status, body)
	}
	if status, _ = do(t, srv, "GET", path, "", apiKey); status != http.StatusNotFound {
		t.Fatalf("get after delete: %d", status)
	}
	if status, _ = do(t, srv, "DELETE", path, "", apiKey); status != http.StatusNotFound {
		t.Fatalf("second delete: %d", status)
	}
}

func TestAuth(t *testing.T) {
	srv := newServer(t)
	const path = "/v1/collections/customers/objects/tok_nope"
	for name, key := range map[string]string{
		"missing":  "",
		"wrong":    "wrong-key-0123456789abcdef",
		"prefixed": apiKey + "x",
	} {
		if status, _ := do(t, srv, "GET", path, "", key); status != http.StatusUnauthorized {
			t.Errorf("%s key: expected 401, got %d", name, status)
		}
	}
	// The right key gets past auth and reaches the vault.
	if status, _ := do(t, srv, "GET", path, "", apiKey); status != http.StatusNotFound {
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
		{"empty object", "customers", `{}`, http.StatusCreated},
	} {
		status, body := do(t, srv, "POST", "/v1/collections/"+tc.collection+"/objects", tc.body, apiKey)
		if status != tc.want {
			t.Errorf("%s: expected %d, got %d %s", tc.name, tc.want, status, body)
		}
	}
}
