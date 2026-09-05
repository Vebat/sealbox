package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Vebat/sealbox/internal/schema"
	"github.com/Vebat/sealbox/internal/store"
)

// fakeVault keeps plaintext and normalized index values in memory and records
// audit entries the way the store does: create and delete inside the write,
// reveals and searches through AuditMany. The real store is tested against
// Postgres in internal/store; here only the HTTP layer is under test.
type fakeVault struct {
	objects   map[string][]byte
	indexed   map[string]map[string]string
	audit     []store.AuditEntry
	failAudit bool
}

func newFakeVault() *fakeVault {
	return &fakeVault{objects: map[string][]byte{}, indexed: map[string]map[string]string{}}
}

func (f *fakeVault) AuditMany(_ context.Context, entries []store.AuditEntry) error {
	if f.failAudit {
		return errors.New("audit log unavailable")
	}
	f.audit = append(f.audit, entries...)
	return nil
}

func (f *fakeVault) PutMany(ctx context.Context, actor, collection string, items []store.Item) ([]string, error) {
	if f.failAudit {
		return nil, errors.New("audit log unavailable")
	}
	ids := make([]string, 0, len(items))
	for _, it := range items {
		id := "tok_" + fmt.Sprintf("%032x", len(f.objects)+1)
		f.objects[collection+"/"+id] = it.Plaintext
		f.indexed[collection+"/"+id] = it.Indexed
		f.audit = append(f.audit, store.AuditEntry{Client: actor, Action: "create", Collection: collection, ObjectID: id})
		ids = append(ids, id)
	}
	return ids, nil
}

func (f *fakeVault) GetMany(_ context.Context, collection string, ids []string) (map[string][]byte, error) {
	found := map[string][]byte{}
	for _, id := range ids {
		if p, ok := f.objects[collection+"/"+id]; ok {
			found[id] = p
		}
	}
	return found, nil
}

func (f *fakeVault) Delete(_ context.Context, actor, collection, id string) error {
	k := collection + "/" + id
	if _, ok := f.objects[k]; !ok {
		return store.ErrNotFound
	}
	if f.failAudit {
		return errors.New("audit log unavailable")
	}
	delete(f.objects, k)
	delete(f.indexed, k)
	f.audit = append(f.audit, store.AuditEntry{Client: actor, Action: "delete", Collection: collection, ObjectID: id})
	return nil
}

func (f *fakeVault) Search(_ context.Context, collection, field, normalized string) ([]string, error) {
	var ids []string
	for k, idx := range f.indexed {
		if c, id, _ := strings.Cut(k, "/"); c == collection && idx[field] == normalized {
			ids = append(ids, id)
		}
	}
	return ids, nil
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
	{Name: "support", Key: supportKey, Roles: []string{RoleReadMasked, RoleSearch}},
	{Name: "privacy", Key: privacyKey, Roles: []string{RoleReadFull, RoleDelete}},
}

const testSchema = `{"customers": {"fields": {
	"email":    {"type": "email", "index": true},
	"card":     {"type": "card"},
	"passport": {"type": "string"}
}}}`

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := newServerWithVault(t)
	return srv
}

func newServerWithVault(t *testing.T) (*httptest.Server, *fakeVault) {
	t.Helper()
	s, err := schema.Parse([]byte(testSchema))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateClients(testClients); err != nil {
		t.Fatal(err)
	}
	vault := newFakeVault()
	srv := httptest.NewServer(New(vault, s, testClients))
	t.Cleanup(srv.Close)
	return srv, vault
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
	if err := json.Unmarshal([]byte(body), &created); err != nil || !idRe.MatchString(created.ID) {
		t.Fatalf("create: bad response %q", body)
	}
	return "/v1/collections/" + collection + "/objects/" + created.ID
}

func idOf(path string) string { return path[strings.LastIndex(path, "/")+1:] }

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

func TestStoredObjectIsCanonical(t *testing.T) {
	// A duplicate key keeps only the value that was validated; whitespace and
	// key order are normalized, so the stored object is exactly what a
	// last-wins JSON parser saw. Malformed ids are simply not found.
	srv := newServer(t)
	path := create(t, srv, "customers", "{ \"passport\": \"x\" , \"card\":\"garbage\",\n\"card\": \"4111 1111 1111 1111\" }")
	if _, body := do(t, srv, "GET", path+"?reveal=full", "", adminKey); body != `{"card":"4111 1111 1111 1111","passport":"x"}` {
		t.Fatalf("stored object: %s", body)
	}
	for _, id := range []string{"tok_zz", "blind-index", "tok_" + strings.Repeat("0", 31)} {
		if status, _ := do(t, srv, "GET", "/v1/collections/customers/objects/"+id, "", adminKey); status != http.StatusNotFound {
			t.Errorf("id %q: expected 404, got %d", id, status)
		}
	}
}

func TestSearch(t *testing.T) {
	srv := newServer(t)
	a := idOf(create(t, srv, "customers", `{"email":"Ivan@Example.com"}`))
	b := idOf(create(t, srv, "customers", `{"email":"ivan@example.com"}`))
	create(t, srv, "customers", `{"email":"other@example.com"}`)

	const path = "/v1/collections/customers/search"
	status, body := do(t, srv, "POST", path, `{"email":" IVAN@example.com"}`, supportKey)
	if status != http.StatusOK {
		t.Fatalf("search: %d %s", status, body)
	}
	var got struct {
		IDs []string `json:"ids"`
	}
	json.Unmarshal([]byte(body), &got)
	if len(got.IDs) != 2 || !strings.Contains(body, a) || !strings.Contains(body, b) {
		t.Fatalf("search: expected %s and %s, got %s", a, b, body)
	}

	if _, body := do(t, srv, "POST", path, `{"email":"nobody@example.com"}`, supportKey); body != `{"ids":[]}` {
		t.Errorf("no match: got %s", body)
	}

	for name, tc := range map[string]struct {
		path, body string
		want       int
	}{
		"not indexed":           {path, `{"passport":"4510 123456"}`, http.StatusBadRequest},
		"unknown field":         {path, `{"ssn":"123"}`, http.StatusBadRequest},
		"two fields":            {path, `{"email":"a@b","passport":"x"}`, http.StatusBadRequest},
		"non-string value":      {path, `{"email":5}`, http.StatusBadRequest},
		"not an object":         {path, `["email"]`, http.StatusBadRequest},
		"undeclared collection": {"/v1/collections/logs/search", `{"email":"a@b"}`, http.StatusBadRequest},
	} {
		status, body := do(t, srv, "POST", tc.path, tc.body, supportKey)
		if status != tc.want {
			t.Errorf("%s: expected %d, got %d %s", name, tc.want, status, body)
		}
		if strings.Contains(body, "4510") || strings.Contains(body, "123") {
			t.Errorf("%s: response echoes submitted data: %s", name, body)
		}
	}
}

func TestBatch(t *testing.T) {
	srv, vault := newServerWithVault(t)
	const batchPath = "/v1/collections/customers/objects/batch"
	const revealPath = "/v1/collections/customers/objects/reveal"

	// One bad object fails the whole batch, named by position, value not echoed.
	status, body := do(t, srv, "POST", batchPath, `{"objects":[{"email":"a@example.com"},{"email":"not-an-address"}]}`, adminKey)
	if status != http.StatusBadRequest || !strings.Contains(body, "objects[1]") || strings.Contains(body, "not-an-address") {
		t.Fatalf("bad batch: %d %s", status, body)
	}
	if len(vault.objects) != 0 || len(vault.audit) != 0 {
		t.Fatal("a rejected batch must store and log nothing")
	}

	status, body = do(t, srv, "POST", batchPath, `{"objects":[{"email":"a@example.com"},{"email":"b@example.com"},{"passport":"1"}]}`, writerKey)
	if status != http.StatusCreated {
		t.Fatalf("batch create: %d %s", status, body)
	}
	var created struct {
		IDs []string `json:"ids"`
	}
	json.Unmarshal([]byte(body), &created)
	if len(created.IDs) != 3 {
		t.Fatalf("batch create: %s", body)
	}
	for i, id := range created.IDs {
		if want := (store.AuditEntry{Client: "checkout", Action: "create", Collection: "customers", ObjectID: id}); vault.audit[i] != want {
			t.Errorf("audit[%d] = %+v, want %+v", i, vault.audit[i], want)
		}
	}

	// Masked reveal of two known ids, one unknown, one duplicate.
	ids := created.IDs
	status, body = do(t, srv, "POST", revealPath, fmt.Sprintf(`{"ids":["%s","%s","tok_nope","%s"]}`, ids[0], ids[1], ids[0]), supportKey)
	if status != http.StatusOK {
		t.Fatalf("batch reveal: %d %s", status, body)
	}
	var revealed struct {
		Objects map[string]map[string]string `json:"objects"`
		Missing []string                     `json:"missing"`
	}
	json.Unmarshal([]byte(body), &revealed)
	if len(revealed.Objects) != 2 || revealed.Objects[ids[0]]["email"] != "a***@example.com" || !slices.Equal(revealed.Missing, []string{"tok_nope"}) {
		t.Fatalf("batch reveal: %s", body)
	}
	if got := vault.audit[3:]; !slices.Equal(got, []store.AuditEntry{
		{Client: "support", Action: "reveal_masked", Collection: "customers", ObjectID: ids[0]},
		{Client: "support", Action: "reveal_masked", Collection: "customers", ObjectID: ids[1]},
	}) {
		t.Fatalf("reveal audit: %+v", got)
	}

	// Full reveal needs read_full and returns the stored object.
	if status, _ := do(t, srv, "POST", revealPath, `{"ids":["x"],"reveal":"full"}`, supportKey); status != http.StatusForbidden {
		t.Errorf("full reveal without role: %d", status)
	}
	status, body = do(t, srv, "POST", revealPath, fmt.Sprintf(`{"ids":["%s"],"reveal":"full"}`, ids[2]), privacyKey)
	if status != http.StatusOK || !strings.Contains(body, `"passport":"1"`) {
		t.Errorf("full reveal: %d %s", status, body)
	}

	for name, tc := range map[string]struct{ path, body string }{
		"empty batch":      {batchPath, `{"objects":[]}`},
		"batch not object": {batchPath, `[{"email":"a@b"}]`},
		"too many objects": {batchPath, `{"objects":[` + strings.Repeat(`{},`, maxBatch) + `{}]}`},
		"empty ids":        {revealPath, `{"ids":[]}`},
		"bad reveal":       {revealPath, `{"ids":["x"],"reveal":"everything"}`},
		"too many ids":     {revealPath, `{"ids":[` + strings.Repeat(`"x",`, maxBatch) + `"x"]}`},
	} {
		if status, body := do(t, srv, "POST", tc.path, tc.body, adminKey); status != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d %s", name, status, body)
		}
	}
}

func TestAudit(t *testing.T) {
	srv, vault := newServerWithVault(t)
	path := create(t, srv, "customers", `{"email":"ivan@example.com"}`)
	id := idOf(path)
	do(t, srv, "GET", path, "", supportKey)
	do(t, srv, "GET", path+"?reveal=full", "", privacyKey)
	do(t, srv, "POST", "/v1/collections/customers/search", `{"email":"ivan@example.com"}`, supportKey)
	do(t, srv, "DELETE", path, "", privacyKey)

	want := []store.AuditEntry{
		{Client: "admin", Action: "create", Collection: "customers", ObjectID: id},
		{Client: "support", Action: "reveal_masked", Collection: "customers", ObjectID: id},
		{Client: "privacy", Action: "reveal_full", Collection: "customers", ObjectID: id},
		{Client: "support", Action: "search", Collection: "customers", Field: "email"},
		{Client: "privacy", Action: "delete", Collection: "customers", ObjectID: id},
	}
	if !slices.Equal(vault.audit, want) {
		t.Fatalf("audit log:\n got %+v\nwant %+v", vault.audit, want)
	}

	// Refused and failed requests leave no trace: nothing was revealed.
	do(t, srv, "GET", path+"?reveal=full", "", supportKey) // 403
	do(t, srv, "GET", path, "", adminKey)                  // 404, deleted
	do(t, srv, "POST", "/v1/collections/customers/search", `{"passport":"x"}`, supportKey)
	if len(vault.audit) != len(want) {
		t.Fatalf("refused requests were logged: %+v", vault.audit[len(want):])
	}
}

func TestNoRevealWithoutAudit(t *testing.T) {
	srv, vault := newServerWithVault(t)
	path := create(t, srv, "customers", `{"email":"ivan@example.com"}`)
	vault.failAudit = true

	for name, tc := range map[string]struct {
		method, path, body, leak string
	}{
		"full get":     {"GET", path + "?reveal=full", "", "ivan"},
		"masked get":   {"GET", path, "", "example.com"},
		"search":       {"POST", "/v1/collections/customers/search", `{"email":"ivan@example.com"}`, "tok_"},
		"batch reveal": {"POST", "/v1/collections/customers/objects/reveal", `{"ids":["` + idOf(path) + `"],"reveal":"full"}`, "ivan"},
	} {
		status, body := do(t, srv, tc.method, tc.path, tc.body, adminKey)
		if status != http.StatusInternalServerError || strings.Contains(body, tc.leak) {
			t.Errorf("%s without audit: %d %s", name, status, body)
		}
	}
}

func TestRoles(t *testing.T) {
	srv := newServer(t)
	const object = `{"email":"ivan@example.com"}`
	path := create(t, srv, "customers", object)
	const nowhere = "/v1/collections/customers/objects/tok_00000000000000000000000000000000"

	for _, tc := range []struct {
		who, key, method, path string
		want                   int
	}{
		{"checkout", writerKey, "POST", "/v1/collections/customers/objects", http.StatusCreated},
		{"checkout", writerKey, "GET", path, http.StatusForbidden},
		{"checkout", writerKey, "GET", path + "?reveal=full", http.StatusForbidden},
		{"checkout", writerKey, "DELETE", path, http.StatusForbidden},
		{"checkout", writerKey, "DELETE", nowhere, http.StatusForbidden},
		{"checkout", writerKey, "POST", "/v1/collections/customers/search", http.StatusForbidden},

		{"support", supportKey, "POST", "/v1/collections/customers/objects", http.StatusForbidden},
		{"support", supportKey, "GET", path, http.StatusOK},
		{"support", supportKey, "GET", path + "?reveal=full", http.StatusForbidden},
		{"support", supportKey, "DELETE", path, http.StatusForbidden},
		{"support", supportKey, "POST", "/v1/collections/customers/search", http.StatusOK},
		// Role is checked before existence: no 404 oracle for the unprivileged.
		{"support", supportKey, "GET", nowhere + "?reveal=full", http.StatusForbidden},

		{"privacy", privacyKey, "POST", "/v1/collections/customers/objects", http.StatusForbidden},
		{"privacy", privacyKey, "GET", path, http.StatusForbidden},
		{"privacy", privacyKey, "POST", "/v1/collections/customers/search", http.StatusForbidden},
		{"privacy", privacyKey, "GET", path + "?reveal=full", http.StatusOK},
		{"privacy", privacyKey, "DELETE", nowhere, http.StatusNotFound},
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
	const path = "/v1/collections/customers/objects/tok_00000000000000000000000000000000"
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
		{"null string field", "customers", `{"passport":null}`, http.StatusBadRequest},
		{"invalid utf-8", "customers", "{\"passport\":\"\xff\"}", http.StatusBadRequest},
		{"invalid utf-8, free-form", "logs", "{\"n\":\"\xff\"}", http.StatusBadRequest},
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
