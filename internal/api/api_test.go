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
	subjects  map[string]string // collection/id → subject
	audit     []store.AuditEntry
	failAudit bool
}

func newFakeVault() *fakeVault {
	return &fakeVault{objects: map[string][]byte{}, indexed: map[string]map[string]string{}, subjects: map[string]string{}}
}

func (f *fakeVault) Subject(_ context.Context, subject string) ([]store.Ref, error) {
	var refs []store.Ref
	for k, s := range f.subjects {
		if s == subject {
			c, id, _ := strings.Cut(k, "/")
			refs = append(refs, store.Ref{Collection: c, ID: id})
		}
	}
	slices.SortFunc(refs, func(a, b store.Ref) int { return strings.Compare(a.Collection+a.ID, b.Collection+b.ID) })
	return refs, nil
}

func (f *fakeVault) DeleteSubject(ctx context.Context, actor, subject string) ([]store.Ref, error) {
	refs, _ := f.Subject(ctx, subject)
	for _, r := range refs {
		if err := f.Delete(ctx, actor, r.Collection, r.ID); err != nil {
			return nil, err
		}
	}
	return refs, nil
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
		if it.Subject != "" {
			f.subjects[collection+"/"+id] = it.Subject
		}
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
	delete(f.subjects, k)
	f.audit = append(f.audit, store.AuditEntry{Client: actor, Action: "delete", Collection: collection, ObjectID: id})
	return nil
}

func (f *fakeVault) Search(_ context.Context, collection, field, normalized, after string) ([]string, error) {
	var ids []string
	for k, idx := range f.indexed {
		if c, id, _ := strings.Cut(k, "/"); c == collection && idx[field] == normalized && id > after {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	if len(ids) > store.SearchPage {
		ids = ids[:store.SearchPage]
	}
	return ids, nil
}

const (
	adminKey   = "admin-key-0123456789abcdef"
	writerKey  = "writer-key-0123456789abcdef"
	supportKey = "support-key-0123456789abcdef"
	privacyKey = "privacy-key-0123456789abcdef"
	slowKey    = "slow-key-0123456789abcdef"
)

var testClients = []Client{
	{Name: "admin", Key: adminKey, Roles: AllRoles},
	{Name: "checkout", Key: writerKey, Roles: []string{RoleWrite}},
	{Name: "support", Key: supportKey, Roles: []string{RoleReadMasked, RoleSearch}},
	{Name: "privacy", Key: privacyKey, Roles: []string{RoleReadFull, RoleDelete}},
	{Name: "slow", Key: slowKey, Roles: AllRoles, RevealPerSecond: 2},
}

const testSchema = `{"customers": {"fields": {
	"email":    {"type": "email", "index": true},
	"card":     {"type": "card", "fragments": ["last4"]},
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

func TestRateLimit(t *testing.T) {
	srv := newServer(t)
	path := create(t, srv, "customers", `{"email":"ivan@example.com"}`)
	// "slow" may reveal 2 per second with a burst of 10.
	count := func(method, p, body string) (limited int) {
		for range 12 {
			if status, _ := do(t, srv, method, p, body, slowKey); status == http.StatusTooManyRequests {
				limited++
			}
		}
		return limited
	}
	if n := count("GET", path+"?reveal=full", ""); n == 0 {
		t.Error("full reveals: expected the burst to run out")
	}
	if n := count("GET", path, ""); n != 0 {
		t.Errorf("masked reads must not be limited, %d refused", n)
	}
	if status, _ := do(t, srv, "GET", path+"?reveal=full", "", adminKey); status != http.StatusOK {
		t.Errorf("another client must be unaffected: %d", status)
	}

	srv = newServer(t)
	create(t, srv, "customers", `{"email":"ivan@example.com"}`)
	if n := count("POST", "/v1/collections/customers/search", `{"email":"ivan@example.com"}`); n == 0 {
		t.Error("searches: expected the burst to run out")
	}

	// A batch full reveal spends one unit per object returned and is refused whole.
	srv = newServer(t)
	var ids []string
	for range 11 {
		ids = append(ids, idOf(create(t, srv, "customers", `{"email":"a@example.com"}`)))
	}
	body, _ := json.Marshal(map[string]any{"ids": ids, "reveal": "full"})
	if status, resp := do(t, srv, "POST", "/v1/collections/customers/objects/reveal", string(body), slowKey); status != http.StatusTooManyRequests || strings.Contains(resp, "example.com") {
		t.Errorf("batch over budget: %d %s", status, resp)
	}
	body, _ = json.Marshal(map[string]any{"ids": ids, "reveal": "masked"})
	if status, _ := do(t, srv, "POST", "/v1/collections/customers/objects/reveal", string(body), slowKey); status != http.StatusOK {
		t.Errorf("masked batch must not be limited: %d", status)
	}
}

func TestSubject(t *testing.T) {
	srv, vault := newServerWithVault(t)
	a := idOf(create(t, srv, "customers", `{"_subject":"user:42","email":"ivan@example.com"}`))
	b := idOf(create(t, srv, "addresses", `{"_subject":"user:42","city":"x"}`))
	create(t, srv, "customers", `{"_subject":"user:7","email":"other@example.com"}`)

	// The reserved key is not part of the stored object.
	if _, body := do(t, srv, "GET", "/v1/collections/customers/objects/"+a+"?reveal=full", "", adminKey); strings.Contains(body, "_subject") {
		t.Fatalf("stored object carries the subject: %s", body)
	}

	status, body := do(t, srv, "GET", "/v1/subjects/user:42", "", supportKey)
	if status != http.StatusOK || body != fmt.Sprintf(`{"objects":[{"collection":"addresses","id":"%s"},{"collection":"customers","id":"%s"}]}`, b, a) {
		t.Fatalf("list: %d %s", status, body)
	}
	if status, _ := do(t, srv, "DELETE", "/v1/subjects/user:42", "", supportKey); status != http.StatusForbidden {
		t.Errorf("erase without delete role: %d", status)
	}
	status, body = do(t, srv, "DELETE", "/v1/subjects/user:42", "", privacyKey)
	if status != http.StatusOK || !strings.Contains(body, a) || !strings.Contains(body, b) {
		t.Fatalf("erase: %d %s", status, body)
	}
	if status, _ := do(t, srv, "GET", "/v1/collections/customers/objects/"+a, "", adminKey); status != http.StatusNotFound {
		t.Errorf("erased object still readable: %d", status)
	}
	if _, body := do(t, srv, "GET", "/v1/subjects/user:42", "", adminKey); body != `{"objects":[]}` {
		t.Errorf("after erase: %s", body)
	}
	if _, body := do(t, srv, "DELETE", "/v1/subjects/user:42", "", adminKey); body != `{"erased":[]}` {
		t.Errorf("second erase: %s", body)
	}
	if n := len(vault.subjects); n != 1 {
		t.Errorf("the other subject must survive: %d left", n)
	}

	for name, body := range map[string]string{
		"not a string": `{"_subject":42}`,
		"bad chars":    `{"_subject":"a b"}`,
		"too long":     `{"_subject":"` + strings.Repeat("x", 129) + `"}`,
	} {
		if status, _ := do(t, srv, "POST", "/v1/collections/customers/objects", body, adminKey); status != http.StatusBadRequest {
			t.Errorf("%s: %d", name, status)
		}
	}
	if status, _ := do(t, srv, "GET", "/v1/subjects/a%20b", "", adminKey); status != http.StatusBadRequest {
		t.Errorf("invalid subject in path: %d", status)
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
	if status, _ := do(t, srv, "POST", path+"?after=nope", `{"email":"a@b"}`, supportKey); status != http.StatusBadRequest {
		t.Errorf("bad cursor: %d", status)
	}

	// A card is searchable by its last four digits only; the whole number is not indexed.
	c := idOf(create(t, srv, "customers", `{"card":"4111 1111 1111 1111"}`))
	if _, body := do(t, srv, "POST", path, `{"card":"1111"}`, supportKey); body != `{"ids":["`+c+`"]}` {
		t.Errorf("last four: %s", body)
	}
	if status, body := do(t, srv, "POST", path, `{"card":"4111 1111 1111 1111"}`, supportKey); status != http.StatusBadRequest || strings.Contains(body, "4111") {
		t.Errorf("whole card: %d %s", status, body)
	}

	for name, tc := range map[string]struct {
		path, body string
		want       int
	}{
		"not indexed":                     {path, `{"passport":"4510 123456"}`, http.StatusBadRequest},
		"fragment on a field without one": {path, `{"email":"1234"}`, http.StatusOK},
		"unknown field":                   {path, `{"ssn":"123"}`, http.StatusBadRequest},
		"two fields":                      {path, `{"email":"a@b","passport":"x"}`, http.StatusBadRequest},
		"non-string value":                {path, `{"email":5}`, http.StatusBadRequest},
		"not an object":                   {path, `["email"]`, http.StatusBadRequest},
		"undeclared collection":           {"/v1/collections/logs/search", `{"email":"a@b"}`, http.StatusBadRequest},
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

func TestSearchPagination(t *testing.T) {
	srv, vault := newServerWithVault(t)
	items := make([]store.Item, store.SearchPage+3)
	for i := range items {
		items[i] = store.Item{Plaintext: []byte(`{"email":"same@example.com"}`), Indexed: map[string]string{"email": "same@example.com"}}
	}
	if _, err := vault.PutMany(context.Background(), "test", "customers", items); err != nil {
		t.Fatal(err)
	}
	const path = "/v1/collections/customers/search"
	var page struct {
		IDs  []string `json:"ids"`
		Next string   `json:"next"`
	}
	_, body := do(t, srv, "POST", path, `{"email":"same@example.com"}`, adminKey)
	json.Unmarshal([]byte(body), &page)
	if len(page.IDs) != store.SearchPage || page.Next != page.IDs[len(page.IDs)-1] {
		t.Fatalf("first page: %d ids, next %q", len(page.IDs), page.Next)
	}
	first := slices.Clone(page.IDs)
	_, body = do(t, srv, "POST", path+"?after="+page.Next, `{"email":"same@example.com"}`, adminKey)
	page.IDs, page.Next = nil, ""
	json.Unmarshal([]byte(body), &page)
	if len(page.IDs) != 3 || page.Next != "" || slices.Contains(first, page.IDs[0]) {
		t.Fatalf("second page: %d ids, next %q", len(page.IDs), page.Next)
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

		{"checkout", writerKey, "GET", "/v1/subjects/u1", http.StatusForbidden},
		{"checkout", writerKey, "DELETE", "/v1/subjects/u1", http.StatusForbidden},
		{"support", supportKey, "GET", "/v1/subjects/u1", http.StatusOK},
		{"support", supportKey, "DELETE", "/v1/subjects/u1", http.StatusForbidden},
		{"privacy", privacyKey, "DELETE", "/v1/subjects/u1", http.StatusOK},
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
