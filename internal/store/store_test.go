package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Vebat/sealbox/internal/envelope"
)

// A database holds one master key lineage: the blind-index key created on
// first start is wrapped under it. So every test shares one fixed key, and
// tests that need isolation use values unique to the run.
var testMasterKey = sha256.Sum256([]byte("sealbox test master key"))

const actor = "test"

// Tests need a real Postgres. Set SEALBOX_TEST_DATABASE_URL to run them;
// they are skipped otherwise, except in CI where they must run. A local
// database left mid-rotation by a crashed run is reset with
// `docker compose down -v`.
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("SEALBOX_TEST_DATABASE_URL")
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("SEALBOX_TEST_DATABASE_URL must be set in CI: store tests must never be skipped there")
		}
		t.Skip("SEALBOX_TEST_DATABASE_URL not set")
	}
	return url
}

// localEnvelope builds an Envelope over local master keys, current first.
func localEnvelope(t *testing.T, current []byte, previous ...[]byte) *envelope.Envelope {
	t.Helper()
	cur, err := envelope.NewLocal(current)
	if err != nil {
		t.Fatal(err)
	}
	var prev []envelope.Wrapper
	for _, key := range previous {
		w, err := envelope.NewLocal(key)
		if err != nil {
			t.Fatal(err)
		}
		prev = append(prev, w)
	}
	return envelope.New(cur, prev...)
}

func openStore(t *testing.T, current []byte, previous ...[]byte) *Store {
	t.Helper()
	s, err := Open(context.Background(), testDatabaseURL(t), localEnvelope(t, current, previous...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func newStore(t *testing.T) *Store {
	t.Helper()
	return openStore(t, testMasterKey[:])
}

func mustPut(t *testing.T, s *Store, collection, plaintext string, indexed map[string]string) string {
	t.Helper()
	ids, err := s.PutMany(context.Background(), actor, collection, []Item{{Plaintext: []byte(plaintext), Indexed: indexed}})
	if err != nil {
		t.Fatal(err)
	}
	return ids[0]
}

// get reads one object the way the API does.
func get(s *Store, collection, id string) ([]byte, error) {
	found, err := s.GetMany(context.Background(), collection, []string{id})
	if err != nil {
		return nil, err
	}
	plaintext, ok := found[id]
	if !ok {
		return nil, ErrNotFound
	}
	return plaintext, nil
}

// uniqueEmail returns an address no other run has indexed.
func uniqueEmail() string { return newID()[4:16] + "@example.com" }

func auditActions(t *testing.T, s *Store, id string) []string {
	t.Helper()
	rows, err := s.pool.Query(context.Background(), `SELECT action FROM audit_log WHERE object_id = $1 ORDER BY id`, id)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return actions
}

func TestPutGetDelete(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	id := mustPut(t, s, "customers", `{"passport":"4510 123456"}`, nil)

	got, err := get(s, "customers", id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(`{"passport":"4510 123456"}`)) {
		t.Fatalf("got %q", got)
	}

	if err := s.Delete(ctx, actor, "customers", id); err != nil {
		t.Fatal(err)
	}
	if _, err := get(s, "customers", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: expected ErrNotFound, got %v", err)
	}
	if err := s.Delete(ctx, actor, "customers", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: expected ErrNotFound, got %v", err)
	}
	// Create and delete are logged in the same transaction as the write.
	if got := auditActions(t, s, id); !slices.Equal(got, []string{"create", "delete"}) {
		t.Fatalf("audit: %v", got)
	}
}

func TestDeleteShredsCiphertext(t *testing.T) {
	// The row survives delete, as a copy in a backup would. The key does not,
	// so the ciphertext is dead even for code that ignores deleted_at.
	ctx := context.Background()
	s := newStore(t)
	id := mustPut(t, s, "customers", "secret", nil)
	if err := s.Delete(ctx, actor, "customers", id); err != nil {
		t.Fatal(err)
	}

	var sealed envelope.Sealed
	err := s.pool.QueryRow(ctx,
		`SELECT key_id, wrapped_dek, ciphertext FROM objects WHERE id = $1`, id).
		Scan(&sealed.KeyID, &sealed.WrappedDEK, &sealed.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.WrappedDEK != nil {
		t.Fatal("wrapped key must be NULL after delete")
	}
	if len(sealed.Ciphertext) == 0 {
		t.Fatal("ciphertext must survive delete; only the key dies")
	}
	if _, err := s.env.Open(ctx, sealed, aad("customers", id)); !errors.Is(err, envelope.ErrOpen) {
		t.Fatalf("shredded ciphertext opened: %v", err)
	}
}

func TestCiphertextBoundToRow(t *testing.T) {
	// Someone with SQL access moves a ciphertext to another id or collection.
	// It must not open there.
	ctx := context.Background()
	s := newStore(t)

	id := mustPut(t, s, "customers", "secret", nil)
	moved := newID()
	if _, err := s.pool.Exec(ctx, `UPDATE objects SET id = $2 WHERE id = $1`, id, moved); err != nil {
		t.Fatal(err)
	}
	if _, err := get(s, "customers", moved); !errors.Is(err, envelope.ErrOpen) {
		t.Fatalf("moved id: expected ErrOpen, got %v", err)
	}

	id = mustPut(t, s, "customers", "secret", nil)
	if _, err := s.pool.Exec(ctx, `UPDATE objects SET collection = 'employees' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := get(s, "employees", id); !errors.Is(err, envelope.ErrOpen) {
		t.Fatalf("moved collection: expected ErrOpen, got %v", err)
	}
}

func TestIndexKeyIsNotAnObject(t *testing.T) {
	// The blind-index key row copied into objects under a matching collection
	// and id must not open through the object path: service keys and objects
	// live in different AAD namespaces.
	ctx := context.Background()
	s := newStore(t)
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO objects (id, collection, key_id, wrapped_dek, ciphertext)
		 SELECT $1, $2, key_id, wrapped_dek, ciphertext FROM keys WHERE name = $3
		 ON CONFLICT (id) DO NOTHING`, indexKeyName, "keys", indexKeyName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.pool.Exec(ctx, `DELETE FROM objects WHERE id = $1`, indexKeyName) })
	if _, err := get(s, "keys", indexKeyName); !errors.Is(err, envelope.ErrOpen) {
		t.Fatalf("index key readable as an object: %v", err)
	}
}

func TestCollectionIsolation(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	id := mustPut(t, s, "customers", "secret", nil)
	if _, err := get(s, "employees", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get from other collection: expected ErrNotFound, got %v", err)
	}
	if err := s.Delete(ctx, actor, "employees", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete from other collection: expected ErrNotFound, got %v", err)
	}
	if _, err := get(s, "customers", id); err != nil {
		t.Fatalf("object must be untouched: %v", err)
	}
}

func TestGetUnknown(t *testing.T) {
	s := newStore(t)
	if _, err := get(s, "customers", "tok_nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSearch(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	// Values arrive normalized; the caller (schema) owns normalization.
	email, other := uniqueEmail(), uniqueEmail()
	a := mustPut(t, s, "customers", `{"email":"A"}`, map[string]string{"email": email})
	b := mustPut(t, s, "customers", `{"email":"B"}`, map[string]string{"email": email})
	mustPut(t, s, "customers", `{"email":"C"}`, map[string]string{"email": other})

	search := func(collection, field, value string) []string {
		t.Helper()
		ids, err := s.Search(ctx, collection, field, value)
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	if ids := search("customers", "email", email); len(ids) != 2 || !slices.Contains(ids, a) || !slices.Contains(ids, b) {
		t.Fatalf("expected %s and %s, got %v", a, b, ids)
	}
	if ids := search("customers", "email", uniqueEmail()); len(ids) != 0 {
		t.Fatalf("unknown value: got %v", ids)
	}
	if ids := search("employees", "email", email); len(ids) != 0 {
		t.Fatalf("other collection: got %v", ids)
	}
	if ids := search("customers", "phone", email); len(ids) != 0 {
		t.Fatalf("other field: got %v", ids)
	}

	// The database holds a 32-byte keyed hash, never the value.
	var stored []byte
	if err := s.pool.QueryRow(ctx, `SELECT hash FROM blind_index WHERE object_id = $1`, a).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 32 || bytes.Contains(stored, []byte(email[:8])) {
		t.Fatalf("index row leaks the value: %q", stored)
	}

	// Shredding removes the object from the index.
	if err := s.Delete(ctx, actor, "customers", a); err != nil {
		t.Fatal(err)
	}
	if ids := search("customers", "email", email); !slices.Equal(ids, []string{b}) {
		t.Fatalf("after delete: expected [%s], got %v", b, ids)
	}
}

func TestIndexKeySurvivesRestart(t *testing.T) {
	// A second process with the same master key must load the stored index
	// key, not invent a new one, or it would never find existing rows.
	ctx := context.Background()
	email := uniqueEmail()
	first := newStore(t)
	id := mustPut(t, first, "customers", `{}`, map[string]string{"email": email})
	second := newStore(t)
	if ids, err := second.Search(ctx, "customers", "email", email); err != nil || !slices.Equal(ids, []string{id}) {
		t.Fatalf("search from a second store: %v, %v", ids, err)
	}
}

func TestPutManyGetMany(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	email := uniqueEmail()
	ids, err := s.PutMany(ctx, actor, "customers", []Item{
		{Plaintext: []byte(`{"n":"1"}`)},
		{Plaintext: []byte(`{"n":"2"}`), Indexed: map[string]string{"email": email}},
	})
	if err != nil || len(ids) != 2 {
		t.Fatalf("got %v, %v", ids, err)
	}
	if err := s.Delete(ctx, actor, "customers", ids[0]); err != nil {
		t.Fatal(err)
	}

	found, err := s.GetMany(ctx, "customers", []string{ids[0], ids[1], "tok_nope"})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || !bytes.Equal(found[ids[1]], []byte(`{"n":"2"}`)) {
		t.Fatalf("deleted and unknown ids must be absent: %v", found)
	}
	if found, _ := s.GetMany(ctx, "employees", ids); len(found) != 0 {
		t.Fatalf("other collection: %v", found)
	}
	if hits, err := s.Search(ctx, "customers", "email", email); err != nil || !slices.Equal(hits, []string{ids[1]}) {
		t.Fatalf("search after batch: %v, %v", hits, err)
	}
	for _, id := range ids {
		if got := auditActions(t, s, id); got[0] != "create" {
			t.Fatalf("batch create audit for %s: %v", id, got)
		}
	}
}

func TestRotate(t *testing.T) {
	ctx := context.Background()
	old := testMasterKey[:]
	fresh := sha256.Sum256([]byte("sealbox test rotation key"))
	email := uniqueEmail()

	s := newStore(t)
	id := mustPut(t, s, "customers", `{"n":"1"}`, map[string]string{"email": email})
	gone := mustPut(t, s, "customers", "bye", nil)
	if err := s.Delete(ctx, actor, "customers", gone); err != nil {
		t.Fatal(err)
	}
	// A row naming a master key nobody has: rotation must report it and go on.
	orphan := mustPut(t, s, "customers", "orphan", nil)
	if _, err := s.pool.Exec(ctx, `UPDATE objects SET key_id = '0000000000000000' WHERE id = $1`, orphan); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.pool.Exec(ctx, `UPDATE objects SET deleted_at = now(), wrapped_dek = NULL WHERE id = $1`, orphan)
	})

	// Step 1: the new key is current, the old one still loaded.
	both := openStore(t, fresh[:], old)
	// Whatever happens below, leave the database on the shared test key.
	t.Cleanup(func() {
		back, err := Open(ctx, testDatabaseURL(t), localEnvelope(t, old, fresh[:]))
		if err != nil {
			t.Fatal(err)
		}
		defer back.Close()
		if _, _, err := back.Rotate(ctx); err != nil {
			t.Fatal(err)
		}
	})

	// Step 2: re-wrap.
	rotated, skipped, err := both.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rotated < 2 {
		t.Fatalf("expected at least the index key and one object, rotated %d", rotated)
	}
	if skipped < 1 {
		t.Fatalf("the orphan row must be counted as skipped, got %d", skipped)
	}
	var keyID string
	if err := s.pool.QueryRow(ctx, `SELECT key_id FROM objects WHERE id = $1`, id).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	if keyID != envelope.KeyID(fresh[:]) {
		t.Fatalf("object still under key %s", keyID)
	}
	if err := s.pool.QueryRow(ctx, `SELECT key_id FROM objects WHERE id = $1`, orphan).Scan(&keyID); err != nil || keyID != "0000000000000000" {
		t.Fatalf("orphan row must be left alone: %q, %v", keyID, err)
	}
	var dek []byte
	if err := s.pool.QueryRow(ctx, `SELECT wrapped_dek FROM objects WHERE id = $1`, gone).Scan(&dek); err != nil || dek != nil {
		t.Fatalf("a shredded row must stay shredded through rotation: %v, %v", dek, err)
	}
	if again, _, err := both.Rotate(ctx); err != nil || again != 0 {
		t.Fatalf("second rotation must be a no-op: %d, %v", again, err)
	}

	// Step 3: the old key retired. Reads and searches work with the new key alone.
	only := openStore(t, fresh[:])
	if got, err := get(only, "customers", id); err != nil || string(got) != `{"n":"1"}` {
		t.Fatalf("get with new key only: %q, %v", got, err)
	}
	if ids, err := only.Search(ctx, "customers", "email", email); err != nil || !slices.Equal(ids, []string{id}) {
		t.Fatalf("search with new key only: %v, %v", ids, err)
	}
	// And the old key alone no longer opens the store.
	if st, err := Open(ctx, testDatabaseURL(t), localEnvelope(t, old)); err == nil {
		st.Close()
		t.Fatal("old key alone must not open the store after rotation")
	}
}

// versioned stands in for a transit engine: one wrapper id, key versions of
// its own, re-wrap in place. Wrapped keys are "v<version>:<ref>".
type versioned struct {
	version int
	keys    map[string]struct{ dek, aad []byte }
}

func (v *versioned) ID() string { return "mem:versioned" }

func (v *versioned) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	ref := fmt.Sprintf("v%d:%s", v.version, newID())
	v.keys[ref] = struct{ dek, aad []byte }{bytes.Clone(dek), bytes.Clone(aad)}
	return []byte(ref), nil
}

func (v *versioned) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	k, ok := v.keys[string(wrapped)]
	if !ok || !bytes.Equal(k.aad, aad) {
		return nil, envelope.ErrOpen
	}
	return k.dek, nil
}

func (v *versioned) Rewrap(ctx context.Context, wrapped, aad []byte) ([]byte, bool, error) {
	if strings.HasPrefix(string(wrapped), fmt.Sprintf("v%d:", v.version)) {
		return wrapped, false, nil
	}
	dek, err := v.Unwrap(ctx, wrapped, aad)
	if err != nil {
		return nil, false, err
	}
	re, err := v.Wrap(ctx, dek, aad)
	return re, true, err
}

func TestRotateInPlace(t *testing.T) {
	ctx := context.Background()
	local, err := envelope.NewLocal(testMasterKey[:])
	if err != nil {
		t.Fatal(err)
	}
	engine := &versioned{version: 1, keys: map[string]struct{ dek, aad []byte }{}}

	// Move to the key service; leave the database on the test key afterwards.
	s, err := Open(ctx, testDatabaseURL(t), envelope.New(engine, local))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	t.Cleanup(func() {
		back, err := Open(ctx, testDatabaseURL(t), envelope.New(local, engine))
		if err != nil {
			t.Fatal(err)
		}
		defer back.Close()
		if _, _, err := back.Rotate(ctx); err != nil {
			t.Fatal(err)
		}
	})
	if _, _, err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	id := mustPut(t, s, "customers", `{"n":"1"}`, nil)
	wrapped := func() string {
		var w []byte
		if err := s.pool.QueryRow(ctx, `SELECT wrapped_dek FROM objects WHERE id = $1`, id).Scan(&w); err != nil {
			t.Fatal(err)
		}
		return string(w)
	}
	if !strings.HasPrefix(wrapped(), "v1:") {
		t.Fatalf("wrapped under %q", wrapped())
	}
	if n, _, err := s.Rotate(ctx); err != nil || n != 0 {
		t.Fatalf("nothing to move yet: %d, %v", n, err)
	}

	// The service rotated its key: rows keep their key_id, the wrapped bytes move.
	engine.version = 2
	n, _, err := s.Rotate(ctx)
	if err != nil || n < 2 {
		t.Fatalf("expected the index key and the object to move, rotated %d, %v", n, err)
	}
	if !strings.HasPrefix(wrapped(), "v2:") {
		t.Fatalf("still wrapped under %q", wrapped())
	}
	var keyID string
	if err := s.pool.QueryRow(ctx, `SELECT key_id FROM objects WHERE id = $1`, id).Scan(&keyID); err != nil || keyID != engine.ID() {
		t.Fatalf("key_id %q, %v", keyID, err)
	}
	if got, err := get(s, "customers", id); err != nil || string(got) != `{"n":"1"}` {
		t.Fatalf("read after in-place rewrap: %q, %v", got, err)
	}
	if n, _, err := s.Rotate(ctx); err != nil || n != 0 {
		t.Fatalf("second run must be a no-op: %d, %v", n, err)
	}
}

func TestAuditMany(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	client := "test-" + newID() // unique, so rows from other runs stay out of the way
	want := []AuditEntry{
		{Client: client, Action: "reveal_masked", Collection: "customers", ObjectID: newID()},
		{Client: client, Action: "search", Collection: "customers", Field: "email"},
	}
	if err := s.AuditMany(ctx, want); err != nil {
		t.Fatal(err)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT client, action, collection, coalesce(object_id, ''), coalesce(field, '')
		 FROM audit_log WHERE client = $1 ORDER BY id`, client)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowToStructByPos[AuditEntry])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
