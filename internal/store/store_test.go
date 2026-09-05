package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Vebat/sealbox/internal/envelope"
)

// A database holds one master key lineage: the blind-index key created on
// first start is wrapped under it. So every test shares one fixed key, and
// tests that need isolation use values unique to the run.
var testMasterKey = sha256.Sum256([]byte("sealbox test master key"))

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

func openStore(t *testing.T, current []byte, previous ...[]byte) *Store {
	t.Helper()
	env, err := envelope.New(current, previous...)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), testDatabaseURL(t), env)
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
	id, err := s.Put(context.Background(), collection, []byte(plaintext), indexed)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// uniqueEmail returns an address no other run has indexed.
func uniqueEmail() string { return newID()[4:16] + "@example.com" }

func TestPutGetDelete(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	id := mustPut(t, s, "customers", `{"passport":"4510 123456"}`, nil)

	got, err := s.Get(ctx, "customers", id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(`{"passport":"4510 123456"}`)) {
		t.Fatalf("got %q", got)
	}

	if err := s.Delete(ctx, "customers", id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "customers", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: expected ErrNotFound, got %v", err)
	}
	if err := s.Delete(ctx, "customers", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: expected ErrNotFound, got %v", err)
	}
}

func TestDeleteShredsCiphertext(t *testing.T) {
	// The row survives delete, as a copy in a backup would. The key does not,
	// so the ciphertext is dead even for code that ignores deleted_at.
	ctx := context.Background()
	s := newStore(t)
	id := mustPut(t, s, "customers", "secret", nil)
	if err := s.Delete(ctx, "customers", id); err != nil {
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
	if _, err := s.env.Open(sealed, aad("customers", id)); !errors.Is(err, envelope.ErrOpen) {
		t.Fatalf("shredded ciphertext opened: %v", err)
	}
}

func TestCiphertextBoundToRow(t *testing.T) {
	// Someone with SQL access moves a ciphertext to another id. It must not open there.
	ctx := context.Background()
	s := newStore(t)
	id := mustPut(t, s, "customers", "secret", nil)
	moved := newID()
	if _, err := s.pool.Exec(ctx, `UPDATE objects SET id = $2 WHERE id = $1`, id, moved); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "customers", moved); !errors.Is(err, envelope.ErrOpen) {
		t.Fatalf("moved ciphertext: expected ErrOpen, got %v", err)
	}
}

func TestCollectionIsolation(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	id := mustPut(t, s, "customers", "secret", nil)
	if _, err := s.Get(ctx, "employees", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get from other collection: expected ErrNotFound, got %v", err)
	}
	if err := s.Delete(ctx, "employees", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete from other collection: expected ErrNotFound, got %v", err)
	}
	if _, err := s.Get(ctx, "customers", id); err != nil {
		t.Fatalf("object must be untouched: %v", err)
	}
}

func TestGetUnknown(t *testing.T) {
	s := newStore(t)
	if _, err := s.Get(context.Background(), "customers", "tok_nope"); !errors.Is(err, ErrNotFound) {
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
	if err := s.Delete(ctx, "customers", a); err != nil {
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
	ids, err := s.PutMany(ctx, "customers", []Item{
		{Plaintext: []byte(`{"n":"1"}`)},
		{Plaintext: []byte(`{"n":"2"}`), Indexed: map[string]string{"email": email}},
	})
	if err != nil || len(ids) != 2 {
		t.Fatalf("got %v, %v", ids, err)
	}
	if err := s.Delete(ctx, "customers", ids[0]); err != nil {
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
}

func TestRotate(t *testing.T) {
	ctx := context.Background()
	old := testMasterKey[:]
	fresh := sha256.Sum256([]byte("sealbox test rotation key"))
	email := uniqueEmail()

	s := newStore(t)
	id := mustPut(t, s, "customers", `{"n":"1"}`, map[string]string{"email": email})
	gone := mustPut(t, s, "customers", "bye", nil)
	if err := s.Delete(ctx, "customers", gone); err != nil {
		t.Fatal(err)
	}

	// Step 1: the new key is current, the old one still loaded.
	both := openStore(t, fresh[:], old)
	// Whatever happens below, leave the database on the shared test key.
	t.Cleanup(func() {
		env, _ := envelope.New(old, fresh[:])
		back, err := Open(ctx, testDatabaseURL(t), env)
		if err != nil {
			t.Fatal(err)
		}
		defer back.Close()
		if _, _, err := back.Rotate(ctx); err != nil {
			t.Fatal(err)
		}
	})

	// Step 2: re-wrap.
	rotated, _, err := both.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rotated < 2 {
		t.Fatalf("expected at least the index key and one object, rotated %d", rotated)
	}
	var keyID string
	if err := s.pool.QueryRow(ctx, `SELECT key_id FROM objects WHERE id = $1`, id).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	if keyID != envelope.KeyID(fresh[:]) {
		t.Fatalf("object still under key %s", keyID)
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
	if got, err := only.Get(ctx, "customers", id); err != nil || string(got) != `{"n":"1"}` {
		t.Fatalf("get with new key only: %q, %v", got, err)
	}
	if ids, err := only.Search(ctx, "customers", "email", email); err != nil || !slices.Equal(ids, []string{id}) {
		t.Fatalf("search with new key only: %v, %v", ids, err)
	}
	// And the old key alone no longer opens the store.
	env, _ := envelope.New(old)
	if st, err := Open(ctx, testDatabaseURL(t), env); err == nil {
		st.Close()
		t.Fatal("old key alone must not open the store after rotation")
	}
}

func TestAudit(t *testing.T) {
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
