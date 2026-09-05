package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"testing"

	"github.com/Vebat/sealbox/internal/envelope"
)

// Tests need a real Postgres. Set SEALBOX_TEST_DATABASE_URL to run them;
// they are skipped otherwise.
func newStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("SEALBOX_TEST_DATABASE_URL")
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("SEALBOX_TEST_DATABASE_URL must be set in CI: store tests must never be skipped there")
		}
		t.Skip("SEALBOX_TEST_DATABASE_URL not set")
	}
	key := make([]byte, envelope.KeySize)
	rand.Read(key)
	env, err := envelope.New(key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), url, env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func mustPut(t *testing.T, s *Store, collection, plaintext string) string {
	t.Helper()
	id, err := s.Put(context.Background(), collection, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPutGetDelete(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	id := mustPut(t, s, "customers", `{"passport":"4510 123456"}`)

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
	id := mustPut(t, s, "customers", "secret")
	if err := s.Delete(ctx, "customers", id); err != nil {
		t.Fatal(err)
	}

	var sealed envelope.Sealed
	err := s.pool.QueryRow(ctx,
		`SELECT wrapped_dek, ciphertext FROM objects WHERE id = $1`, id).
		Scan(&sealed.WrappedDEK, &sealed.Ciphertext)
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
	id := mustPut(t, s, "customers", "secret")
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
	id := mustPut(t, s, "customers", "secret")
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
