package envelope

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func newEnvelope(t *testing.T) *Envelope {
	t.Helper()
	key := make([]byte, KeySize)
	rand.Read(key)
	e, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func mustSeal(t *testing.T, e *Envelope, plaintext, aad string) Sealed {
	t.Helper()
	s, err := e.Seal([]byte(plaintext), []byte(aad))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundtrip(t *testing.T) {
	e := newEnvelope(t)
	s := mustSeal(t, e, "4510 123456", "customers/obj-1")
	got, err := e.Open(s, []byte("customers/obj-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("4510 123456")) {
		t.Fatalf("got %q", got)
	}
}

func TestEmptyPlaintext(t *testing.T) {
	e := newEnvelope(t)
	s := mustSeal(t, e, "", "x")
	got, err := e.Open(s, []byte("x"))
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestShredded(t *testing.T) {
	// Deleting the wrapped DEK is the erase operation: the ciphertext stays
	// wherever it was copied (backups, replicas) but can never be opened.
	e := newEnvelope(t)
	s := mustSeal(t, e, "secret", "x")
	s.WrappedDEK = nil
	if _, err := e.Open(s, []byte("x")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	e := newEnvelope(t)
	s := mustSeal(t, e, "secret", "x")
	s.Ciphertext[len(s.Ciphertext)-1] ^= 1
	if _, err := e.Open(s, []byte("x")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestTamperedWrappedDEK(t *testing.T) {
	e := newEnvelope(t)
	s := mustSeal(t, e, "secret", "x")
	s.WrappedDEK[len(s.WrappedDEK)-1] ^= 1
	if _, err := e.Open(s, []byte("x")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestWrongAAD(t *testing.T) {
	// A ciphertext moved to another record must not open there.
	e := newEnvelope(t)
	s := mustSeal(t, e, "secret", "customers/obj-1")
	if _, err := e.Open(s, []byte("customers/obj-2")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestWrongMasterKey(t *testing.T) {
	s := mustSeal(t, newEnvelope(t), "secret", "x")
	if _, err := newEnvelope(t).Open(s, []byte("x")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestFreshKeyPerSeal(t *testing.T) {
	e := newEnvelope(t)
	a := mustSeal(t, e, "same", "x")
	b := mustSeal(t, e, "same", "x")
	if bytes.Equal(a.WrappedDEK, b.WrappedDEK) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("two seals of the same value must not share key material or ciphertext")
	}
}

func TestBadMasterKeySize(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("expected error for 16-byte master key")
	}
}

func TestBlindIndex(t *testing.T) {
	e := newEnvelope(t)
	h := e.BlindIndex("customers", "email", "ivan@example.com")
	if len(h) != 32 {
		t.Fatalf("hash length %d", len(h))
	}
	if !bytes.Equal(h, e.BlindIndex("customers", "email", "ivan@example.com")) {
		t.Fatal("same input must hash the same")
	}
	for name, other := range map[string][]byte{
		"other value":      e.BlindIndex("customers", "email", "ivan@example.org"),
		"other field":      e.BlindIndex("customers", "phone", "ivan@example.com"),
		"other collection": e.BlindIndex("employees", "email", "ivan@example.com"),
		"other master key": newEnvelope(t).BlindIndex("customers", "email", "ivan@example.com"),
	} {
		if bytes.Equal(h, other) {
			t.Errorf("%s: hash must differ", name)
		}
	}
}
