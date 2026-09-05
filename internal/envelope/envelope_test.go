package envelope

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	rand.Read(key)
	return key
}

func mustNew(t *testing.T, current []byte, previous ...[]byte) *Envelope {
	t.Helper()
	e, err := New(current, previous...)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func newEnvelope(t *testing.T) *Envelope {
	t.Helper()
	return mustNew(t, randomKey(t))
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
	if s.KeyID != e.CurrentKeyID() {
		t.Fatalf("sealed under %q, current is %q", s.KeyID, e.CurrentKeyID())
	}
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
	if _, err := newEnvelope(t).Open(s, []byte("x")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got %v", err)
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
	if _, err := New(randomKey(t), make([]byte, 16)); err == nil {
		t.Fatal("expected error for 16-byte previous key")
	}
}

func TestKeyID(t *testing.T) {
	a, b := randomKey(t), randomKey(t)
	if len(KeyID(a)) != 16 || KeyID(a) != KeyID(a) || KeyID(a) == KeyID(b) {
		t.Fatalf("key ids %q %q", KeyID(a), KeyID(b))
	}
}

func TestRotation(t *testing.T) {
	a, b := randomKey(t), randomKey(t)
	old := mustNew(t, a)
	s := mustSeal(t, old, "secret", "x")

	// During rotation the new key is current and the old one still opens.
	both := mustNew(t, b, a)
	if both.CurrentKeyID() != KeyID(b) {
		t.Fatal("first key must be current")
	}
	if got, err := both.Open(s, []byte("x")); err != nil || string(got) != "secret" {
		t.Fatalf("open old row during rotation: %q, %v", got, err)
	}

	re, changed, err := both.Rewrap(s, []byte("x"))
	if err != nil || !changed || re.KeyID != KeyID(b) || !bytes.Equal(re.Ciphertext, s.Ciphertext) {
		t.Fatalf("rewrap: changed=%v key=%q err=%v", changed, re.KeyID, err)
	}
	if _, changed, _ := both.Rewrap(re, []byte("x")); changed {
		t.Fatal("rewrap of a current row must be a no-op")
	}
	if _, _, err := both.Rewrap(s, []byte("other")); !errors.Is(err, ErrOpen) {
		t.Fatalf("rewrap with wrong aad: %v", err)
	}

	// After rotation the old key can be retired.
	fresh := mustNew(t, b)
	if got, err := fresh.Open(re, []byte("x")); err != nil || string(got) != "secret" {
		t.Fatalf("open rewrapped row with new key only: %q, %v", got, err)
	}
	if _, err := fresh.Open(s, []byte("x")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("old row with new key only: expected ErrUnknownKey, got %v", err)
	}
	if _, _, err := fresh.Rewrap(s, []byte("x")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("rewrap without the old key: expected ErrUnknownKey, got %v", err)
	}
}

func TestRewrapShredded(t *testing.T) {
	// A shredded row has no key to re-wrap; rotation must not invent one.
	a, b := randomKey(t), randomKey(t)
	s := mustSeal(t, mustNew(t, a), "secret", "x")
	s.WrappedDEK = nil
	if _, _, err := mustNew(t, b, a).Rewrap(s, []byte("x")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestBlindIndex(t *testing.T) {
	if _, err := NewIndex(make([]byte, 16)); err == nil {
		t.Fatal("expected error for 16-byte index key")
	}
	x, err := NewIndex(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	h := x.Hash("customers", "email", "ivan@example.com")
	if len(h) != 32 {
		t.Fatalf("hash length %d", len(h))
	}
	if !bytes.Equal(h, x.Hash("customers", "email", "ivan@example.com")) {
		t.Fatal("same input must hash the same")
	}
	other, _ := NewIndex(randomKey(t))
	for name, got := range map[string][]byte{
		"other value":      x.Hash("customers", "email", "ivan@example.org"),
		"other field":      x.Hash("customers", "phone", "ivan@example.com"),
		"other collection": x.Hash("employees", "email", "ivan@example.com"),
		"other key":        other.Hash("customers", "email", "ivan@example.com"),
	} {
		if bytes.Equal(h, got) {
			t.Errorf("%s: hash must differ", name)
		}
	}
}
