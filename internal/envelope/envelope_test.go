package envelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

var ctx = context.Background()

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	rand.Read(key)
	return key
}

func local(t *testing.T, key []byte) *Local {
	t.Helper()
	w, err := NewLocal(key)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func mustNew(t *testing.T, current []byte, previous ...[]byte) *Envelope {
	t.Helper()
	ws := make([]Wrapper, 0, len(previous))
	for _, k := range previous {
		ws = append(ws, local(t, k))
	}
	return New(local(t, current), ws...)
}

func newEnvelope(t *testing.T) *Envelope {
	t.Helper()
	return mustNew(t, randomKey(t))
}

func mustSeal(t *testing.T, e *Envelope, plaintext, aad string) Sealed {
	t.Helper()
	s, err := e.Seal(ctx, []byte(plaintext), []byte(aad))
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
	got, err := e.Open(ctx, s, []byte("customers/obj-1"))
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
	got, err := e.Open(ctx, s, []byte("x"))
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
	if _, err := e.Open(ctx, s, []byte("x")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	e := newEnvelope(t)
	s := mustSeal(t, e, "secret", "x")
	s.Ciphertext[len(s.Ciphertext)-1] ^= 1
	if _, err := e.Open(ctx, s, []byte("x")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestTamperedWrappedDEK(t *testing.T) {
	e := newEnvelope(t)
	s := mustSeal(t, e, "secret", "x")
	s.WrappedDEK[len(s.WrappedDEK)-1] ^= 1
	if _, err := e.Open(ctx, s, []byte("x")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestWrongAAD(t *testing.T) {
	// A ciphertext moved to another record must not open there.
	e := newEnvelope(t)
	s := mustSeal(t, e, "secret", "customers/obj-1")
	if _, err := e.Open(ctx, s, []byte("customers/obj-2")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestWrongMasterKey(t *testing.T) {
	s := mustSeal(t, newEnvelope(t), "secret", "x")
	if _, err := newEnvelope(t).Open(ctx, s, []byte("x")); !errors.Is(err, ErrUnknownKey) {
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
	if _, err := NewLocal(make([]byte, 16)); err == nil {
		t.Fatal("expected error for 16-byte master key")
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
	if got, err := both.Open(ctx, s, []byte("x")); err != nil || string(got) != "secret" {
		t.Fatalf("open old row during rotation: %q, %v", got, err)
	}

	re, changed, err := both.Rewrap(ctx, s, []byte("x"))
	if err != nil || !changed || re.KeyID != KeyID(b) || !bytes.Equal(re.Ciphertext, s.Ciphertext) {
		t.Fatalf("rewrap: changed=%v key=%q err=%v", changed, re.KeyID, err)
	}
	if _, changed, _ := both.Rewrap(ctx, re, []byte("x")); changed {
		t.Fatal("rewrap of a current row must be a no-op")
	}
	if _, _, err := both.Rewrap(ctx, s, []byte("other")); !errors.Is(err, ErrOpen) {
		t.Fatalf("rewrap with wrong aad: %v", err)
	}

	// After rotation the old key can be retired.
	fresh := mustNew(t, b)
	if got, err := fresh.Open(ctx, re, []byte("x")); err != nil || string(got) != "secret" {
		t.Fatalf("open rewrapped row with new key only: %q, %v", got, err)
	}
	if _, err := fresh.Open(ctx, s, []byte("x")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("old row with new key only: expected ErrUnknownKey, got %v", err)
	}
	if _, _, err := fresh.Rewrap(ctx, s, []byte("x")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("rewrap without the old key: expected ErrUnknownKey, got %v", err)
	}
}

func TestRewrapShredded(t *testing.T) {
	// A shredded row has no key to re-wrap; rotation must not invent one.
	a, b := randomKey(t), randomKey(t)
	s := mustSeal(t, mustNew(t, a), "secret", "x")
	s.WrappedDEK = nil
	if _, _, err := mustNew(t, b, a).Rewrap(ctx, s, []byte("x")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

// memWrapper stands in for a key service: it keeps the wrapped keys itself
// and hands one back only with the aad it was wrapped with.
type memWrapper struct {
	id   string
	keys map[string]struct{ dek, aad []byte }
}

func newMemWrapper(id string) *memWrapper {
	return &memWrapper{id: id, keys: map[string]struct{ dek, aad []byte }{}}
}

func (m *memWrapper) ID() string { return m.id }

func (m *memWrapper) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	ref := make([]byte, 8)
	rand.Read(ref)
	m.keys[hex.EncodeToString(ref)] = struct{ dek, aad []byte }{bytes.Clone(dek), bytes.Clone(aad)}
	return []byte(hex.EncodeToString(ref)), nil
}

func (m *memWrapper) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	k, ok := m.keys[string(wrapped)]
	if !ok || !bytes.Equal(k.aad, aad) {
		return nil, ErrOpen
	}
	return k.dek, nil
}

func TestMigrateBetweenWrappers(t *testing.T) {
	// From a local master key to a key service and back: the same rewrap.
	key := randomKey(t)
	s := mustSeal(t, mustNew(t, key), "secret", "x")

	kms := newMemWrapper("kms:test")
	migrating := New(kms, local(t, key))
	re, changed, err := migrating.Rewrap(ctx, s, []byte("x"))
	if err != nil || !changed || re.KeyID != "kms:test" {
		t.Fatalf("to kms: changed=%v key=%q err=%v", changed, re.KeyID, err)
	}
	if got, err := New(kms).Open(ctx, re, []byte("x")); err != nil || string(got) != "secret" {
		t.Fatalf("open with kms only: %q, %v", got, err)
	}
	if _, err := New(kms).Open(ctx, re, []byte("other")); !errors.Is(err, ErrOpen) {
		t.Fatalf("kms must honour aad: %v", err)
	}

	back, changed, err := New(local(t, key), kms).Rewrap(ctx, re, []byte("x"))
	if err != nil || !changed || back.KeyID != KeyID(key) {
		t.Fatalf("back to local: changed=%v key=%q err=%v", changed, back.KeyID, err)
	}
	if got, err := mustNew(t, key).Open(ctx, back, []byte("x")); err != nil || string(got) != "secret" {
		t.Fatalf("open with local only: %q, %v", got, err)
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
