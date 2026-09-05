package envelope

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeTransit emulates the encrypt and decrypt endpoints of a transit engine
// with a derived key: the context must match on decrypt, a bad ciphertext
// is a 400, a bad token a 403.
func fakeTransit(t *testing.T, token string) *httptest.Server {
	t.Helper()
	type entry struct{ plaintext, context string }
	store := map[string]entry{}
	fail := func(w http.ResponseWriter, status int, msg string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string][]string{"errors": {msg}})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/transit/encrypt/{key}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			fail(w, http.StatusForbidden, "permission denied")
			return
		}
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		ref := make([]byte, 8)
		rand.Read(ref)
		ct := "vault:v1:" + hex.EncodeToString(ref)
		store[ct] = entry{req["plaintext"], req["context"]}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": ct}})
	})
	mux.HandleFunc("POST /v1/transit/decrypt/{key}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			fail(w, http.StatusForbidden, "permission denied")
			return
		}
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		e, ok := store[req["ciphertext"]]
		if !ok || e.context != req["context"] {
			fail(w, http.StatusBadRequest, "invalid ciphertext")
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": e.plaintext}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestTransit(t *testing.T) {
	srv := fakeTransit(t, "s.token")
	w := NewTransit(srv.URL, "transit", "sealbox", "s.token")
	if w.ID() != "transit:transit/sealbox" {
		t.Fatalf("id %q", w.ID())
	}
	e := New(w)
	s := mustSeal(t, e, "secret", "customers/obj-1")
	if got, err := e.Open(ctx, s, []byte("customers/obj-1")); err != nil || string(got) != "secret" {
		t.Fatalf("roundtrip: %q, %v", got, err)
	}

	// The engine rejects a tampered ciphertext and a foreign context.
	tampered := s
	tampered.WrappedDEK = append([]byte{}, s.WrappedDEK...)
	tampered.WrappedDEK[len(tampered.WrappedDEK)-1] ^= 1
	if _, err := e.Open(ctx, tampered, []byte("customers/obj-1")); !errors.Is(err, ErrOpen) {
		t.Fatalf("tampered: expected ErrOpen, got %v", err)
	}
	if _, err := e.Open(ctx, s, []byte("customers/obj-2")); !errors.Is(err, ErrOpen) {
		t.Fatalf("wrong aad: expected ErrOpen, got %v", err)
	}

	// A backend failure is not ErrOpen: rotation must stop, not skip rows.
	bad := New(NewTransit(srv.URL, "transit", "sealbox", "wrong"))
	if _, err := bad.Open(ctx, s, []byte("customers/obj-1")); err == nil || errors.Is(err, ErrOpen) || errors.Is(err, ErrUnknownKey) {
		t.Fatalf("wrong token: %v", err)
	}
	srv.Close()
	if _, err := e.Open(ctx, s, []byte("customers/obj-1")); err == nil || errors.Is(err, ErrOpen) {
		t.Fatalf("server down: %v", err)
	}
}
