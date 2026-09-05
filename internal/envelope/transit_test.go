package envelope

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeEngine emulates a transit engine with a derived key: the context must
// match on decrypt, a bad ciphertext is a 400, a bad token a 403. Its key
// version can be bumped, after which rewrap moves ciphertexts to it.
type fakeEngine struct {
	token   string
	version string
	calls   int // batch decrypt round trips
	store   map[string]struct{ plaintext, context string }
}

func newFakeEngine(t *testing.T, token string) (*httptest.Server, *fakeEngine) {
	t.Helper()
	e := &fakeEngine{token: token, version: "v1", store: map[string]struct{ plaintext, context string }{}}
	srv := httptest.NewServer(e.handler())
	t.Cleanup(srv.Close)
	return srv, e
}

func (e *fakeEngine) seal(plaintext, context string) string {
	ref := make([]byte, 8)
	rand.Read(ref)
	ct := "vault:" + e.version + ":" + hex.EncodeToString(ref)
	e.store[ct] = struct{ plaintext, context string }{plaintext, context}
	return ct
}

func (e *fakeEngine) handler() http.Handler {
	fail := func(w http.ResponseWriter, status int, msg string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string][]string{"errors": {msg}})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != e.token {
			fail(w, http.StatusForbidden, "permission denied")
			return
		}
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		str := func(k string) string { s, _ := req[k].(string); return s }
		op := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/transit/"), "/")[0]
		if batch, ok := req["batch_input"].([]any); ok && op == "decrypt" {
			e.calls++
			results := make([]map[string]string, 0, len(batch))
			for _, item := range batch {
				m, _ := item.(map[string]any)
				ct, _ := m["ciphertext"].(string)
				cx, _ := m["context"].(string)
				if entry, ok := e.store[ct]; ok && entry.context == cx {
					results = append(results, map[string]string{"plaintext": entry.plaintext})
				} else {
					results = append(results, map[string]string{"error": "invalid ciphertext"})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"batch_results": results}})
			return
		}
		switch op {
		case "encrypt":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": e.seal(str("plaintext"), str("context"))}})
		case "decrypt", "rewrap":
			req := map[string]string{"ciphertext": str("ciphertext"), "context": str("context")}
			entry, ok := e.store[req["ciphertext"]]
			if !ok || entry.context != req["context"] {
				fail(w, http.StatusBadRequest, "invalid ciphertext")
				return
			}
			if op == "decrypt" {
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": entry.plaintext}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": e.seal(entry.plaintext, entry.context)}})
		default:
			fail(w, http.StatusNotFound, "unsupported path")
		}
	})
}

func TestTransit(t *testing.T) {
	srv, _ := newFakeEngine(t, "s.token")
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

func TestTransitRewrapInPlace(t *testing.T) {
	srv, engine := newFakeEngine(t, "s.token")
	e := New(NewTransit(srv.URL, "transit", "sealbox", "s.token"))
	if !e.RewrapsInPlace() || mustNew(t, randomKey(t)).RewrapsInPlace() {
		t.Fatal("transit re-wraps in place, a local key does not")
	}
	s := mustSeal(t, e, "secret", "x")

	// Same engine version: nothing to do, even though the engine would answer.
	if _, changed, err := e.Rewrap(ctx, s, []byte("x")); err != nil || changed {
		t.Fatalf("same version: changed=%v err=%v", changed, err)
	}

	// The engine's key rotated: the wrapper id stays, the wrapped bytes move.
	engine.version = "v2"
	re, changed, err := e.Rewrap(ctx, s, []byte("x"))
	if err != nil || !changed || re.KeyID != s.KeyID || !strings.HasPrefix(string(re.WrappedDEK), "vault:v2:") {
		t.Fatalf("rewrap: changed=%v key=%q wrapped=%q err=%v", changed, re.KeyID, re.WrappedDEK, err)
	}
	if got, err := e.Open(ctx, re, []byte("x")); err != nil || string(got) != "secret" {
		t.Fatalf("open after rewrap: %q, %v", got, err)
	}
	if _, changed, _ := e.Rewrap(ctx, re, []byte("x")); changed {
		t.Fatal("second rewrap must be a no-op")
	}
	if _, _, err := e.Rewrap(ctx, s, []byte("other")); !errors.Is(err, ErrOpen) {
		t.Fatalf("rewrap with wrong aad: %v", err)
	}
}

func TestTransitBatch(t *testing.T) {
	srv, engine := newFakeEngine(t, "s.token")
	transit := NewTransit(srv.URL, "transit", "sealbox", "s.token")
	key := randomKey(t)
	e := New(transit, local(t, key))

	// Three rows under transit, one under the local key, one tampered, one
	// under a key nobody has: one round trip for the transit group.
	var sealed []Sealed
	var aads [][]byte
	for i := range 3 {
		aad := fmt.Sprintf("row-%d", i)
		sealed = append(sealed, mustSeal(t, e, "secret-"+aad, aad))
		aads = append(aads, []byte(aad))
	}
	sealed = append(sealed, mustSeal(t, mustNew(t, key), "local", "row-local"))
	aads = append(aads, []byte("row-local"))
	tampered := sealed[0]
	tampered.WrappedDEK = append([]byte{}, sealed[0].WrappedDEK...)
	tampered.WrappedDEK[len(tampered.WrappedDEK)-1] ^= 1
	sealed = append(sealed, tampered)
	aads = append(aads, []byte("row-0"))
	sealed = append(sealed, Sealed{KeyID: "nobody", WrappedDEK: []byte("x"), Ciphertext: []byte("y")})
	aads = append(aads, []byte("row-x"))

	plaintexts, errs, err := e.OpenMany(ctx, sealed, aads)
	if err != nil {
		t.Fatal(err)
	}
	if engine.calls != 1 {
		t.Fatalf("expected one batch round trip, got %d", engine.calls)
	}
	for i := range 3 {
		if errs[i] != nil || string(plaintexts[i]) != fmt.Sprintf("secret-row-%d", i) {
			t.Errorf("row %d: %q, %v", i, plaintexts[i], errs[i])
		}
	}
	if errs[3] != nil || string(plaintexts[3]) != "local" {
		t.Errorf("local row: %q, %v", plaintexts[3], errs[3])
	}
	if !errors.Is(errs[4], ErrOpen) {
		t.Errorf("tampered row: %v", errs[4])
	}
	if !errors.Is(errs[5], ErrUnknownKey) {
		t.Errorf("unknown key row: %v", errs[5])
	}

	// A backend that is down fails the whole call rather than every row.
	srv.Close()
	if _, _, err := e.OpenMany(ctx, sealed[:3], aads[:3]); err == nil {
		t.Fatal("expected a round-trip error")
	}
}

func TestVersionPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"vault:v2:abc":        "vault:v2",
		"keeper:0123abcd:xyz": "keeper:0123abcd",
		"vault:v10:a:b":       "vault:v10",
		"no-separators":       "no-separators",
		"one:separator":       "one:separator",
	} {
		if got := version(in); got != want {
			t.Errorf("version(%q) = %q, want %q", in, got, want)
		}
	}
}
