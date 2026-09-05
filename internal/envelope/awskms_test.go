//go:build awskms

package envelope

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// fakeKMS emulates the Encrypt and Decrypt operations of the KMS JSON API,
// including the rule that the encryption context must match on decrypt.
func fakeKMS(t *testing.T) *httptest.Server {
	t.Helper()
	type entry struct {
		plaintext []byte
		context   map[string]string
	}
	store := map[string]entry{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			KeyID             string            `json:"KeyId"`
			Plaintext         []byte            `json:"Plaintext"`
			CiphertextBlob    []byte            `json:"CiphertextBlob"`
			EncryptionContext map[string]string `json:"EncryptionContext"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.Encrypt":
			blob := make([]byte, 16)
			rand.Read(blob)
			store[hex.EncodeToString(blob)] = entry{req.Plaintext, req.EncryptionContext}
			json.NewEncoder(w).Encode(map[string]any{"CiphertextBlob": base64.StdEncoding.EncodeToString(blob), "KeyId": req.KeyID})
		case "TrentService.Decrypt":
			e, ok := store[hex.EncodeToString(req.CiphertextBlob)]
			if !ok || !reflect.DeepEqual(e.context, req.EncryptionContext) {
				w.Header().Set("X-Amzn-Errortype", "InvalidCiphertextException")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"__type": "InvalidCiphertextException", "message": "ciphertext or context invalid"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"Plaintext": base64.StdEncoding.EncodeToString(e.plaintext), "KeyId": req.KeyID})
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAWSKMS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	srv := fakeKMS(t)

	w, err := NewAWSKMS(ctx, "alias/sealbox", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if w.ID() != "awskms:alias/sealbox" {
		t.Fatalf("id %q", w.ID())
	}
	e := New(w)
	s := mustSeal(t, e, "secret", "customers/obj-1")
	if got, err := e.Open(ctx, s, []byte("customers/obj-1")); err != nil || string(got) != "secret" {
		t.Fatalf("roundtrip: %q, %v", got, err)
	}
	if _, err := e.Open(ctx, s, []byte("customers/obj-2")); !errors.Is(err, ErrOpen) {
		t.Fatalf("wrong aad: expected ErrOpen, got %v", err)
	}
	if _, err := NewAWSKMS(ctx, "", ""); err == nil {
		t.Fatal("expected error without a key id")
	}
}
