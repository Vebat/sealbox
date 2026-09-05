package envelope

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Transit wraps per-object keys with the transit secrets engine of
// HashiCorp Vault or OpenBao. The wrapping key never leaves the engine:
// sealbox sends each DEK to be encrypted and asks for it back to be
// decrypted, one call per key. The row identity goes along as the transit
// context; create the key with derived=true and the engine enforces it.
//
// ponytail: one HTTP call per wrapped key. Transit has batch_input; use it
// for batch reveal when latency matters.
type Transit struct {
	addr, mount, key, token string
	http                    *http.Client
}

// NewTransit returns a wrapper for the key named key under the engine
// mounted at mount, on the server at addr, authenticating with token.
func NewTransit(addr, mount, key, token string) *Transit {
	return &Transit{
		addr:  strings.TrimRight(addr, "/"),
		mount: strings.Trim(mount, "/"),
		key:   key,
		token: token,
		http:  &http.Client{Timeout: 10 * time.Second},
	}
}

// ID names the engine mount and key, not the server, so a row stays
// readable when the server moves.
func (t *Transit) ID() string { return "transit:" + t.mount + "/" + t.key }

// Wrap encrypts dek; the result is the engine's own ciphertext string.
func (t *Transit) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	var res struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := t.call(ctx, "encrypt", map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(dek),
		"context":   base64.StdEncoding.EncodeToString(aad),
	}, &res)
	if err != nil {
		return nil, err
	}
	return []byte(res.Data.Ciphertext), nil
}

// Unwrap is the inverse of Wrap.
func (t *Transit) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	var res struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	err := t.call(ctx, "decrypt", map[string]string{
		"ciphertext": string(wrapped),
		"context":    base64.StdEncoding.EncodeToString(aad),
	}, &res)
	if err != nil {
		return nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(res.Data.Plaintext)
	if err != nil {
		return nil, ErrOpen
	}
	return dek, nil
}

// Rewrap asks the engine to re-encrypt the wrapped key under its current key
// version. Engines answer with fresh ciphertext even when the version did not
// move, so the version segment of the ciphertext decides whether anything
// changed.
func (t *Transit) Rewrap(ctx context.Context, wrapped, aad []byte) ([]byte, bool, error) {
	var res struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := t.call(ctx, "rewrap", map[string]string{
		"ciphertext": string(wrapped),
		"context":    base64.StdEncoding.EncodeToString(aad),
	}, &res)
	if err != nil {
		return nil, false, err
	}
	return []byte(res.Data.Ciphertext), version(res.Data.Ciphertext) != version(string(wrapped)), nil
}

// version returns the "<scheme>:<version>" prefix of a transit ciphertext,
// "vault:v2" or "keeper:<id>", or the whole string when there is none.
func version(ciphertext string) string {
	first := strings.IndexByte(ciphertext, ':')
	if first < 0 {
		return ciphertext
	}
	second := strings.IndexByte(ciphertext[first+1:], ':')
	if second < 0 {
		return ciphertext
	}
	return ciphertext[:first+1+second]
}

// call posts to /v1/<mount>/<op>/<key>. A 400 means the engine rejected the
// ciphertext or context and maps to ErrOpen; anything else is a backend
// failure and keeps its own message, which never contains key material.
func (t *Transit) call(ctx context.Context, op string, body map[string]string, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.addr+"/v1/"+t.mount+"/"+op+"/"+t.key, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", t.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.http.Do(req)
	if err != nil {
		return fmt.Errorf("transit %s: %w", op, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Errors []string `json:"errors"`
		}
		json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		if resp.StatusCode == http.StatusBadRequest {
			return fmt.Errorf("%w: transit %s: %s", ErrOpen, op, strings.Join(e.Errors, "; "))
		}
		return fmt.Errorf("transit %s: HTTP %d: %s", op, resp.StatusCode, strings.Join(e.Errors, "; "))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
