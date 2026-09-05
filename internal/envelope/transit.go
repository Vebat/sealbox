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
// decrypted, one call per key on single reads and one call per batchSize
// keys on batch reads. The row identity goes along as the transit context;
// create the key with derived=true and the engine enforces it.
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

// UnwrapMany decrypts up to batchSize keys per round trip through the
// engine's batch_input. A key the engine rejects comes back with ErrOpen in
// its slot; a failed round trip fails the call.
func (t *Transit) UnwrapMany(ctx context.Context, wrapped, aads [][]byte) ([]Unwrapped, error) {
	out := make([]Unwrapped, 0, len(wrapped))
	for start := 0; start < len(wrapped); start += batchSize {
		end := min(start+batchSize, len(wrapped))
		items := make([]map[string]string, 0, end-start)
		for i := start; i < end; i++ {
			items = append(items, map[string]string{
				"ciphertext": string(wrapped[i]),
				"context":    base64.StdEncoding.EncodeToString(aads[i]),
			})
		}
		var res struct {
			Data struct {
				Results []struct {
					Plaintext string `json:"plaintext"`
					Error     string `json:"error"`
				} `json:"batch_results"`
			} `json:"data"`
		}
		if err := t.call(ctx, "decrypt", map[string]any{"batch_input": items}, &res); err != nil {
			return nil, err
		}
		if len(res.Data.Results) != len(items) {
			return nil, fmt.Errorf("transit decrypt: %d results for %d inputs", len(res.Data.Results), len(items))
		}
		for _, r := range res.Data.Results {
			if r.Error != "" {
				out = append(out, Unwrapped{Err: fmt.Errorf("%w: transit decrypt: %s", ErrOpen, r.Error)})
				continue
			}
			dek, err := base64.StdEncoding.DecodeString(r.Plaintext)
			if err != nil {
				out = append(out, Unwrapped{Err: ErrOpen})
				continue
			}
			out = append(out, Unwrapped{DEK: dek})
		}
	}
	return out, nil
}

// batchSize is how many keys one batch_input carries; a batch reveal of a
// thousand objects is two round trips.
const batchSize = 500

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
func (t *Transit) call(ctx context.Context, op string, body any, out any) error {
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
