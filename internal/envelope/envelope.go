// Package envelope implements envelope encryption: every value is encrypted
// with its own random data-encryption key (DEK), and the DEK is wrapped by a
// wrapping key. Deleting the wrapped DEK makes the ciphertext unrecoverable,
// which is what "delete the key, shred the data" means.
//
// The wrapping key is held by a Wrapper: Local keeps a master key in this
// process, Transit and AWSKMS keep it in an external key service and wrap
// and unwrap over the network, so the process never holds it. Several
// wrappers may be loaded at once: the current one wraps new keys, previous
// ones only open rows that have not been re-wrapped yet. Rotation, and
// migration from one wrapper to another, re-wraps DEKs and never touches
// ciphertext.
//
// No custom cryptography lives here: values and locally wrapped keys use
// XChaCha20-Poly1305 from golang.org/x/crypto with random 24-byte nonces;
// blind-index hashes and key fingerprints are HMAC-SHA256.
package envelope

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the length in bytes of every master key, DEK and index key.
const KeySize = chacha20poly1305.KeySize

var (
	// ErrOpen is returned when a value or a wrapped key fails to open under
	// the key it names. The reason is deliberately not distinguished: a
	// caller must not learn whether the key, the nonce, the tag or the
	// associated data was wrong.
	ErrOpen = errors.New("envelope: open failed")
	// ErrUnknownKey means the row names a wrapping key that is not loaded.
	// Load it as a previous key, or rotate before retiring it.
	ErrUnknownKey = errors.New("envelope: wrapped by a key this server does not have")
)

// Wrapper protects per-object keys under one wrapping key. ID is stored next
// to every wrapped key as objects.key_id, so rotation knows which rows still
// need re-wrapping. aad is the row identity; wrappers bind the wrapped key
// to it where their backend allows. Unwrap returns ErrOpen for a wrapped
// key that does not open under this key, and any other error for a backend
// that could not be reached.
type Wrapper interface {
	ID() string
	Wrap(ctx context.Context, dek, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
}

// Rewrapper is a Wrapper whose backend keeps key versions of its own and can
// move a wrapped key to its current version in place: the wrapper's ID stays
// the same, only the wrapped bytes change. Transit engines do this. A local
// master key does not; it changes ID instead.
type Rewrapper interface {
	Wrapper
	// Rewrap returns wrapped re-sealed under the backend's current version,
	// and whether anything changed.
	Rewrap(ctx context.Context, wrapped, aad []byte) ([]byte, bool, error)
}

// Local wraps with a master key held in this process: XChaCha20-Poly1305
// with the row identity as associated data.
type Local struct {
	id  string
	kek cipher.AEAD
}

// NewLocal returns a Local wrapper for a 32-byte master key.
func NewLocal(masterKey []byte) (*Local, error) {
	kek, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, err
	}
	return &Local{id: KeyID(masterKey), kek: kek}, nil
}

// ID is the fingerprint of the master key.
func (l *Local) ID() string { return l.id }

// Wrap encrypts dek under the master key, bound to aad.
func (l *Local) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	return seal(l.kek, dek, aad), nil
}

// Unwrap is the inverse of Wrap.
func (l *Local) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	dek, err := open(l.kek, wrapped, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return dek, nil
}

// KeyID is a short fingerprint of a master key. It cannot be turned back
// into the key.
func KeyID(masterKey []byte) string {
	m := hmac.New(sha256.New, masterKey)
	m.Write([]byte("sealbox/key-id/v1"))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// Sealed is one encrypted value together with everything needed to open it,
// except the wrapping key. Ciphertext carries its nonce as a prefix.
//
// WrappedDEK is the per-object key wrapped by the Wrapper named by KeyID.
// Setting it to nil is the crypto-shred: Ciphertext can never be opened
// again.
type Sealed struct {
	KeyID      string
	WrappedDEK []byte
	Ciphertext []byte
}

// Envelope seals under the current wrapper and opens under any loaded one.
type Envelope struct {
	current Wrapper
	all     map[string]Wrapper
}

// New returns an Envelope that seals under current and also opens rows
// wrapped by any of previous.
func New(current Wrapper, previous ...Wrapper) *Envelope {
	e := &Envelope{current: current, all: map[string]Wrapper{current.ID(): current}}
	for _, w := range previous {
		if _, dup := e.all[w.ID()]; !dup {
			e.all[w.ID()] = w
		}
	}
	return e
}

// CurrentKeyID is the id of the wrapper that wraps new objects.
func (e *Envelope) CurrentKeyID() string { return e.current.ID() }

// RewrapsInPlace reports whether rows already under the current wrapper may
// still need re-wrapping, because its backend has key versions of its own.
func (e *Envelope) RewrapsInPlace() bool {
	_, ok := e.current.(Rewrapper)
	return ok
}

// Seal encrypts plaintext under a fresh DEK wrapped by the current wrapper.
// aad is authenticated but not encrypted; pass the row identity so a
// ciphertext cannot be moved to another row without failing to open.
func (e *Envelope) Seal(ctx context.Context, plaintext, aad []byte) (Sealed, error) {
	dek := make([]byte, KeySize)
	rand.Read(dek)
	dataAEAD, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return Sealed{}, err
	}
	wrapped, err := e.current.Wrap(ctx, dek, aad)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{
		KeyID:      e.current.ID(),
		WrappedDEK: wrapped,
		Ciphertext: seal(dataAEAD, plaintext, aad),
	}, nil
}

// Open decrypts s. aad must equal the value passed to Seal.
func (e *Envelope) Open(ctx context.Context, s Sealed, aad []byte) ([]byte, error) {
	dek, err := e.unwrap(ctx, s, aad)
	if err != nil {
		return nil, err
	}
	dataAEAD, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, ErrOpen
	}
	plaintext, err := open(dataAEAD, s.Ciphertext, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}

// Rewrap returns s with its per-object key wrapped by the current wrapper.
// Ciphertext is carried over untouched and may be nil. The bool reports
// whether anything changed. Moving from one wrapper to another, for example
// from a local master key to a KMS, is the same operation. A row already
// under a Rewrapper is handed to the backend, which moves it to its current
// key version.
func (e *Envelope) Rewrap(ctx context.Context, s Sealed, aad []byte) (Sealed, bool, error) {
	if s.KeyID == e.current.ID() {
		rw, ok := e.current.(Rewrapper)
		if !ok {
			return s, false, nil
		}
		wrapped, changed, err := rw.Rewrap(ctx, s.WrappedDEK, aad)
		if err != nil || !changed {
			return s, false, err
		}
		return Sealed{KeyID: s.KeyID, WrappedDEK: wrapped, Ciphertext: s.Ciphertext}, true, nil
	}
	dek, err := e.unwrap(ctx, s, aad)
	if err != nil {
		return Sealed{}, false, err
	}
	wrapped, err := e.current.Wrap(ctx, dek, aad)
	if err != nil {
		return Sealed{}, false, err
	}
	return Sealed{KeyID: e.current.ID(), WrappedDEK: wrapped, Ciphertext: s.Ciphertext}, true, nil
}

// unwrap recovers the DEK through the wrapper named by s.KeyID.
func (e *Envelope) unwrap(ctx context.Context, s Sealed, aad []byte) ([]byte, error) {
	w, ok := e.all[s.KeyID]
	if !ok {
		return nil, ErrUnknownKey
	}
	dek, err := w.Unwrap(ctx, s.WrappedDEK, aad)
	if err != nil {
		return nil, err
	}
	if len(dek) != KeySize {
		return nil, ErrOpen
	}
	return dek, nil
}

// seal returns nonce || ciphertext with a fresh random nonce.
func seal(aead cipher.AEAD, plaintext, aad []byte) []byte {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	rand.Read(nonce)
	return aead.Seal(nonce, nonce, plaintext, aad)
}

// open is the inverse of seal.
func open(aead cipher.AEAD, blob, aad []byte) ([]byte, error) {
	ns := aead.NonceSize()
	if len(blob) < ns {
		return nil, ErrOpen
	}
	return aead.Open(nil, blob[:ns], blob[ns:], aad)
}

// Index computes blind-index hashes under a dedicated key. The key lives in
// the database wrapped like any per-object key, so key rotation re-wraps it
// and never changes a hash.
type Index struct {
	key []byte
}

// NewIndex returns an Index for a 32-byte key.
func NewIndex(key []byte) (*Index, error) {
	if len(key) != KeySize {
		return nil, errors.New("envelope: index key must be 32 bytes")
	}
	return &Index{key: key}, nil
}

// Hash returns a keyed hash of a normalized value for exact-match lookup.
// Without the key a database dump cannot be used to test guesses.
// collection and field are part of the input, so the same value in two
// fields yields two unrelated hashes.
func (x *Index) Hash(collection, field, normalized string) []byte {
	m := hmac.New(sha256.New, x.key)
	m.Write([]byte(collection))
	m.Write([]byte{0})
	m.Write([]byte(field))
	m.Write([]byte{0})
	m.Write([]byte(normalized))
	return m.Sum(nil)
}
