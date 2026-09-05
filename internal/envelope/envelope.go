// Package envelope implements envelope encryption: every value is encrypted
// with its own random data-encryption key (DEK), and the DEK is wrapped with
// a master key (KEK). Deleting the wrapped DEK makes the ciphertext
// unrecoverable, which is what "delete the key, shred the data" means.
//
// Several master keys may be loaded at once: the current one wraps new keys,
// previous ones only open rows that have not been re-wrapped yet. Rotation
// re-wraps DEKs and never touches ciphertext.
//
// No custom cryptography lives here: both layers are XChaCha20-Poly1305 from
// golang.org/x/crypto with random 24-byte nonces; blind-index hashes and key
// fingerprints are HMAC-SHA256.
package envelope

import (
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
	// ErrOpen is returned for every failed decryption. The reason is
	// deliberately not distinguished: a caller must not learn whether the
	// key, the nonce, the tag or the associated data was wrong.
	ErrOpen = errors.New("envelope: open failed")
	// ErrUnknownKey means the row names a master key that is not loaded.
	// Load it as a previous key, or rotate before retiring it.
	ErrUnknownKey = errors.New("envelope: wrapped by a master key this server does not have")
)

// Sealed is one encrypted value together with everything needed to open it,
// except the master key. Both byte fields carry their nonce as a prefix.
//
// WrappedDEK is the per-object key encrypted under the master key named by
// KeyID. Setting it to nil is the crypto-shred: Ciphertext can never be
// opened again.
type Sealed struct {
	KeyID      string
	WrappedDEK []byte
	Ciphertext []byte
}

// Envelope seals under the current master key and opens under any loaded one.
type Envelope struct {
	current string
	keks    map[string]cipher.AEAD
}

// New returns an Envelope that seals under masterKey and also opens rows
// wrapped by any of previous.
func New(masterKey []byte, previous ...[]byte) (*Envelope, error) {
	e := &Envelope{keks: map[string]cipher.AEAD{}}
	for _, key := range append([][]byte{masterKey}, previous...) {
		kek, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, err
		}
		id := KeyID(key)
		if e.current == "" {
			e.current = id
		}
		e.keks[id] = kek
	}
	return e, nil
}

// KeyID is a short fingerprint of a master key. It is stored next to every
// wrapped key so rotation knows which rows still need re-wrapping. It cannot
// be turned back into the key.
func KeyID(masterKey []byte) string {
	m := hmac.New(sha256.New, masterKey)
	m.Write([]byte("sealbox/key-id/v1"))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// CurrentKeyID is the fingerprint of the key that wraps new objects.
func (e *Envelope) CurrentKeyID() string { return e.current }

// Seal encrypts plaintext under a fresh DEK wrapped by the current master
// key. aad is authenticated but not encrypted; pass the row identity so a
// ciphertext cannot be moved to another row without failing to open.
func (e *Envelope) Seal(plaintext, aad []byte) (Sealed, error) {
	dek := make([]byte, KeySize)
	rand.Read(dek)
	dataAEAD, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{
		KeyID:      e.current,
		WrappedDEK: seal(e.keks[e.current], dek, aad),
		Ciphertext: seal(dataAEAD, plaintext, aad),
	}, nil
}

// Open decrypts s. aad must equal the value passed to Seal.
func (e *Envelope) Open(s Sealed, aad []byte) ([]byte, error) {
	dek, err := e.unwrap(s, aad)
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

// Rewrap returns s with its per-object key wrapped under the current master
// key. Ciphertext is carried over untouched and may be nil. The bool
// reports whether anything changed.
func (e *Envelope) Rewrap(s Sealed, aad []byte) (Sealed, bool, error) {
	if s.KeyID == e.current {
		return s, false, nil
	}
	dek, err := e.unwrap(s, aad)
	if err != nil {
		return Sealed{}, false, err
	}
	return Sealed{
		KeyID:      e.current,
		WrappedDEK: seal(e.keks[e.current], dek, aad),
		Ciphertext: s.Ciphertext,
	}, true, nil
}

// unwrap recovers the DEK under the master key named by s.KeyID.
func (e *Envelope) unwrap(s Sealed, aad []byte) ([]byte, error) {
	kek, ok := e.keks[s.KeyID]
	if !ok {
		return nil, ErrUnknownKey
	}
	dek, err := open(kek, s.WrappedDEK, aad)
	if err != nil {
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
// the database wrapped like any per-object key, so master key rotation
// re-wraps it and never changes a hash.
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
