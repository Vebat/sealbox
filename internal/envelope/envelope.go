// Package envelope implements envelope encryption: every value is encrypted
// with its own random data-encryption key (DEK), and the DEK is wrapped with
// the master key (KEK). Deleting the wrapped DEK makes the ciphertext
// unrecoverable, which is what "delete the key, shred the data" means.
//
// No custom cryptography lives here: both layers are XChaCha20-Poly1305 from
// golang.org/x/crypto with random 24-byte nonces.
package envelope

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the length in bytes of both the master key and every DEK.
const KeySize = chacha20poly1305.KeySize

// ErrOpen is returned for every failed decryption. The reason is deliberately
// not distinguished: a caller must not learn whether the key, the nonce, the
// tag or the associated data was wrong.
var ErrOpen = errors.New("envelope: open failed")

// Sealed is one encrypted value together with everything needed to open it,
// except the master key. Both fields carry their nonce as a prefix.
//
// WrappedDEK is the per-object key encrypted under the master key. Setting it
// to nil is the crypto-shred: Ciphertext can never be opened again.
type Sealed struct {
	WrappedDEK []byte
	Ciphertext []byte
}

// Envelope seals and opens values under one master key.
type Envelope struct {
	kek cipher.AEAD
}

// New returns an Envelope for a 32-byte master key.
func New(masterKey []byte) (*Envelope, error) {
	kek, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, err
	}
	return &Envelope{kek: kek}, nil
}

// Seal encrypts plaintext under a fresh DEK. aad is authenticated but not
// encrypted; pass the object identity so a ciphertext cannot be moved to
// another record without failing to open.
func (e *Envelope) Seal(plaintext, aad []byte) (Sealed, error) {
	dek := make([]byte, KeySize)
	rand.Read(dek)
	dataAEAD, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{
		WrappedDEK: seal(e.kek, dek, aad),
		Ciphertext: seal(dataAEAD, plaintext, aad),
	}, nil
}

// Open decrypts s. aad must equal the value passed to Seal.
func (e *Envelope) Open(s Sealed, aad []byte) ([]byte, error) {
	dek, err := open(e.kek, s.WrappedDEK, aad)
	if err != nil {
		return nil, ErrOpen
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
