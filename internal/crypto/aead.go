package crypto

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEADBox wraps an AEAD cipher with nonce management.
type AEADBox struct {
	aead cipher.AEAD
}

// NewXChaCha20Poly1305 returns an AEADBox using a 32-byte key.
func NewXChaCha20Poly1305(key []byte) (*AEADBox, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}
	return &AEADBox{aead: a}, nil
}

// Seal encrypts the plaintext and returns nonce and ciphertext.
func (b *AEADBox) Seal(plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	nonce, err = RandomBytes(b.aead.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	ct := b.aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ct, nil
}

// Open decrypts ciphertext with the provided nonce and aad.
func (b *AEADBox) Open(nonce, ciphertext, aad []byte) ([]byte, error) {
	return b.aead.Open(nil, nonce, ciphertext, aad)
}
