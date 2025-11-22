package crypto

import (
	"fmt"

	siv "github.com/secure-io/siv-go"
)

// SIV provides deterministic AEAD (SIV mode) for misuse resistance.
type SIV struct {
	aead cipherAEAD
}

type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
}

// NewSIV creates a new AES-SIV-CMAC AEAD with the provided key (32/48/64 bytes).
func NewSIV(key []byte) (*SIV, error) {
	a, err := siv.NewCMAC(key)
	if err != nil {
		return nil, fmt.Errorf("siv init: %w", err)
	}
	return &SIV{aead: a}, nil
}

// Seal appends authenticated ciphertext; nonce may be empty (SIV is deterministic).
func (s *SIV) Seal(plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, 0)
	ct := s.aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ct, nil
}

// Open decrypts ciphertext with AAD.
func (s *SIV) Open(nonce, ciphertext, aad []byte) ([]byte, error) {
	return s.aead.Open(nil, nonce, ciphertext, aad)
}
