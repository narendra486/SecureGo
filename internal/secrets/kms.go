package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

// DecryptEnv loads a base64-encoded AES-GCM encrypted value from envKey using the provided 32-byte master key.
// This is a lightweight stand-in for KMS-decrypted secrets when running locally.
func DecryptEnv(envKey string, masterKey []byte) ([]byte, error) {
	enc := os.Getenv(envKey)
	if enc == "" {
		return nil, fmt.Errorf("env %s missing", envKey)
	}
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be 32 bytes for AES-256-GCM")
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("decode env: %w", err)
	}
	if len(raw) < 12 {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:12], raw[12:]
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plain, nil
}
