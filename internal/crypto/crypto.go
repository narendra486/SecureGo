package crypto

import (
	"crypto/hmac"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// RandomBytes returns cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := crypto_rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	return b, nil
}

// RandomString returns a URL-safe base64 encoded random string.
func RandomString(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DeriveKey uses HKDF-SHA256 to expand a secret into a key of length outLen.
func DeriveKey(secret, salt []byte, info string, outLen int) ([]byte, error) {
	h := hkdf.New(sha256.New, secret, salt, []byte(info))
	out := make([]byte, outLen)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return out, nil
}

// HMACSHA256 signs the message using the provided key.
func HMACSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// Equal reports constant-time equality of two byte slices.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
