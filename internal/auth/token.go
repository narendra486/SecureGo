package auth

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	internalcrypto "Securego/internal/crypto"
)

// SignedToken issues and verifies short-lived opaque tokens using HMAC-SHA256.
type SignedToken struct {
	Key []byte
	TTL time.Duration
}

// Mint returns a URL-safe token containing expiry and MAC.
func (t SignedToken) Mint() (string, error) {
	if len(t.Key) < 16 {
		return "", errors.New("token key too short")
	}
	nonce, err := internalcrypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	exp := time.Now().Add(t.TTL).Unix()
	buf := make([]byte, 16+8)
	copy(buf[:16], nonce)
	binary.BigEndian.PutUint64(buf[16:], uint64(exp))
	mac := internalcrypto.HMACSHA256(t.Key, buf)
	full := append(buf, mac...)
	return base64.RawURLEncoding.EncodeToString(full), nil
}

// Verify parses and validates a token, returning its expiry.
func (t SignedToken) Verify(token string) (time.Time, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode token: %w", err)
	}
	if len(raw) < 16+8+sha256Size {
		return time.Time{}, errors.New("token too short")
	}
	body := raw[:24]
	sig := raw[24:]
	expected := internalcrypto.HMACSHA256(t.Key, body)
	if !internalcrypto.Equal(expected, sig) {
		return time.Time{}, errors.New("invalid token signature")
	}
	exp := int64(binary.BigEndian.Uint64(body[16:]))
	expiry := time.Unix(exp, 0)
	if time.Now().After(expiry) {
		return time.Time{}, errors.New("token expired")
	}
	return expiry, nil
}

const sha256Size = 32
