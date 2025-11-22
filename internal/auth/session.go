package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

// SessionCodec issues and verifies encrypted+signed cookies using AEAD.
type SessionCodec struct {
	aead     cipher.AEAD
	Name     string
	Path     string
	Domain   string
	MaxAge   time.Duration
	SameSite http.SameSite
	Secure   bool
	HTTPOnly bool
}

// NewSessionCodec constructs an AEAD-backed cookie codec.
func NewSessionCodec(name string, key []byte) (*SessionCodec, error) {
	if len(key) != 32 {
		return nil, errors.New("session key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SessionCodec{
		aead:     aead,
		Name:     name,
		Path:     "/",
		MaxAge:   8 * time.Hour,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
		HTTPOnly: true,
	}, nil
}

// Set writes an encrypted session value to the response.
func (s *SessionCodec) Set(w http.ResponseWriter, value []byte) error {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := s.aead.Seal(nil, nonce, value, nil)
	token := append(nonce, ct...)
	encoded := base64.RawStdEncoding.EncodeToString(token)
	c := &http.Cookie{
		Name:     s.Name,
		Value:    encoded,
		Path:     s.Path,
		Domain:   s.Domain,
		Secure:   s.Secure,
		HttpOnly: s.HTTPOnly,
		SameSite: s.SameSite,
		MaxAge:   int(s.MaxAge.Seconds()),
	}
	http.SetCookie(w, c)
	return nil
}

// Clear removes the session cookie.
func (s *SessionCodec) Clear(w http.ResponseWriter) {
	c := &http.Cookie{
		Name:     s.Name,
		Value:    "",
		Path:     s.Path,
		Domain:   s.Domain,
		MaxAge:   -1,
		Secure:   s.Secure,
		HttpOnly: s.HTTPOnly,
		SameSite: s.SameSite,
	}
	http.SetCookie(w, c)
}

// Parse decrypts and verifies the session cookie value.
func (s *SessionCodec) Parse(r *http.Request) ([]byte, error) {
	c, err := r.Cookie(s.Name)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawStdEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, err
	}
	nonceSize := s.aead.NonceSize()
	if len(raw) < nonceSize {
		return nil, errors.New("token too short")
	}
	nonce := raw[:nonceSize]
	ct := raw[nonceSize:]
	return s.aead.Open(nil, nonce, ct, nil)
}
