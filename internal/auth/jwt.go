package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTValidator validates JWTs with issuer/audience/alg whitelists and clock skew.
type JWTValidator struct {
	Issuer            string
	Audiences         []string
	Algorithms        []string
	KeyFunc           jwt.Keyfunc
	ClockSkew         time.Duration
	RequireExpiration bool
	RequireNotBefore  bool
	RequireSubject    bool
	AllowedTypes      []string
	AllowedKids       []string
	SubjectValidator  func(string) error
}

// Validate parses and validates a token string, returning claims map when valid.
func (v JWTValidator) Validate(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods(v.Algorithms),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(v.ClockSkew),
	)
	claims := jwt.MapClaims{}
	tok, err := parser.ParseWithClaims(tokenString, claims, v.KeyFunc)
	if err != nil {
		return nil, fmt.Errorf("jwt parse: %w", err)
	}
	if tok.Method.Alg() == jwt.SigningMethodNone.Alg() {
		return nil, errors.New("none algorithm not allowed")
	}
	if len(v.Algorithms) > 0 && !inSlice(tok.Method.Alg(), v.Algorithms) {
		return nil, errors.New("unexpected signing algorithm")
	}
	if len(v.AllowedTypes) > 0 {
		typ, _ := tok.Header["typ"].(string)
		if typ == "" || !inSliceFold(typ, v.AllowedTypes) {
			return nil, errors.New("invalid typ header")
		}
	}
	if len(v.AllowedKids) > 0 {
		kid, _ := tok.Header["kid"].(string)
		if kid == "" || !inSlice(kid, v.AllowedKids) {
			return nil, errors.New("invalid kid header")
		}
	}
	if iss, ok := claims["iss"].(string); !ok || iss != v.Issuer {
		return nil, errors.New("invalid issuer")
	}
	if len(v.Audiences) > 0 {
		if !audContains(claims, v.Audiences) {
			return nil, errors.New("invalid audience")
		}
	}
	now := time.Now()
	if v.RequireExpiration {
		expRaw, ok := claims["exp"]
		if !ok {
			return nil, errors.New("exp required")
		}
		exp, err := timeFromClaim(expRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid exp: %w", err)
		}
		if now.After(exp.Add(v.ClockSkew)) {
			return nil, errors.New("token expired")
		}
	}
	if v.RequireNotBefore {
		nbfRaw, ok := claims["nbf"]
		if !ok {
			return nil, errors.New("nbf required")
		}
		nbf, err := timeFromClaim(nbfRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid nbf: %w", err)
		}
		if now.Add(v.ClockSkew).Before(nbf) {
			return nil, errors.New("token not yet valid")
		}
	}
	if v.RequireSubject {
		sub, ok := claims["sub"].(string)
		if !ok || strings.TrimSpace(sub) == "" {
			return nil, errors.New("subject required")
		}
		if v.SubjectValidator != nil {
			if err := v.SubjectValidator(sub); err != nil {
				return nil, fmt.Errorf("invalid subject: %w", err)
			}
		}
	}
	return claims, nil
}

func audContains(claims jwt.MapClaims, allowed []string) bool {
	raw, ok := claims["aud"]
	if !ok {
		return false
	}
	switch v := raw.(type) {
	case string:
		return inSlice(v, allowed)
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && inSlice(s, allowed) {
				return true
			}
		}
	}
	return false
}

func inSlice(val string, list []string) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}

func inSliceFold(val string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(v, val) {
			return true
		}
	}
	return false
}

func timeFromClaim(v any) (time.Time, error) {
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0), nil
	case int64:
		return time.Unix(t, 0), nil
	case int:
		return time.Unix(int64(t), 0), nil
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return time.Unix(i, 0), nil
		}
		if f, err := t.Float64(); err == nil {
			return time.Unix(int64(f), 0), nil
		}
	case string:
		if t == "" {
			return time.Time{}, errors.New("empty time value")
		}
		if i, err := strconv.ParseInt(t, 10, 64); err == nil {
			return time.Unix(i, 0), nil
		}
		if f, err := strconv.ParseFloat(t, 64); err == nil {
			return time.Unix(int64(f), 0), nil
		}
	}
	return time.Time{}, errors.New("unsupported time claim format")
}

// StaticKeyFunc returns a Keyfunc for HMAC/RS/ES/Ed keys.
func StaticKeyFunc(key any) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			b, ok := key.([]byte)
			if !ok {
				return nil, errors.New("expected HMAC key []byte")
			}
			return b, nil
		case *jwt.SigningMethodRSA:
			k, ok := key.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("expected RSA public key")
			}
			return k, nil
		case *jwt.SigningMethodECDSA:
			k, ok := key.(*ecdsa.PublicKey)
			if !ok {
				return nil, errors.New("expected ECDSA public key")
			}
			return k, nil
		case *jwt.SigningMethodEd25519:
			k, ok := key.(ed25519.PublicKey)
			if !ok {
				return nil, errors.New("expected ed25519 public key")
			}
			return k, nil
		default:
			return nil, errors.New("unsupported signing method")
		}
	}
}

// BearerExtractor pulls a bearer token from Authorization header.
func BearerExtractor(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errors.New("authorization header missing")
	}
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return "", errors.New("authorization not bearer")
	}
	return strings.TrimSpace(h[7:]), nil
}

// JWKS represents a JWKS set for remote keys.
type JWKS struct {
	Keys []json.RawMessage `json:"keys"`
}

// ParseRSAPublicKeyFromPEM parses a PEM-encoded RSA public key.
func ParseRSAPublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse rsa public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

// ParseEd25519PublicKeyFromPEM parses a PEM-encoded Ed25519 public key.
func ParseEd25519PublicKeyFromPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ed25519 public key: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an ed25519 public key")
	}
	return edPub, nil
}
