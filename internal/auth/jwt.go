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
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTValidator validates JWTs with issuer/audience/alg whitelists and clock skew.
type JWTValidator struct {
	Issuer     string
	Audiences  []string
	Algorithms []string
	KeyFunc    jwt.Keyfunc
	ClockSkew  time.Duration
}

// Validate parses and validates a token string, returning claims map when valid.
func (v JWTValidator) Validate(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods(v.Algorithms),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(v.ClockSkew),
	)
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(tokenString, claims, v.KeyFunc)
	if err != nil {
		return nil, fmt.Errorf("jwt parse: %w", err)
	}
	if iss, ok := claims["iss"].(string); !ok || iss != v.Issuer {
		return nil, errors.New("invalid issuer")
	}
	if len(v.Audiences) > 0 {
		if !audContains(claims, v.Audiences) {
			return nil, errors.New("invalid audience")
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
