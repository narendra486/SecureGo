package middleware

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"crypto/subtle"

	securecrypto "Securego/internal/crypto"
)

// CSRFConfig defines cookie/header names and token settings.
type CSRFConfig struct {
	CookieName string
	HeaderName string
	Path       string
	Domain     string
	MaxAge     time.Duration
	SameSite   http.SameSite
	Secure     bool
	HTTPOnly   bool
	TokenBytes int
}

// DefaultCSRFConfig returns secure defaults with random 32-byte tokens.
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		CookieName: "csrf_token",
		HeaderName: "X-CSRF-Token",
		Path:       "/",
		MaxAge:     8 * time.Hour,
		SameSite:   http.SameSiteStrictMode,
		Secure:     true,
		HTTPOnly:   false, // allow JS to read for SPA header placement (double-submit pattern)
		TokenBytes: 32,
	}
}

// CSRFMiddleware implements double-submit-cookie CSRF defense.
type CSRFMiddleware struct {
	cfg CSRFConfig
}

// NewCSRF constructs CSRFMiddleware with defaults merged.
func NewCSRF(cfg CSRFConfig) *CSRFMiddleware {
	def := DefaultCSRFConfig()
	if cfg.CookieName == "" {
		cfg.CookieName = def.CookieName
	}
	if cfg.HeaderName == "" {
		cfg.HeaderName = def.HeaderName
	}
	if cfg.Path == "" {
		cfg.Path = def.Path
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = def.MaxAge
	}
	if cfg.SameSite == 0 {
		cfg.SameSite = def.SameSite
	}
	if cfg.TokenBytes == 0 {
		cfg.TokenBytes = def.TokenBytes
	}
	cfg.Secure = cfg.Secure || def.Secure
	return &CSRFMiddleware{cfg: cfg}
}

// IssueToken sets a new CSRF cookie and returns the token.
func (c *CSRFMiddleware) IssueToken(w http.ResponseWriter) (string, error) {
	token, err := securecrypto.RandomString(c.cfg.TokenBytes)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     c.cfg.CookieName,
		Value:    token,
		Path:     c.cfg.Path,
		Domain:   c.cfg.Domain,
		MaxAge:   int(c.cfg.MaxAge.Seconds()),
		Secure:   c.cfg.Secure,
		HttpOnly: c.cfg.HTTPOnly,
		SameSite: c.cfg.SameSite,
	})
	return token, nil
}

// Middleware enforces CSRF token checks on state-changing methods.
func (c *CSRFMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		header := r.Header.Get(c.cfg.HeaderName)
		if header == "" {
			http.Error(w, "missing csrf token", http.StatusForbidden)
			return
		}
		cookie, err := r.Cookie(c.cfg.CookieName)
		if err != nil {
			http.Error(w, "missing csrf cookie", http.StatusForbidden)
			return
		}
		if !constantTimeEqual(header, cookie.Value) {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	switch strings.ToUpper(m) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(a), []byte(b)) != 1 {
		return false
	}
	return true
}

// EnsureCSRF ensures a token exists by setting one if absent.
func (c *CSRFMiddleware) EnsureCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(c.cfg.CookieName); err != nil {
			if _, err := c.IssueToken(w); err != nil {
				http.Error(w, "unable to set csrf token", http.StatusInternalServerError)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ValidateToken compares provided header token with cookie directly for custom handlers.
func (c *CSRFMiddleware) ValidateToken(r *http.Request) error {
	if isSafeMethod(r.Method) {
		return nil
	}
	h := r.Header.Get(c.cfg.HeaderName)
	if h == "" {
		return errors.New("missing csrf header")
	}
	cookie, err := r.Cookie(c.cfg.CookieName)
	if err != nil {
		return errors.New("missing csrf cookie")
	}
	if !constantTimeEqual(h, cookie.Value) {
		return errors.New("csrf token mismatch")
	}
	return nil
}
