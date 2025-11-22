package middleware

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"crypto/subtle"
	"net/url"

	securecrypto "Securego/internal/crypto"
)

// CSRFConfig defines cookie/header names and token settings.
type CSRFConfig struct {
	CookieName     string
	HeaderName     string
	Path           string
	Domain         string
	MaxAge         time.Duration
	SameSite       http.SameSite
	Secure         bool
	HTTPOnly       bool
	TokenBytes     int
	ExposeHeader   bool
	ValidateOrigin bool
	AllowedOrigins []string
	AllowedHosts   []string
}

// DefaultCSRFConfig returns secure defaults with random 32-byte tokens.
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		CookieName:     "csrf_token",
		HeaderName:     "X-CSRF-Token",
		Path:           "/",
		MaxAge:         2 * time.Hour,
		SameSite:       http.SameSiteStrictMode,
		Secure:         true,
		HTTPOnly:       true,
		TokenBytes:     64, // 64 bytes (~86 chars base64url) for stronger entropy
		ExposeHeader:   true,
		ValidateOrigin: true,
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
	if !cfg.ExposeHeader {
		cfg.ExposeHeader = def.ExposeHeader
	}
	if cfg.AllowedOrigins == nil {
		cfg.AllowedOrigins = def.AllowedOrigins
	}
	if cfg.AllowedHosts == nil {
		cfg.AllowedHosts = def.AllowedHosts
	}
	return &CSRFMiddleware{cfg: cfg}
}

// IssueToken sets a new CSRF cookie and returns the token.
func (c *CSRFMiddleware) IssueToken(w http.ResponseWriter) (string, error) {
	token, err := securecrypto.RandomString(c.cfg.TokenBytes)
	if err != nil {
		return "", err
	}
	if c.cfg.ExposeHeader {
		w.Header().Set(c.cfg.HeaderName, token)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     c.cfg.CookieName,
		Value:    token,
		Path:     c.cfg.Path,
		Domain:   c.cfg.Domain,
		MaxAge:   int(c.cfg.MaxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: c.cfg.SameSite,
	})
	return token, nil
}

// Middleware enforces CSRF token checks on state-changing methods.
func (c *CSRFMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			// Ensure a token exists for subsequent unsafe requests.
			_, _ = c.ensureToken(w, r)
			next.ServeHTTP(w, r)
			return
		}
		if c.cfg.ValidateOrigin && !originAllowed(r, c.cfg.AllowedOrigins, c.cfg.AllowedHosts) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
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
		// Rotate token after successful validation to reduce replay window.
		_, _ = c.ensureToken(w, r)
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
		_, _ = c.ensureToken(w, r)
		next.ServeHTTP(w, r)
	})
}

// ValidateToken compares provided header token with cookie directly for custom handlers.
func (c *CSRFMiddleware) ValidateToken(r *http.Request) error {
	if isSafeMethod(r.Method) {
		return nil
	}
	if c.cfg.ValidateOrigin && !originAllowed(r, c.cfg.AllowedOrigins, c.cfg.AllowedHosts) {
		return errors.New("origin not allowed")
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

func (c *CSRFMiddleware) ensureToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if _, err := r.Cookie(c.cfg.CookieName); err == nil {
		return "", nil
	}
	return c.IssueToken(w)
}

func originAllowed(r *http.Request, allowedOrigins, allowedHosts []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
		if origin == "" {
			return false
		}
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if len(allowedOrigins) > 0 {
		for _, o := range allowedOrigins {
			if strings.EqualFold(origin, o) {
				return true
			}
		}
		return false
	}
	if len(allowedHosts) > 0 {
		for _, h := range allowedHosts {
			if strings.EqualFold(host, h) {
				return true
			}
		}
		return false
	}
	return strings.EqualFold(host, r.Host)
}
