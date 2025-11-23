package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"Securego/internal/inputvalidation"
	jwt "github.com/golang-jwt/jwt/v5"
)

// Demo server with secure (/api) and vulnerable (/vuln) routes.
// Only XSS uses inputvalidation; other vulns are intentionally lax.
func main() {
	mux := http.NewServeMux()

	// Serve UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "src/demo/ui.html")
	})

	// Secure routes (minimal validation via internal/inputvalidation for XSS; CSRF/JWT guarding)
	mux.HandleFunc("/api/csrf", func(w http.ResponseWriter, r *http.Request) {
		token := issueCSRF(w)
		fmt.Fprintf(w, `{"csrf_token":"%s"}`, token)
	})

	mux.HandleFunc("/api/xss", func(w http.ResponseWriter, r *http.Request) {
		if !checkCSRF(w, r) || !checkJWT(r) {
			return
		}
		in := r.FormValue("input")
		if err := inputvalidation.LengthBetween(in, 1, 256); err != nil {
			http.Error(w, "invalid input", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.UTF8(in); err != nil {
			http.Error(w, "invalid utf-8", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, `{"status":"sanitized","echo":"%s"}`, html.EscapeString(in))
	})

	// Other secure routes: no deep validation here (demo), still require CSRF/JWT.
	mux.HandleFunc("/api/sqli", func(w http.ResponseWriter, r *http.Request) {
		if !checkCSRF(w, r) || !checkJWT(r) {
			return
		}
		fmt.Fprint(w, `{"status":"blocked","reason":"parameterized queries only"}`)
	})
	mux.HandleFunc("/api/ssrf", func(w http.ResponseWriter, r *http.Request) {
		if !checkCSRF(w, r) || !checkJWT(r) {
			return
		}
		fmt.Fprint(w, `{"status":"blocked","reason":"egress allowlist"}`)
	})
	mux.HandleFunc("/api/path", func(w http.ResponseWriter, r *http.Request) {
		if !checkCSRF(w, r) || !checkJWT(r) {
			return
		}
		fmt.Fprint(w, `{"status":"blocked","reason":"path traversal denied"}`)
	})
	mux.HandleFunc("/api/cmd", func(w http.ResponseWriter, r *http.Request) {
		if !checkCSRF(w, r) || !checkJWT(r) {
			return
		}
		fmt.Fprint(w, `{"status":"blocked","reason":"no shell exec on untrusted input"}`)
	})
	mux.HandleFunc("/api/idor", func(w http.ResponseWriter, r *http.Request) {
		if !checkCSRF(w, r) || !checkJWT(r) {
			return
		}
		resource := r.FormValue("user")
		if resource != "user" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"status":"blocked","reason":"requires subject=resource owner"}`)
	})
	mux.HandleFunc("/api/jwt/mint", func(w http.ResponseWriter, r *http.Request) {
		if !checkCSRF(w, r) {
			return
		}
		sub := r.FormValue("sub")
		if sub == "" {
			sub = "demo"
		}
		claims := jwt.MapClaims{"sub": sub, "iss": "securego", "exp": time.Now().Add(10 * time.Minute).Unix()}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, _ := tok.SignedString([]byte(jwtDemoKey))
		fmt.Fprintf(w, `{"token":"%s"}`, signed)
	})
	mux.HandleFunc("/api/jwt/validate", func(w http.ResponseWriter, r *http.Request) {
		if !checkCSRF(w, r) {
			return
		}
		raw := r.FormValue("token")
		if raw == "" {
			raw = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if raw == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}
		tok, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) { return []byte(jwtDemoKey), nil })
		if err != nil || !tok.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"status":"valid"}`)
	})
	mux.HandleFunc("/api/headers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "secure headers applied via middleware\n")
	})

	// Insecure routes
	users := map[string]struct {
		Email   string
		Balance int
	}{
		"user1331": {"1331@example.com", 100},
		"user1335": {"1335@example.com", 250},
		"user1337": {"1337@example.com", 500},
		"user1339": {"1339@example.com", 1000},
	}
	const weakSecret = "insecure-secret"

	mux.HandleFunc("/vuln/xss", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello %s", r.FormValue("input"))
	})
	mux.HandleFunc("/vuln/sqli", func(w http.ResponseWriter, r *http.Request) {
		u := r.FormValue("user")
		for name := range users {
			if u == "" || name == u {
				fmt.Fprintf(w, "%s,%s\n", name, users[name].Email)
			}
		}
	})
	mux.HandleFunc("/vuln/ssrf", func(w http.ResponseWriter, r *http.Request) {
		target := r.FormValue("url")
		resp, err := http.Get(target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	})
	mux.HandleFunc("/vuln/path", func(w http.ResponseWriter, r *http.Request) {
		path := r.FormValue("file")
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})
	mux.HandleFunc("/vuln/cmd", func(w http.ResponseWriter, r *http.Request) {
		host := r.FormValue("host")
		out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
		w.Write(out)
	})
	mux.HandleFunc("/vuln/idor", func(w http.ResponseWriter, r *http.Request) {
		u := r.FormValue("user")
		if u == "" {
			u = "user"
		}
		info, ok := users[u]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, "user=%s,email=%s,balance=%d\n", u, info.Email, info.Balance)
	})
	mux.HandleFunc("/vuln/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("user")
		claims := jwt.MapClaims{"sub": user, "iss": "vuln", "exp": time.Now().Add(2 * time.Hour).Unix()}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, _ := tok.SignedString([]byte(weakSecret))
		fmt.Fprintf(w, `{"access_token":"%s","token_type":"bearer"}`, signed)
	})
	mux.HandleFunc("/vuln/oauth/validate", func(w http.ResponseWriter, r *http.Request) {
		raw := r.FormValue("token")
		if raw == "" {
			raw = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if raw == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}
		tok, _ := jwt.Parse(raw, nil, jwt.WithoutClaimsValidation())
		fmt.Fprintf(w, "token accepted: %v\n", tok.Claims)
	})
	mux.HandleFunc("/vuln/jwt/mint", func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("sub")
		if user == "" {
			user = "guest"
		}
		claims := jwt.MapClaims{"sub": user, "iss": "vuln", "exp": time.Now().Add(2 * time.Hour).Unix()}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, _ := tok.SignedString([]byte(weakSecret))
		fmt.Fprintf(w, `{"token":"%s"}`, signed)
	})
	mux.HandleFunc("/vuln/jwt/validate", func(w http.ResponseWriter, r *http.Request) {
		raw := r.FormValue("token")
		if raw == "" {
			raw = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if raw == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}
		tok, _ := jwt.Parse(raw, nil, jwt.WithoutClaimsValidation())
		fmt.Fprintf(w, "token accepted (no sig check): %v\n", tok.Claims)
	})
	mux.HandleFunc("/vuln/csrf", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"csrf_token":"static-weak-token"}`)
	})
	mux.HandleFunc("/vuln/headers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "no security headers here\n")
	})

	addr := ":1337"
	log.Printf("Demo server listening on %s\n", addr)
	if err := http.ListenAndServe(addr, withSecurityHeaders(mux)); err != nil {
		log.Fatal(err)
	}
}

const csrfCookieName = "csrf_token"
const jwtDemoKey = "demo-securego-key"

func issueCSRF(w http.ResponseWriter) string {
	token := fmt.Sprintf("%d", time.Now().UnixNano())
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

func checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil {
		http.Error(w, "missing csrf cookie, call /api/csrf", http.StatusForbidden)
		return false
	}
	if r.Header.Get("X-CSRF-Token") == "" || r.Header.Get("X-CSRF-Token") != c.Value {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return false
	}
	return true
}

func checkJWT(r *http.Request) bool {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if raw == "" {
		return true // allow non-jwt calls in demo by default
	}
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		return []byte(jwtDemoKey), nil
	})
	if err != nil || !tok.Valid {
		return false
	}
	return true
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}
