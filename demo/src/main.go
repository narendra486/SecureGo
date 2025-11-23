package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"Securego/internal/auth"
	"Securego/internal/graphqlapi"
	"Securego/internal/grpcapi"
	"Securego/internal/httpclient"
	"Securego/internal/inputvalidation"
	"Securego/internal/middleware"
	"Securego/internal/persistence"
	"Securego/internal/telemetry"

	jwt "github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

var (
	allowedIdent = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	allowedHost  = regexp.MustCompile(`^[A-Za-z0-9\.-:]+$`)
)

// Demo server with secure (/secure) and vulnerable (/vuln) routes.
// Secure flows are wired through internal packages only (validation, JWT, SSRF guard, persistence, GraphQL/gRPC).
func main() {
	logger := telemetry.NewLogger()
	jwtKey := mustRSAPrivateKey()
	jwtValidator := auth.JWTValidator{
		Issuer:     "securego",
		Audiences:  []string{"securego"},
		Algorithms: []string{jwt.SigningMethodRS256.Alg()},
		KeyFunc:    auth.StaticKeyFunc(&jwtKey.PublicKey),
		ClockSkew:  30 * time.Second,
	}
	csrf := middleware.NewCSRF(middleware.CSRFConfig{
		Secure:         false, // demo runs over HTTP; keep secure flag for HTTPS deployments
		ValidateOrigin: false,
		SameSite:       http.SameSiteLaxMode,
	})
	safeDB := mustInitDB()
	startGRPC(logger)

	mux := http.NewServeMux()

	// Serve UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	// Secure routes (validation via /internal packages only)
	mux.HandleFunc("/secure/xss", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		in := r.FormValue("input")
		if err := inputvalidation.LengthBetween(in, 1, 256); err != nil {
			http.Error(w, "invalid input", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.UTF8(in); err != nil {
			http.Error(w, "invalid utf-8", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><html><body><p>Echo: <span>%s</span></p></body></html>", html.EscapeString(in))
	}))

	mux.HandleFunc("/secure/sqli", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("user")
		if err := inputvalidation.LengthBetween(user, 1, 64); err != nil {
			http.Error(w, "invalid user", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.UTF8(user); err != nil {
			http.Error(w, "invalid utf-8", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.MatchesRegex(user, allowedIdent); err != nil {
			http.Error(w, "invalid user characters", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"status":"blocked","reason":"parameterized queries only"}`)
	}))

	mux.HandleFunc("/secure/db", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("user")
		if err := inputvalidation.LengthBetween(user, 3, 32); err != nil {
			http.Error(w, "invalid user", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.MatchesRegex(user, allowedIdent); err != nil {
			http.Error(w, "invalid user characters", http.StatusBadRequest)
			return
		}
		var balance int
		if err := safeDB.QueryRow(r.Context(), "SELECT balance FROM accounts WHERE user = ?", user).Scan(&balance); err != nil {
			http.Error(w, "not found or error", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"user":"%s","balance":%d}`, user, balance)
	}))

	mux.HandleFunc("/secure/ssrf", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		raw := r.FormValue("url")
		if err := inputvalidation.ValidateURL(raw, []string{"http", "https"}, nil); err != nil {
			http.Error(w, "invalid url", http.StatusBadRequest)
			return
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			http.Error(w, "invalid url host", http.StatusBadRequest)
			return
		}
		client := httpclient.New()
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, raw, nil)
		if err != nil {
			http.Error(w, "invalid url", http.StatusBadRequest)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "blocked: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"fetched","code":%d}`, resp.StatusCode)
	}))

	mux.HandleFunc("/secure/path", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		path := r.FormValue("file")
		if err := inputvalidation.LengthBetween(path, 1, 256); err != nil {
			http.Error(w, "invalid file", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.UTF8(path); err != nil {
			http.Error(w, "invalid utf-8", http.StatusBadRequest)
			return
		}
		if _, err := inputvalidation.SanitizePath(".", path); err != nil {
			http.Error(w, "path traversal denied", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"status":"blocked","reason":"path traversal denied"}`)
	}))

	mux.HandleFunc("/secure/cmd", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		host := r.FormValue("host")
		if err := inputvalidation.LengthBetween(host, 1, 128); err != nil {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.UTF8(host); err != nil {
			http.Error(w, "invalid utf-8", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.MatchesRegex(host, allowedHost); err != nil {
			http.Error(w, "invalid host characters", http.StatusBadRequest)
			return
		}
		// Secure variant disables command execution entirely.
		fmt.Fprint(w, `{"status":"blocked","reason":"command execution disabled"}`)
	}))

	mux.HandleFunc("/secure/idor", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		resource := r.FormValue("user")
		if err := inputvalidation.LengthBetween(resource, 1, 64); err != nil {
			http.Error(w, "invalid user", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.UTF8(resource); err != nil {
			http.Error(w, "invalid utf-8", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.MatchesRegex(resource, allowedIdent); err != nil {
			http.Error(w, "invalid user characters", http.StatusBadRequest)
			return
		}
		if resource == "" {
			http.Error(w, "user required", http.StatusBadRequest)
			return
		}
		if resource != "user1334" {
			http.Error(w, "invalid user", http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"status":"valid","user":"user1334"}`)
	}))

	mux.HandleFunc("/secure/csrf", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token, err := csrf.IssueToken(w)
		if err != nil {
			http.Error(w, "could not issue csrf token", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `{"csrf_token":"%s"}`, token)
	})

	mux.HandleFunc("/secure/jwt/mint", func(w http.ResponseWriter, r *http.Request) {
		sub := r.FormValue("username")
		if sub == "" {
			sub = "guest"
		}
		if err := inputvalidation.LengthBetween(sub, 1, 128); err != nil {
			http.Error(w, "invalid username", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.UTF8(sub); err != nil {
			http.Error(w, "invalid utf-8", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.MatchesRegex(sub, allowedIdent); err != nil {
			http.Error(w, "invalid username characters", http.StatusBadRequest)
			return
		}
		claims := jwt.MapClaims{"sub": sub, "iss": "securego", "aud": "securego", "exp": time.Now().Add(10 * time.Minute).Unix()}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed, _ := tok.SignedString(jwtKey)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":   signed,
			"alg":     tok.Method.Alg(),
			"payload": claims,
		})
	})

	mux.HandleFunc("/secure/jwt/validate", func(w http.ResponseWriter, r *http.Request) {
		raw := r.FormValue("token")
		if raw == "" {
			raw, _ = auth.BearerExtractor(r)
		}
		if raw == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.LengthBetween(raw, 16, 4096); err != nil {
			http.Error(w, "invalid token", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.UTF8(raw); err != nil {
			http.Error(w, "invalid utf-8", http.StatusBadRequest)
			return
		}
		if _, err := jwtValidator.Validate(r.Context(), raw); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"status":"valid"}`)
	})

	mux.HandleFunc("/secure/headers", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		// Add commonly recommended security headers; middleware sets most, fill gaps here.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		// CORS for demo visibility.
		w.Header().Set("Access-Control-Allow-Origin", "https://example.com")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "Security headers applied. Inspect the response headers.")
	}))

	mux.HandleFunc("/secure/error", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		cause := r.FormValue("cause")
		if err := inputvalidation.LengthBetween(cause, 1, 128); err != nil {
			http.Error(w, "invalid cause", http.StatusBadRequest)
			return
		}
		if err := inputvalidation.UTF8(cause); err != nil {
			http.Error(w, "invalid utf-8", http.StatusBadRequest)
			return
		}
		lower := strings.ToLower(cause)
		if strings.Contains(lower, "panic") || strings.Contains(cause, "!") {
			// Let recovery middleware return a generic 500 without stack leakage.
			panic("demo panic")
		}
		http.Error(w, "something went wrong", http.StatusInternalServerError)
	}))

	gqlHandler, _ := graphqlapi.NewHandler(graphqlapi.DefaultConfig())
	mux.Handle("/secure/graphql", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if ct := strings.ToLower(r.Header.Get("Content-Type")); ct != "" && !strings.HasPrefix(ct, "application/json") {
			http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		gqlHandler.ServeHTTP(w, r)
	}))

	// Insecure routes
	users := map[string]struct {
		Email   string
		Balance int
	}{
		"user1334": {"1331@example.com", 100},
		"user1335": {"1335@example.com", 250},
		"user1336": {"1337@example.com", 500},
		"user1337": {"1339@example.com", 1000},
	}
	const weakSecret = "insecure-secret"

	mux.HandleFunc("/vuln/xss", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><html><body>Hello %s</body></html>", r.FormValue("input"))
	})
	mux.HandleFunc("/vuln/sqli", func(w http.ResponseWriter, r *http.Request) {
		u := r.FormValue("user")
		w.Header().Set("Content-Type", "application/json")
		if u == "" {
			w.Write([]byte(`{"error":"user parameter required"}`))
			return
		}
		upper := strings.ToUpper(u)
		if u == "*" ||
			strings.Contains(upper, "' OR TRUE") ||
			strings.Contains(upper, " OR 1=1") {
			io.WriteString(w, `{"users":[`)
			first := true
			for name, info := range users {
				if !first {
					io.WriteString(w, ",")
				}
				first = false
				fmt.Fprintf(w, `{"user":"%s","email":"%s","balance":%d}`, name, info.Email, info.Balance)
			}
			io.WriteString(w, `]}`)
			return
		}
		if strings.Contains(upper, " OR FALSE") || strings.Contains(upper, "1=2") {
			w.Write([]byte(`{"rows":0,"error":"no rows (boolean false)"}`))
			return
		}
		if info, ok := users[u]; ok {
			fmt.Fprintf(w, `{"user":"%s","email":"%s","balance":%d}`, u, info.Email, info.Balance)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
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
		out, _ := exec.Command("sh", "-c", "ping -c 1 "+host+"; whoami; uname -a").CombinedOutput()
		resp := string(out)
		if strings.Contains(resp, "connect: Connection refused") {
			resp = strings.ReplaceAll(resp, "connect: Connection refused", "connect: connection Succesfully!")
		}
		w.Write([]byte(resp))
	})
	mux.HandleFunc("/vuln/idor", func(w http.ResponseWriter, r *http.Request) {
		u := r.FormValue("user")
		if u == "" {
			http.Error(w, "user parameter required (e.g., user1334)", http.StatusBadRequest)
			return
		}
		info, ok := users[u]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, "user=%s,email=%s,balance=%d\n", u, info.Email, info.Balance)
	})
	mux.HandleFunc("/vuln/jwt/mint", func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("sub")
		if user == "" {
			user = "guest"
		}
		claims := jwt.MapClaims{"sub": user, "iss": "vuln", "exp": time.Now().Add(2 * time.Hour).Unix()}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed, _ := tok.SignedString(jwtKey)
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
		tok, _ := jwt.Parse(raw, auth.StaticKeyFunc(&jwtKey.PublicKey), jwt.WithoutClaimsValidation(), jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
		fmt.Fprintf(w, "token accepted (claims not validated, RS256 only): %v\n", tok.Claims)
	})
	mux.HandleFunc("/vuln/error", func(w http.ResponseWriter, r *http.Request) {
		cause := r.FormValue("cause")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		if cause == "panic" {
			w.Write([]byte("panic: demo panic\n"))
		} else {
			w.Write([]byte("error: something went wrong\n"))
		}
		w.Write(debug.Stack())
	})
	mux.HandleFunc("/vuln/csrf", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"csrf_token":"static-weak-token"}`)
	})
	mux.HandleFunc("/vuln/headers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "no security headers here\n")
	})
	mux.HandleFunc("/vuln/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sample := `{
  "data": {
    "__schema": {
      "queryType": { "name": "Query" },
      "mutationType": null,
      "types": [
        { "kind": "OBJECT", "name": "Query", "fields": [{ "name": "hello", "type": { "name": "String", "kind": "SCALAR" } }] },
        { "kind": "SCALAR", "name": "String", "fields": null }
      ]
    }
  }
}`
		fmt.Fprint(w, sample)
	})

	addr := ":1337"
	log.Printf("Demo server listening on %s\n", addr)
	secured := middleware.Recovery(
		middleware.BodyLimit(1 << 20)(mux),
	)
	if err := http.ListenAndServe(addr, secured); err != nil {
		log.Fatal(err)
	}
}

func secureHandler(csrf *middleware.CSRFMiddleware, validator *auth.JWTValidator, next http.HandlerFunc) http.HandlerFunc {
	csrfProtected := csrf.EnsureCSRF(csrf.Middleware(http.HandlerFunc(next)))
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := auth.BearerExtractor(r)
		if raw != "" {
			if _, err := validator.Validate(r.Context(), raw); err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
		}
		csrfProtected.ServeHTTP(w, r)
	}
}

func mustRSAPrivateKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func mustInitDB() persistence.SafeDB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal(err)
	}
	persistence.Configure(db)
	safe := persistence.SafeDB{DB: db, DefaultTimeout: 2 * time.Second}
	_, _ = safe.Exec(context.Background(), "CREATE TABLE accounts(user TEXT PRIMARY KEY, balance INTEGER)")
	for user, bal := range map[string]int{"user1334": 100, "user1335": 250, "user1337": 500, "user1339": 1000} {
		_, _ = safe.Exec(context.Background(), "INSERT INTO accounts(user, balance) VALUES(?, ?)", user, bal)
	}
	return safe
}

func startGRPC(logger telemetry.Logger) {
	go func() {
		lis, err := net.Listen("tcp", ":1338")
		if err != nil {
			logger.Error("grpc listen failed", "err", err)
			return
		}
		s := grpcapi.NewServer(logger, grpcapi.DefaultConfig())
		grpcapi.RegisterPing(s, nil)
		logger.Info("grpc server listening", "addr", ":1338")
		if err := s.Serve(lis); err != nil && !strings.Contains(err.Error(), "closed") {
			logger.Error("grpc serve failed", "err", err)
		}
	}()
}

func init() {
	// Demo ignores SECUREGO_MASTER_KEY; production should set and require secrets explicitly.
}

// demoSecurityHeaders sets a minimal header baseline without CSP so inline styles work.
func demoSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
