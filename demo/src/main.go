package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
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

// Demo server with secure (/api) and vulnerable (/vuln) routes.
// Secure flows are wired through internal packages only (validation, CSRF, JWT, sandbox, SSRF guard, persistence, GraphQL/gRPC).
func main() {
	logger := telemetry.NewLogger()
	csrf := middleware.NewCSRF(middleware.CSRFConfig{
		Secure:         false, // allow http demo locally
		HTTPOnly:       true,
		ValidateOrigin: false,
	})
	jwtKey := mustRSAPrivateKey()
	jwtValidator := auth.JWTValidator{
		Issuer:     "securego",
		Audiences:  []string{"securego"},
		Algorithms: []string{jwt.SigningMethodRS256.Alg()},
		KeyFunc:    auth.StaticKeyFunc(&jwtKey.PublicKey),
		ClockSkew:  30 * time.Second,
	}
	safeDB := mustInitDB()
	startGRPC(logger)

	mux := http.NewServeMux()

	// Serve UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	// Secure routes (validation via /internal packages only)
	mux.HandleFunc("/api/csrf", func(w http.ResponseWriter, r *http.Request) {
		token, err := csrf.IssueToken(w)
		if err != nil {
			http.Error(w, "csrf issue failed", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `{"csrf_token":"%s"}`, token)
	})

	mux.HandleFunc("/api/xss", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
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
	}))

	mux.HandleFunc("/api/sqli", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"blocked","reason":"parameterized queries only"}`)
	}))

	mux.HandleFunc("/api/db", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("user")
		if err := inputvalidation.LengthBetween(user, 3, 32); err != nil {
			http.Error(w, "invalid user", http.StatusBadRequest)
			return
		}
		var balance int
		if err := safeDB.QueryRow(r.Context(), "SELECT balance FROM accounts WHERE user = ?", user).Scan(&balance); err != nil {
			http.Error(w, "not found or error", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"user":"%s","balance":%d}`, user, balance)
	}))

	mux.HandleFunc("/api/ssrf", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		raw := r.FormValue("url")
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

	mux.HandleFunc("/api/path", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"blocked","reason":"path traversal denied"}`)
	}))

	mux.HandleFunc("/api/cmd", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		// Secure variant disables command execution entirely.
		fmt.Fprint(w, `{"status":"blocked","reason":"command execution disabled"}`)
	}))

	mux.HandleFunc("/api/idor", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		resource := r.FormValue("user")
		if resource != "user" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"status":"blocked","reason":"requires subject=resource owner"}`)
	}))

	mux.HandleFunc("/api/jwt/mint", func(w http.ResponseWriter, r *http.Request) {
		if err := csrf.ValidateToken(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		sub := r.FormValue("sub")
		if sub == "" {
			sub = "demo"
		}
		claims := jwt.MapClaims{"sub": sub, "iss": "securego", "aud": "securego", "exp": time.Now().Add(10 * time.Minute).Unix()}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed, _ := tok.SignedString(jwtKey)
		fmt.Fprintf(w, `{"token":"%s"}`, signed)
	})

	mux.HandleFunc("/api/jwt/validate", func(w http.ResponseWriter, r *http.Request) {
		if err := csrf.ValidateToken(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		raw := r.FormValue("token")
		if raw == "" {
			raw, _ = auth.BearerExtractor(r)
		}
		if raw == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}
		if _, err := jwtValidator.Validate(r.Context(), raw); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"status":"valid"}`)
	})

	mux.HandleFunc("/api/headers", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"applied","headers":"strict CSP/HSTS/frame/xct options via middleware"}`)
	})

	gqlHandler, _ := graphqlapi.NewHandler(graphqlapi.DefaultConfig())
	mux.Handle("/api/graphql", secureHandler(csrf, &jwtValidator, func(w http.ResponseWriter, r *http.Request) {
		gqlHandler.ServeHTTP(w, r)
	}))

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
			http.Error(w, "user parameter required (e.g., user1331)", http.StatusBadRequest)
			return
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
	secured := middleware.RequestID(
		middleware.Recovery(
			middleware.SecurityHeaders(
				middleware.BodyLimit(1 << 20)(mux),
			),
		),
	)
	if err := http.ListenAndServe(addr, secured); err != nil {
		log.Fatal(err)
	}
}

func secureHandler(csrf *middleware.CSRFMiddleware, validator *auth.JWTValidator, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := csrf.ValidateToken(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		raw, _ := auth.BearerExtractor(r)
		if raw != "" {
			if _, err := validator.Validate(r.Context(), raw); err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
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
	for user, bal := range map[string]int{"user1331": 100, "user1335": 250, "user1337": 500, "user1339": 1000} {
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
