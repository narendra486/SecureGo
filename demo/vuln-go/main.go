package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// WARNING: This server is intentionally vulnerable for testing.
func main() {
	type profile struct {
		ID       int
		Username string
		Password string
		Email    string
		Balance  int
		Role     string
	}
	users := []profile{
		{1, "admin", "secret", "admin@example.com", 100000, "admin"},
		{2, "user", "password", "user@example.com", 250, "user"},
		{3, "alice", "alicepwd", "alice@example.com", 500, "user"},
	}
	userByName := map[string]profile{}
	for _, u := range users {
		userByName[u.Username] = u
	}

	const insecureJWTSecret = "insecure-secret"

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Vuln-Go: intentionally insecure demo. Endpoints: /xss?input=, /sqli?user=, /path?file=, /ssrf?url=, /cmd?host=, /idor?user=, /oauth/token?user=, /oauth/validate?token=")
	})

	// Reflected XSS
	http.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		in := r.URL.Query().Get("input")
		fmt.Fprintf(w, "Hello %s", in) // no escaping
	})

	// SQLi (string concat)
	http.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		for _, u := range users {
			if user == "" || u.Username == user {
				fmt.Fprintf(w, "%d,%s,%s\n", u.ID, u.Username, u.Password)
			}
		}
	})

	// Path traversal
	http.HandleFunc("/path", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		data, err := os.ReadFile(file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	// SSRF
	http.HandleFunc("/ssrf", func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		resp, err := http.Get(url)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	})

	// Command injection
	http.HandleFunc("/cmd", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		out, err := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(out)
	})

	// IDOR: no authz check, returns any user profile by query param.
	http.HandleFunc("/idor", func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("user")
		u, ok := userByName[username]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, "user=%s,email=%s,balance=%d,role=%s\n", u.Username, u.Email, u.Balance, u.Role)
	})

	// Insecure OAuth-like token mint: no client validation, weak HS256 secret.
	http.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if user == "" {
			user = "guest"
		}
		scope := r.URL.Query().Get("scope")
		claims := jwt.MapClaims{
			"sub":   user,
			"scope": scope,
			"iss":   "vulngo",
			"exp":   time.Now().Add(2 * time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, _ := token.SignedString([]byte(insecureJWTSecret))
		fmt.Fprintf(w, `{"access_token":"%s","token_type":"bearer","expires_in":7200}`, signed)
	})

	// Insecure token "validation": parses without signature verification.
	http.HandleFunc("/oauth/validate", func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("token")
		if raw == "" {
			raw = r.Header.Get("Authorization")
		}
		if raw == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}
		tok, _ := jwt.Parse(raw, nil, jwt.WithoutClaimsValidation())
		fmt.Fprintf(w, "token accepted: %v\n", tok.Claims)
	})

	log.Println("Vuln-Go running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
