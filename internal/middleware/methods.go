package middleware

import (
	"net/http"
	"strings"
)

// Methods restricts handlers to an allowlist of HTTP methods.
func Methods(allowed ...string) func(http.Handler) http.Handler {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, m := range allowed {
		allowedSet[strings.ToUpper(m)] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := allowedSet[r.Method]; !ok {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
