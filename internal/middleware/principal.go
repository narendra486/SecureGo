package middleware

import (
	"net/http"

	"Securego/internal/security"
)

// RequirePrincipal ensures a principal is present in context; returns 401 if missing.
func RequirePrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := security.FromContext(r.Context()); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
