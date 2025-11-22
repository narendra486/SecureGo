package middleware

import (
	"net/http"
)

// RequireRole denies access unless the provided hasRole function returns true.
func RequireRole(hasRole func(r *http.Request, role string) bool, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !hasRole(r, role) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
