package middleware

import "net/http"

// RequireOwnership enforces ownership/ABAC via a custom decision function.
// The checker should return true when the caller is authorized for the resource.
func RequireOwnership(check func(r *http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if check == nil || !check(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
