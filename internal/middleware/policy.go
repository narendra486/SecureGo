package middleware

import (
	"net/http"
)

// PolicyChecker evaluates whether a principal may perform an action on a resource.
// Implementations should derive principal/attributes from the request (e.g., context).
type PolicyChecker func(r *http.Request, action, resource string) bool

// EnforcePolicy wraps a handler with a policy decision for a given action/resource.
// Returns 403 when the checker denies access.
func EnforcePolicy(action, resource string, checker PolicyChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil || !checker(r, action, resource) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
