package security

import "context"

// Principal carries authenticated identity and roles for access decisions.
type Principal struct {
	ID    string
	Roles []string
}

type ctxKey struct{}

// WithPrincipal stores principal in context.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext retrieves principal if present.
func FromContext(ctx context.Context) (Principal, bool) {
	val := ctx.Value(ctxKey{})
	if val == nil {
		return Principal{}, false
	}
	p, ok := val.(Principal)
	return p, ok
}

// HasRole checks if the principal has the given role.
func HasRole(p Principal, role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}
