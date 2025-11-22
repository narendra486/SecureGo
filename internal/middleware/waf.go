package middleware

import (
	"net/http"

	coraza "github.com/corazawaf/coraza/v3"
)

// WAF wraps coraza to reject malicious requests when configured.
type WAF struct {
	engine coraza.WAF
}

// NewWAF builds a WAF from provided directives (rules). Caller should load CRS or custom rules.
func NewWAF(directives string) (*WAF, error) {
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		return nil, err
	}
	return &WAF{engine: w}, nil
}

// Middleware enforces WAF decision before hitting next handler.
func (w *WAF) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		tx := w.engine.NewTransaction()
		defer tx.Close()
		// Process request line.
		tx.ProcessConnection(r.RemoteAddr, 0, "", 0)
		tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
		for k, vals := range r.Header {
			for _, v := range vals {
				tx.AddRequestHeader(k, v)
			}
		}
		if it := tx.Interruption(); it != nil {
			status := it.Status
			if status == 0 {
				status = http.StatusForbidden
			}
			http.Error(rw, "request blocked", status)
			return
		}
		next.ServeHTTP(rw, r)
	})
}
