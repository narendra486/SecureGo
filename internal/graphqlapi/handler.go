package graphqlapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"Securego/internal/middleware"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/handler"
)

// Config controls GraphQL exposure.
type Config struct {
	AllowIntrospection bool
	MaxBodyBytes       int64
	MaxQueryLength     int
	MaxOperationName   int
	MaxDepth           int
	MaxComplexity      int
}

// DefaultConfig sets secure defaults: introspection off, 1MB bodies.
func DefaultConfig() Config {
	return Config{
		AllowIntrospection: false,
		MaxBodyBytes:       1 << 20,
		MaxQueryLength:     4096,
		MaxOperationName:   64,
		MaxDepth:           8,
		MaxComplexity:      200,
	}
}

// NewHandler returns a secure GraphQL HTTP handler with a tiny default schema.
func NewHandler(cfg Config) (http.Handler, error) {
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	rootQuery := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"health": &graphql.Field{
				Type: graphql.String,
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return "ok", nil
				},
			},
		},
	})
	schema, err := graphql.NewSchema(graphql.SchemaConfig{Query: rootQuery})
	if err != nil {
		return nil, err
	}
	h := handler.New(&handler.Config{
		Schema:     &schema,
		Pretty:     false,
		GraphiQL:   false,
		Playground: false,
	})

	secureWrapper := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
			http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if !cfg.AllowIntrospection && containsIntrospection(body) {
			http.Error(w, "introspection disabled", http.StatusForbidden)
			return
		}
		if err := validateQuery(body, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		h.ServeHTTP(w, r)
	})

	// Wrap with JSON-only and body-size protections (redundant guard to ensure upstream handlers cannot bypass).
	return middleware.BodyLimit(cfg.MaxBodyBytes)(middleware.RequireJSON(secureWrapper)), nil
}

func containsIntrospection(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "__schema") || strings.Contains(lower, "__type")
}

type gqlRequest struct {
	Query         string          `json:"query"`
	OperationName string          `json:"operationName,omitempty"`
	Variables     json.RawMessage `json:"variables,omitempty"`
}

func validateQuery(body []byte, cfg Config) error {
	var req gqlRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected extra input")
	}
	q := strings.TrimSpace(req.Query)
	if q == "" {
		return errors.New("query required")
	}
	if cfg.MaxQueryLength > 0 && len(q) > cfg.MaxQueryLength {
		return errors.New("query too large")
	}
	if cfg.MaxDepth > 0 && depth(q) > cfg.MaxDepth {
		return fmt.Errorf("query depth exceeded")
	}
	if cfg.MaxComplexity > 0 && complexity(q) > cfg.MaxComplexity {
		return fmt.Errorf("query complexity exceeded")
	}
	op := strings.TrimSpace(req.OperationName)
	if op != "" {
		if cfg.MaxOperationName > 0 && len(op) > cfg.MaxOperationName {
			return errors.New("operation name too long")
		}
		if strings.ContainsAny(op, " \t\r\n") {
			return errors.New("operation name must not contain whitespace")
		}
	}
	return nil
}

// depth/complexity are lightweight heuristic guards to deter expensive queries.
func depth(q string) int {
	max := 0
	cur := 0
	for _, r := range q {
		switch r {
		case '{':
			cur++
			if cur > max {
				max = cur
			}
		case '}':
			if cur > 0 {
				cur--
			}
		}
	}
	return max
}

func complexity(q string) int {
	c := 0
	for _, r := range q {
		if r == '{' || r == '}' || r == ',' {
			c++
		}
	}
	return c
}
