# SecureGO

SecureGO is a secure-by-default Go starter for HTTP, GraphQL, and gRPC services. The toolkit wraps standard libraries with safe defaults (tight timeouts, secure headers, CSRF-resilient JSON-only routes, hardened crypto, request IDs, panic recovery, and env-first configuration).

## Quick start

```bash
go run ./cmd/example-api         # HTTP on :8443 (or HTTP_ADDR)
GRPC_ADDR=:50051 go run ./cmd/example-api  # gRPC listener
```

Environment knobs:

- `HTTP_ADDR` / `GRPC_ADDR`: bind addresses (`:8443`, `:50051`).
- `TLS_CERT_FILE` / `TLS_KEY_FILE`: enable HTTPS when present.
- `TOKEN_KEY`: HMAC key for signing short-lived tokens (random one generated if missing).

## What’s included

- Hardened HTTP server (`internal/server`) with strict TLS/cipher defaults and timeouts.
- Middleware (`internal/middleware`): request IDs, panic recovery, body size limits, JSON-only enforcement, secure headers.
- Auth/crypto (`internal/auth`, `internal/crypto`): argon2id password hashing, signed opaque tokens, AEAD helpers, HKDF derivation, random token utilities.
- Auth protocols: RS256/RS512-only JWT validator with issuer/audience/alg whitelists, OAuth2 client helper, AEAD-backed session cookies, SAML validator skeleton with replay hook.
- Input validation (`internal/inputvalidation`): strict JSON decode, path traversal-safe joins, validator tags, and field/path/URL/file checks.
- Persistence helpers (`internal/persistence`): context deadlines and prepared statement enforcement.
- Secrets/config (`internal/secrets`): env validation with fail-fast required keys.
- Telemetry (`internal/telemetry`): UTC structured logging with redaction helpers.
- Sandbox (`pkg/sandbox`): shell-free command runner with allowlisted binaries and timeouts.
- GraphQL handler (`internal/graphqlapi`): JSON-only, 1MB body cap, introspection disabled by default, query length/depth/complexity limits.
- gRPC server (`internal/grpcapi`): interceptor chain for recovery, timeouts, logging, content-type allowlist (proto + optional JSON), health service, and message size limits.
- CSRF: double-submit cookie + `X-CSRF-Token` header with strong random tokens.
- Rate limiting: IP token-bucket middleware baseline.
- WAF hook: optional Coraza integration via `CORAZA_DIRECTIVES`.
- SSRF guard: outbound HTTP client wrapper blocking private/local IPs with timeouts (`internal/httpclient`).

## Extending

- Add custom middlewares (rate limiting, CSRF token checks, ownership checks) inside `internal/middleware`.
- Register real GraphQL schema and gRPC services in their respective packages.
- Wire database connections via `internal/persistence.SafeDB` and enforce prepared statements.
- Apply linting/security checks in CI: `go vet`, `staticcheck`, `gosec`, `govulncheck`, `semgrep` tuned to forbid unsafe patterns (raw SQL concatenation, shell exec, unbounded readers).
- Example Coraza CRS directives in `configs/waf.conf`; provide your own rule path.
- Optional semgrep baseline `.semgrep.yml` and `.golangci.yml` for local/CI linting.
