# Securego Architecture Overview

High-level map of what lives where:

- `cmd/example-api/`: sample HTTP server showing middleware chain, CSRF, JWT/session demos, GraphQL, gRPC.
- `internal/middleware/`: HTTP middleware (secure headers, panic recovery, body caps, CSRF, rate limiting, WAF hook, authZ scaffolds).
- `internal/server/`: hardened HTTP server construction (timeouts/TLS).
- `internal/auth/`: JWT validation, password KDFs, session cookies, opaque tokens, OAuth2 server scaffold, SAML skeleton.
- `internal/validation/`: strict JSON decoding, validator tags, regex/allowlist/length, path/URL and file checks.
- `internal/encoding/`: safe escaping helpers (HTML/attr/URL).
- `internal/security/`: principal context helpers for consistent authZ decisions.
- `internal/crypto/`: AEAD/SIV encryption, HKDF/HMAC, randoms, const-time compares.
- `internal/httpclient/`: SSRF-safe outbound client.
- `pkg/sandbox/`: safe subprocess runner (no shell expansion).
- `internal/persistence/`: DB helper enforcing prepared statements and timeouts.
- `internal/graphqlapi/` / `internal/grpcapi/`: hardened handlers/servers for GraphQL and gRPC.
- `internal/secrets/`: env loader, memguard buffers, ssh-vault loader.
- `internal/audit/` and `internal/telemetry/`: audit/event logging and app logging.
- Config/docs: `configs/` (WAF), `docs/` (coverage, package overview), `test/regression/` plan.

See `docs/package-overview.md` for per-package method references and `docs/developer-usage.md` for usage patterns.
