# Package Overview (How to Choose the Right Helpers)

Use this as a quick map of what each package does and which methods to call.

## internal/middleware
- `SecurityHeaders`, `RequestID`, `Recovery`, `BodyLimit`: baseline hardening for every handler.
- CSRF: `NewCSRF(DefaultCSRFConfig)` + `EnsureCSRF`/`Middleware` for double-submit tokens.
- Rate limiting: `NewIPRateLimit` or `NewKeyRateLimit` + `Middleware`.
- WAF: `NewWAF(directives)` + `Middleware` to apply Coraza rules.
- Access control: `RequireRole`, `RequireOwnership` scaffolds.
- Utils: `IPFromRequest`.

## internal/server
- `DefaultConfig` for hardened timeouts/TLS.
- `New(handler, cfg)` to create the HTTP server.

## internal/auth
- JWT: `JWTValidator.Validate` with RS256/RS512 only; `BearerExtractor`.
- Passwords/KDFs: `HashPassword` (argon2id) / `VerifyPassword`; `HashWithScrypt` / `VerifyScrypt`.
- Sessions: `NewSessionCodec` + `Set`/`Parse` for AEAD-protected cookies.
- Tokens: `SignedToken.Mint` / `Verify` for HMAC-signed opaque tokens.
- OAuth2 server: `NewInMemoryOAuthServer`, `AddClient`, `AuthorizeHandler`, `TokenHandler`.
- SAML: `SAMLValidator.ValidateAssertion` skeleton.

## InputValidation
- `internal/validation`: JSON decode + unknown-field rejection (`DecodeStrictJSON`), `DecodeAndValidate` (with validator tags), `NewValidator`, `ValidateStruct`, `CleanJoin`, and helpers for strings (`ASCIIOnly`, `UTF8`, `LengthBetween`, `MatchesRegex`, `InAllowlist`), paths/URLs (`SanitizePath`, `ValidateURL`), files/forms (`ValidateMultipart`, `ValidateFileUpload`).

## internal/encoding
- Escapers: `HTMLEscape`, `AttributeEscape`, `URLEncode` for templating/output contexts.

## internal/security
- Principal context: `WithPrincipal`, `FromContext`, `HasRole` for consistent authZ decisions.

## internal/crypto
- Randoms: `RandomBytes`, `RandomString`.
- AEAD: `NewXChaCha20Poly1305` with `Seal`/`Open`.
- SIV (misuse-resistant): `NewSIV` with `Seal`/`Open`.
- HKDF/HMAC: `DeriveKey`, `HMACSHA256`; constant-time compare via `Equal`.

## internal/httpclient
- SSRF-safe client: `New()` then `Do(req)` to block private/local IPs with timeouts.

## pkg/sandbox
- Safe subprocess: `CommandRunner.Run` (no shell expansion, allowlisted dirs, timeout).

## internal/persistence
- Safe DB wrapper: `SafeDB.Exec/Query/QueryRow`; `MustPrepared` for prepared statements; set pool defaults via `Configure`.

## internal/graphqlapi
- Hardened GraphQL handler: `NewHandler(DefaultConfig)` (POST+JSON-only, introspection off, body and depth/complexity caps).

## internal/grpcapi
- Hardened gRPC server: `NewServer(DefaultConfig)` with recovery/logging/timeouts/content-type and size limits.

## SecretsManagement (internal/secrets)
- Env/config loader: `ConfigLoader`, `MustRequire`, `ValidateRequired`.
- Secure buffers: `NewSecureBuffer` (memguard) + `Destroy`.
- ssh-vault loader: `LoadSSHVaultSecret`.

## internal/audit
- Audit logger: `NewLogger(w)`; `Log(Event{Actor, Action, Resource, Result, IP, CorrelationID, Metadata})`.

## internal/telemetry
- App logging: `NewLogger()` for structured logs (UTC).

## configs/docs
- WAF sample: `configs/waf.conf` (include CRS paths).
- Security coverage/checklists: `docs/security-coverage.md`, `docs/package-overview.md`, `docs/architecture-overview.md`, `docs/developer-usage.md`.
- Regression plan: `test/regression/README.md`.
