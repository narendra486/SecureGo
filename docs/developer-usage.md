# Securego Developer Usage Guide

This guide lists the key helpers and how to call them. No CI gates are enabled; you opt in where needed.

## HTTP server & middleware
- Build handler chain: wrap your mux with:
  - `middleware.BodyLimit(maxBytes)`, `middleware.Recovery`, `middleware.RequestID`, `middleware.SecurityHeaders` to cap payloads, catch panics, add correlation IDs, and set secure headers.
  - CSRF: `csrf := middleware.NewCSRF(middleware.DefaultCSRFConfig())`; wrap with `csrf.EnsureCSRF(csrf.Middleware(handler))` to enforce double-submit token (cookie + header).
  - Rate limiting: `middleware.NewIPRateLimit(rate, burst)` or `middleware.NewKeyRateLimit(rate, burst, keyFunc)`; wrap with `limiter.Middleware(handler)` to throttle clients.
  - Optional WAF: `waf := middleware.NewWAF(directives)`; wrap with `waf.Middleware(handler)` to block malicious patterns via Coraza.
- Server: `srv := server.New(handler, server.DefaultConfig())`; call `ListenAndServe` / `ListenAndServeTLS` for hardened timeouts/TLS defaults.

## Auth & sessions
- JWT: `v := auth.JWTValidator{Issuer, Audiences, Algorithms, KeyFunc, ClockSkew}; claims, err := v.Validate(ctx, tokenStr)`; `auth.BearerExtractor` reads the Authorization header. RS256/RS512 enforced.
- Passwords/KDF: `auth.HashPassword` (argon2id) or `auth.HashWithScrypt`; verify with corresponding `Verify*` to avoid weak hashes.
- Sessions: `codec, _ := auth.NewSessionCodec("sid", key32Bytes)`; `codec.Set(w, data)` and `codec.Parse(r)` for AEAD-protected cookies (Secure/HttpOnly/SameSite).
- Opaque tokens: `tok := auth.SignedToken{Key, TTL}`; `Mint()` / `Verify()` for short-lived bearer tokens.
- OAuth2 server scaffolding: `o := auth.NewInMemoryOAuthServer(); o.AddClient(id, secret, domain); o.TokenHandler(w,r); o.AuthorizeHandler(w,r)` (swap to persistent stores in prod).

## Access control & security context
- Role check: `middleware.RequireRole(hasRoleFunc, "admin")` to enforce role decisions.
- Ownership/ABAC: `middleware.RequireOwnership(checkFunc)` to gate on resource ownership/custom policy.
- Principal context: `ctx = security.WithPrincipal(ctx, security.Principal{ID, Roles}); p, ok := security.FromContext(ctx); security.HasRole(p,"admin")` for consistent decisions across layers.

## Input validation
- JSON + struct tags: `var req T; err := validation.DecodeAndValidate(r.Body, &req, validation.NewValidator())` to reject unknown fields and enforce tags.
- Additional checks (validation helpers):
  - Strings: `ASCIIOnly`, `UTF8`, `LengthBetween`, `MatchesRegex(re)`, `InAllowlist`.
  - Paths/URLs: `SanitizePath(base, target)`, `ValidateURL(raw, allowedSchemes, allowedHosts)`.
  - Files/forms: `ValidateMultipart` for size/count limits, `ValidateFileUpload` for size/ext/MIME allowlists.

## Output encoding
- JSON responses: `json.NewEncoder(w).Encode(data)` to avoid injection in JSON.
- HTML/attr/URL escape helpers: `encoding.HTMLEscape`, `encoding.AttributeEscape`, `encoding.URLEncode` for templating contexts.

## GraphQL/gRPC
- GraphQL: `h, _ := graphqlapi.NewHandler(graphqlapi.DefaultConfig())` (POST+JSON-only, introspection off, caps on length/depth/complexity); mount on `/graphql`.
- gRPC: `s := grpcapi.NewServer(logger, grpcapi.DefaultConfig())` (content-type allowlist, size/timeouts, recovery/logging).

## Networking & exec
- SSRF-safe HTTP: `c := httpclient.New(); resp, err := c.Do(req)` (blocks private/local IPs before outbound).
- Subprocess: `runner := sandbox.CommandRunner{AllowedDirs, Timeout}; out, err := runner.Run(ctx, bin, args...)` (no shell expansion).

## Database
- Safe DB wrapper: `sdb := persistence.SafeDB{DB: db, DefaultTimeout: d}; sdb.Query(ctx, "SELECT ...", args...)`; `MustPrepared` for prepared stmts with deadlines.

## Crypto
- Randoms: `crypto.RandomBytes(n)`, `crypto.RandomString(n)` from `crypto/rand`.
- AEAD: `box, _ := crypto.NewXChaCha20Poly1305(key32); nonce, ct, _ := box.Seal(pt, aad); pt, _ := box.Open(nonce, ct, aad)` for confidentiality/integrity.
- SIV: `siv, _ := crypto.NewSIV(key32or64); _, ct, _ := siv.Seal(pt, aad); pt, _ := siv.Open(nil, ct, aad)` for misuse-resistant encryption.
- HKDF/HMAC: `crypto.DeriveKey(secret, salt, info, outLen)`, `crypto.HMACSHA256(key, msg)` for key derivation/signing.

## Secrets
- Env/config: `loader := secrets.MustRequire(...); loader.ValidateRequired()` to fail fast on missing secrets.
- Protected memory: `buf, _ := secrets.NewSecureBuffer(data); b := buf.Bytes(); buf.Destroy()` for memguard-protected buffers.
- ssh-vault stub: `secrets.LoadSSHVaultSecret(ctx, vaultFile)` to decrypt via ssh-vault CLI.

## Audit & logging
- Audit events: `al := audit.NewLogger(w); al.Log(audit.Event{Actor, Action, Resource, Result, IP, CorrelationID, Metadata})` for security-relevant actions.
- App logging: `logger := telemetry.NewLogger(); logger.Info(...)` for structured app logs.

## Config samples & docs
- WAF directives: `configs/waf.conf` (include CRS paths).
- Coverage docs: `docs/security-coverage.md`, `docs/package-overview.md`, `docs/architecture-overview.md`, `docs/developer-usage.md`.
- Regression test plan: `test/regression/README.md`.

## Notes
- Ownership/ABAC, MFA/lockout, KMS/HSM key rotation, per-user rate limits, audit emission, and cloud hardening remain app/deployment tasks—use the scaffolds above to implement them.
