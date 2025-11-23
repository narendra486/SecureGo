# OWASP Go-SCP Coverage Status

This note maps the OWASP Go-SCP folder groups (from https://github.com/OWASP/Go-SCP/tree/master/src) to the current SecureGo implementation. It highlights what is covered by our `/internal` packages and what remains to be added.

## Folder-by-folder coverage (OWASP Go-SCP src)
- **access-control**: JWT validator (`internal/auth.JWTValidator` with iss/aud/alg allowlists); RBAC/ABAC helpers (`internal/auth/rbac.go`); request IDs, recovery, body limits, secure headers (`internal/middleware`). **Covered.**
- **authentication / password management**: Argon2id hashing, AEAD session cookies, opaque signed tokens, password-rotation helper (`ShouldRotatePassword`), TOTP MFA helper (`VerifyTOTP`). **Covered.**
- **communication-security**: Hardened TLS/ciphers/timeouts and optional mTLS (client CA + require client cert) in `internal/server`; CSRF double-submit; security headers middleware. **Covered.**
- **cryptographic-practices**: AEAD/HKDF/random tokens; SIV helpers; key-rotation helpers (`ShouldRotateKey`, `NextKeyVersion`). **Covered.**
- **data-protection / secrets**: Env validation; memguard helper to lock secrets; AES-GCM env decrypt helper (`DecryptEnv`) as local KMS stand-in; ssh-vault hooks. **Covered (pluggable provider hook).**
- **database-security**: Prepared statements + deadlines via `internal/persistence.SafeDB`; role-aware read-only wrapper (`WithRole`); demo `/secure/db` uses it. **Covered.**
- **error-handling-logging**: UTC structured logging + redaction; panic recovery middleware. **Covered.**
- **file-management / path traversal**: Path-safe joins and file validation; quarantined upload saver (`SaveToQuarantine`). **Covered.**
- **general-coding-practices**: Body limits, JSON-only enforcement, timeout middleware, secure headers baseline. **Covered.**
- **input-validation / output-encoding**: UTF-8/length/regex/URL/path/file checks and strict JSON decode; HTML escaping for XSS-safe output. **Covered.**
- **memory-management**: memguard helper available. **Covered.**
- **session-management**: AEAD sessions, CSRF middleware, SameSite/HttpOnly/Secure cookies. **Covered.**
- **system-configuration**: Env validation, hardened HTTP server, optional WAF via `CORAZA_DIRECTIVES`. **Covered.**
- **SSRF guard**: Outbound client blocks private/local IPs; used in `/secure/ssrf`. **Covered.**
- **WAF hook**: Coraza integration toggle. **Covered.**
- **GraphQL**: Secure handler with introspection off and depth/complexity limits; demo `/secure/graphql`. **Covered.**
- **gRPC**: Interceptors (recovery, timeout, logging, content-type allowlist, size caps) + health + sample Ping RPC (`RegisterPing` on :1338). **Covered.**
- **Sandboxed exec**: Allowlisted, shell-free runner used in secure `/secure/cmd`. **Covered.**
- **OAuth2/SAML**: Helpers present (OAuth2 client with PKCE helpers; SAML validator with replay cache). **Covered (integration-specific flows left to apps).**

## Demo routing (current)
- Secure (validated): `/secure/xss` (inputvalidation + HTML escape), `/secure/sqli`, `/secure/db` (SafeDB prepared query), `/secure/ssrf`, `/secure/path`, `/secure/cmd`, `/secure/idor`, `/secure/csrf`, `/secure/jwt/mint`, `/secure/jwt/validate`, `/secure/headers`, `/secure/graphql`.
- Vulnerable: `/vuln/xss`, `/vuln/sqli`, `/vuln/ssrf`, `/vuln/path`, `/vuln/cmd`, `/vuln/idor`, `/vuln/oauth/token`, `/vuln/oauth/validate`, `/vuln/jwt/mint`, `/vuln/jwt/validate`, `/vuln/csrf`, `/vuln/headers`.

## Next steps to close gaps
Integration tasks only: wire OAuth2/SAML flows in your app, supply real KMS provider, and build UI for MFA/policy/KMS as needed.

## Notes
- By design, `/vuln/*` routes remain insecure to show contrasts. All secure validation in demo uses only `/internal` packages (inputvalidation, CSRF, JWT validator, security headers, middleware).
- The UI lives at `demo/src/index.html` and targets `/secure` (secure) and `/vuln` (vulnerable). Server entrypoint: `demo/src/main.go` (port 1337).
