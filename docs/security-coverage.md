# Security Coverage (No CI Gate)

This repo addresses the following categories; items marked ⚠️ need project-specific wiring or deployment steps.

- Access Control: RequireRole middleware scaffold; ⚠️ implement ownership/ABAC per resource; default-deny.
- Authentication & Password Management: RS256/RS512 JWT validation, OAuth2 server/client helpers, SAML skeleton, argon2id+scrypt KDFs, AEAD session cookies; ⚠️ MFA/step-up and credential rotation handled by the app/IdP.
- Session Management: Secure/HttpOnly/SameSite=Strict cookies, rotation helper, CSRF double-submit, short token TTLs; ⚠️ device binding / token revocation lists are app-specific.
- Input Validation: Strict JSON decode with unknown-field rejection, go-playground/validator wrapper, GraphQL POST+JSON-only with length/depth/complexity caps, content-type allowlists, body size/time caps.
- Output Encoding: Default html/template auto-escapes; CSP, X-Content-Type-Options, X-Frame-Options set; ⚠️ ensure any custom templating remains auto-escaped.
- Communication Security: TLS 1.2+ prefs, secure headers, HSTS on HTTPS; optional mTLS; ⚠️ cert pinning and ALB/edge configs are deployment tasks.
- Cryptographic Practices: AEAD (XChaCha20-Poly1305), HKDF, HMAC, optional AES-SIV; strong randomness; constant-time compares; ⚠️ key rotation with KMS/HSM is deployment-specific.
- Data Protection: Path traversal-safe joins, SSRF-safe HTTP client, sandboxed exec, memguard helper for secrets, ssh-vault loader stub; ⚠️ encryption at rest via KMS/Secrets Manager handled in infra.
- Database Security: Prepared-statement helper with context timeouts; ⚠️ per-DB RBAC, row-level security, audit/slow logs configured in DB layer.
- Error Handling & Logging: Panic recovery, user-safe errors, structured logging with redaction helper; ⚠️ PII redaction discipline and audit trail for sensitive actions belong in app logic.
- File Management: Path cleaning; ⚠️ add archive extraction with zip-slip checks if handling uploads; avoid gob/untrusted deserialization.
- Memory Management: memguard helper for sensitive buffers; ⚠️ apply where secrets are processed.
- General Coding Practices: Secure defaults, body caps/timeouts, request IDs, rate limiting, optional WAF; lint configs (gosec/staticcheck/govulncheck) provided; no CI gate per request.
- System Configuration: Samples for Coraza CRS (`configs/waf.conf`), KrakenD httpsecure; ⚠️ apply cloud hardening (private subnets, SG least privilege, IMDSv2, KMS) in deployment.
