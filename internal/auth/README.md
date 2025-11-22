# auth
How it works: primitives for authN/authZ tokens, secure password hashing, sessions, and OAuth2/SAML glue.
When to use: any time you issue/verify tokens or handle passwords/sessions.
Mitigates: weak hashes, JWT alg confusion, session theft/fixation, replay of opaque tokens.

- JWT: `JWTValidator.Validate` (RS256/RS512 only) with issuer/audience checks; `BearerExtractor` pulls the Authorization header.
- Passwords: `HashPassword` (argon2id), `HashWithScrypt` + verify helpers to avoid plain or weak hashes.
- Sessions: `NewSessionCodec` + `Set`/`Parse` for AEAD-secure cookies (Secure/HttpOnly/SameSite) to prevent tampering/reading.
- Opaque tokens: `SignedToken.Mint` / `Verify` for short-lived bearer tokens (HMAC signed).
- OAuth2 server scaffold: `NewInMemoryOAuthServer`, `AddClient`, `AuthorizeHandler`, `TokenHandler` for dev/stage flows (swap storage for prod).
- SAML: `SAMLValidator.ValidateAssertion` skeleton to validate assertions with audience/time checks.
