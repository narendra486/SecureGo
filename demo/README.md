# SecureGO Demo (Docker)

Spin up the SecureGO API with a simple UI for testing CSRF/session/token flows, without touching your existing code.

## Prereqs
- Docker and docker-compose
- Provide a JWT public key if you want to hit `/api/jwt/check` (optional):
  - Ed25519: set `JWT_ED_PUBLIC_KEY` and mount the PEM in `demo/keys`.
  - Or RSA: set `JWT_RS_PUBLIC_KEY`.

## Run
```
cd demo
docker compose up --build
```

- UI: http://localhost:8080
- API: proxied via Caddy at `/api/*` (upstream on api:8443, HTTP by default)
- Use the single UI at http://localhost:8080 to target either SecureGO (`/api`) or the Vuln-Go app (`/vuln`).

## What the UI does
- Fetch CSRF token (`/api/csrf`) and store it.
- Set session cookie (`/api/session/set`) with `X-CSRF-Token`.
- Check session (`/api/session/check`).
- Mint opaque token (`/api/token`).

## Notes
- API is HTTPS-capable if you supply certs; by default it runs HTTP internally in Docker.
- Adjust `CORAZA_DIRECTIVES` in compose if you want WAF rules.
- Keep this demo separate from production; it is for local testing only.

## Vulnerable app (Go)
- Included via `vuln-go` service; proxied in Caddy at `/vuln*`.
- Use the UI at http://localhost:8080 to run XSS, SQLi, SSRF, traversal, command injection, and upload payloads against `vuln-go`, then replay against SecureGO to confirm they’re blocked.
