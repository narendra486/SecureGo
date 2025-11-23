# SecureGO Demo (Docker)

Spin up a single demo server that serves the UI, SecureGo endpoints, and the VulnGo lab from one container.

## Prereqs
- Docker and docker-compose

## Run
```
cd demo
docker compose up --build
```

- UI + API + Vuln lab all live at http://localhost:8080
- The UI targets SecureGo at `/api/*` and the VulnGo lab at `/vuln/*`.

## What the UI does
- Lets you send POST requests with raw bodies to common vuln cases: XSS, SQLi, SSRF, path traversal, command injection, IDOR, weak OAuth token, and OAuth validate with no signature check.
- Toggle targets between SecureGo (`/api`) and VulnGo (`/vuln`); compare behavior.

## Notes
- Single Go process serves everything on port 8080.
- Keep this demo separate from production; it is for local testing only.
