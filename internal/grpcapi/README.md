# grpcapi
Purpose: hardened gRPC server defaults.
When to use: gRPC services that need resilience and basic abuse protection.
Mitigates: panics leaking info, oversized/slow requests, content-type abuse.

- `NewServer(DefaultConfig())` returns server with recovery/logging interceptors, method timeouts, content-type allowlist (proto + optional JSON), size limits, and health service.
- Configure per-prod settings via `Config` (timeout, max sizes, AllowJSON).
