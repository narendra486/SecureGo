# server

Purpose: build an HTTP server with secure defaults.
When to use: stand up HTTP endpoints with strict timeouts/TLS.
Mitigates: slowloris/timeouts misconfigurations and weak TLS.

- `DefaultConfig` sets conservative read/write/idle timeouts and TLS cipher prefs.
- `New(handler, cfg)` constructs `http.Server` with those settings; call `ListenAndServe`/`ListenAndServeTLS`.
