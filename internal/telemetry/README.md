# telemetry

Purpose: structured application logging.
When to use: general app logs, errors, and metrics-friendly output.
Mitigates: unstructured logs that are hard to trace; includes UTC timestamps.

- `NewLogger()` returns a logger; use `Info`, `Error`, `Redact` for consistent formatting.
