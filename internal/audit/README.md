# audit
Purpose: record security-relevant events in a structured way.
When to use: authN/authZ decisions, admin actions, token issuance/revocation, data access.
Mitigates: missing audit trail and tampering by using JSON lines with UTC timestamps (ensure append-only storage).

- `NewLogger(w)` creates JSON-lines auditor.
- `Log(Event{Actor, Action, Resource, Result, IP, CorrelationID, Metadata})`; redact PII in metadata yourself.
