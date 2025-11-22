# security
Purpose: carry authenticated identity through context for consistent authZ.
When to use: set once after authN, read in handlers/services for decisions.
Mitigates: ad-hoc role checks and drift; keeps identity consistent across layers.

- `WithPrincipal(ctx, Principal{ID, Roles})` to inject identity.
- `FromContext(ctx)` to retrieve it; `HasRole(p, role)` to test roles.
