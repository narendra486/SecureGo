# persistence
Purpose: safer DB access patterns.
When to use: any DB interaction (reads/writes/prepared statements).
Mitigates: SQL injection via forced prepared statements, runaway queries via timeouts.

- Wrap `*sql.DB` with `SafeDB{DB, DefaultTimeout}` and use `Exec`, `Query`, `QueryRow` (adds context timeouts).
- Enforce prepared statements with `MustPrepared` rather than string concatenation.
- Set pool defaults via `Configure` (conn max lifetime, idle/open limits).
