# graphqlapi
Purpose: secure-by-default GraphQL endpoint.
When to use: expose GraphQL while limiting abuse.
Mitigates: introspection abuse, large/complex query DoS, method/content-type misuse.

- `NewHandler(DefaultConfig())` yields POST+JSON-only endpoint with 1 MB cap, introspection off, and query length/depth/complexity limits.
- Mount on `/graphql`; replace schema in handler if needed.
