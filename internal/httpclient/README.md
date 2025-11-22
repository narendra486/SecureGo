# httpclient
Purpose: outbound HTTP with SSRF guards.
When to use: any time you fetch URLs from user input or untrusted sources.
Mitigates: SSRF to internal services by blocking private/local IP ranges.

- `New()` returns a client that resolves hosts and blocks private/local IPs.
- Use `resp, err := client.Do(req)`; set `Timeout`, `AllowedCIDRs`, or custom resolver if needed.
