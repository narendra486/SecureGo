# secrets
Purpose: manage configuration secrets safely.
When to use: loading env/config secrets, handling sensitive bytes.
Mitigates: missing secrets at startup, exposing secrets in heap/plain bytes.

- Env loader: `ConfigLoader`, `MustRequire`, `ValidateRequired` to fail fast on missing secrets.
- Secure buffers: `NewSecureBuffer` (memguard) + `Destroy` for in-memory protection of key material.
- ssh-vault: `LoadSSHVaultSecret` to decrypt vault files via CLI (optional).
