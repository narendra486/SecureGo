# crypto
Purpose: safe cryptographic primitives.
When to use: whenever you need random tokens, encryption, or signing; avoid rolling your own.
Mitigates: weak RNG, nonce misuse, unsafe hashes/alg confusion.

- Randoms: `RandomBytes`, `RandomString` from `crypto/rand`.
- AEAD: `NewXChaCha20Poly1305` with `Seal`/`Open` for authenticated encryption (nonce handled for you).
- SIV: `NewSIV` with `Seal`/`Open` for misuse-resistant encryption when nonces are hard to manage.
- KDF/signing: `DeriveKey` (HKDF), `HMACSHA256`; const-time comparison via `Equal`.
