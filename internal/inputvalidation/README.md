# inputvalidation

Purpose: validation and sanitization utilities.
When to use: anytime you accept untrusted strings, JSON, paths/URLs, or uploads.
Mitigates: invalid encodings, overlong inputs, regex bypass, path traversal, malicious uploads.

- JSON decoding with unknown-field rejection: `DecodeStrictJSON`.
- JSON + struct validation: `DecodeAndValidate` with validator tags (`NewValidator`, `ValidateStruct`).
- Strings: `ASCIIOnly`, `UTF8`, `LengthBetween`, `MatchesRegex`, `InAllowlist`.
- Paths/URLs: `SanitizePath` to keep paths inside a base; `ValidateURL` to enforce scheme/host allowlists for outbound calls.
- Files/forms: `ValidateMultipart` for size/part-count limits; `ValidateFileUpload` for size/extension/MIME allowlists.

Use with escaping helpers for output to avoid injection.
