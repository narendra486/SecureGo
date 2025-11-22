# validation
Purpose: strict JSON parsing and safe path joining.
When to use: whenever you decode request bodies or build file paths from input.
Mitigates: mass assignment via extra fields, invalid JSON, path traversal.

- JSON decoding with unknown-field rejection: `DecodeStrictJSON`.
- JSON + struct validation: `DecodeAndValidate` with validator tags (`NewValidator`, `ValidateStruct`).
- Path safety: `CleanJoin` to prevent traversal outside a base directory.
