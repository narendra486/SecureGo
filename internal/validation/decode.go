package validation

import (
	"encoding/json"
	"fmt"
	"io"
)

// DecodeAndValidate decodes JSON with unknown-field rejection and validates struct tags.
func DecodeAndValidate(r io.Reader, dst any, v *Validator) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("json decode: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("unexpected extra input")
	}
	if v == nil {
		v = NewValidator()
	}
	return v.ValidateStruct(dst)
}
