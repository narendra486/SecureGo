package inputvalidation

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-playground/validator/v10"
)

// DecodeStrictJSON disallows unknown fields to prevent mass assignment issues.
func DecodeStrictJSON(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("json decode: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("unexpected extra JSON input")
	}
	return nil
}

// Validator wraps go-playground/validator with pre-registered rules.
type Validator struct {
	v *validator.Validate
}

// NewValidator returns a validator with common tags.
func NewValidator() *Validator {
	v := validator.New(validator.WithRequiredStructEnabled())
	return &Validator{v: v}
}

// ValidateStruct validates a struct using `validate` tags.
func (v *Validator) ValidateStruct(s any) error {
	if err := v.v.Struct(s); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	return nil
}

// DecodeAndValidate decodes JSON with unknown-field rejection and validates struct tags.
func DecodeAndValidate(r io.Reader, dst any, v *Validator) error {
	if err := DecodeStrictJSON(r, dst); err != nil {
		return err
	}
	if v == nil {
		v = NewValidator()
	}
	return v.ValidateStruct(dst)
}
