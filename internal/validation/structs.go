package validation

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

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
