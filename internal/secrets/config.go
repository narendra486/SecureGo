package secrets

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// ConfigLoader pulls strongly typed configuration from environment.
type ConfigLoader struct {
	Required []string
}

// Get returns value or error when missing.
func (c ConfigLoader) Get(key string) (string, error) {
	val := os.Getenv(key)
	if val == "" {
		for _, req := range c.Required {
			if req == key {
				return "", fmt.Errorf("required secret %s missing", key)
			}
		}
	}
	return val, nil
}

// Duration loads a duration value or uses a default.
func (c ConfigLoader) Duration(key string, def time.Duration) (time.Duration, error) {
	val := os.Getenv(key)
	if val == "" {
		return def, nil
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("duration %s invalid: %w", key, err)
	}
	return d, nil
}

// MustRequire sets required keys.
func MustRequire(keys ...string) ConfigLoader {
	return ConfigLoader{Required: keys}
}

// ValidateRequired ensures all required keys are present.
func (c ConfigLoader) ValidateRequired() error {
	for _, k := range c.Required {
		if os.Getenv(k) == "" {
			return errors.New("missing required secret: " + k)
		}
	}
	return nil
}
