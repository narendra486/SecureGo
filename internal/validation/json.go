package validation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// DecodeStrictJSON disallows unknown fields to prevent mass-assignment issues.
func DecodeStrictJSON(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("json decode: %w", err)
	}
	if dec.More() {
		return errors.New("unexpected extra JSON input")
	}
	return nil
}

// CleanJoin ensures target stays within base, preventing path traversal.
func CleanJoin(base, target string) (string, error) {
	clean := filepath.Clean("/" + target)
	if strings.Contains(clean, "..") {
		return "", errors.New("invalid path segment")
	}
	full := filepath.Join(base, clean)
	if !strings.HasPrefix(full, base) {
		return "", errors.New("path escapes base directory")
	}
	return full, nil
}
