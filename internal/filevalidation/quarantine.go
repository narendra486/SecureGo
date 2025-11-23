package filevalidation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// SaveToQuarantine writes the content to a quarantined temp file under dir with a max size limit.
// It returns the absolute path and SHA-256 hash of the stored file.
func SaveToQuarantine(r io.Reader, dir string, maxBytes int64) (string, string, error) {
	if maxBytes <= 0 {
		maxBytes = 10 << 20 // default 10MB
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", fmt.Errorf("mkdir quarantine: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "quarantine-*")
	if err != nil {
		return "", "", fmt.Errorf("create temp: %w", err)
	}
	defer tmp.Close()

	lim := &io.LimitedReader{R: r, N: maxBytes + 1}
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, h), lim)
	if err != nil {
		return "", "", fmt.Errorf("copy: %w", err)
	}
	if written > maxBytes {
		os.Remove(tmp.Name())
		return "", "", fmt.Errorf("file exceeds max size %d bytes", maxBytes)
	}
	hash := hex.EncodeToString(h.Sum(nil))
	return filepath.Clean(tmp.Name()), hash, nil
}
