//go:build !windows

package secrets

import (
	"fmt"

	"github.com/awnumar/memguard"
)

// ProtectBytes locks the provided secret in an encrypted, locked buffer.
func ProtectBytes(secret []byte) (*memguard.LockedBuffer, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret is empty")
	}
	memguard.CatchInterrupt()
	buf, err := memguard.NewImmutableFromBytes(secret)
	if err != nil {
		return nil, fmt.Errorf("memguard: %w", err)
	}
	return buf, nil
}
