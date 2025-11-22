package secrets

import (
	"fmt"

	"github.com/awnumar/memguard"
)

// SecureBuffer wraps memguard LockedBuffer for sensitive material (keys/secrets).
type SecureBuffer struct {
	buf *memguard.LockedBuffer
}

// NewSecureBuffer creates a new guarded buffer from bytes (copied into protected memory).
func NewSecureBuffer(data []byte) (*SecureBuffer, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty secret")
	}
	b := memguard.NewBufferFromBytes(data)
	return &SecureBuffer{buf: b}, nil
}

// Bytes returns a copy of the secret to avoid leaking the guarded region.
func (s *SecureBuffer) Bytes() []byte {
	if s == nil || s.buf == nil {
		return nil
	}
	return s.buf.Bytes()
}

// Destroy wipes the buffer.
func (s *SecureBuffer) Destroy() {
	if s != nil && s.buf != nil {
		s.buf.Destroy()
	}
}
