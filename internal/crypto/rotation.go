package crypto

import "time"

// ShouldRotateKey indicates whether a key created at createdAt should be rotated after maxAge.
func ShouldRotateKey(createdAt time.Time, maxAge time.Duration) bool {
	if maxAge <= 0 {
		return false
	}
	return time.Since(createdAt) >= maxAge
}

// NextKeyVersion increments a numeric key version; helper for rolling keys.
func NextKeyVersion(current int) int {
	return current + 1
}
