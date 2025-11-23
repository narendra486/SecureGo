package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// VerifyTOTP validates a 6-digit TOTP code against a base32 secret with configurable skew (steps).
// This is a lightweight helper for MFA enforcement.
func VerifyTOTP(secretBase32, code string, skewSteps int) (bool, error) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secretBase32))
	if err != nil {
		return false, fmt.Errorf("decode secret: %w", err)
	}
	trimmed := strings.TrimSpace(code)
	if len(trimmed) != 6 {
		return false, fmt.Errorf("code must be 6 digits")
	}
	inputCode, err := strconv.Atoi(trimmed)
	if err != nil {
		return false, fmt.Errorf("code not numeric")
	}
	// 30s step per RFC 6238
	epochSteps := time.Now().Unix() / 30
	if skewSteps < 0 {
		skewSteps = 0
	}
	for i := -skewSteps; i <= skewSteps; i++ {
		if generateTOTP(secret, epochSteps+int64(i)) == inputCode {
			return true, nil
		}
	}
	return false, nil
}

// ShouldRotatePassword reports when the password age exceeds maxAge.
func ShouldRotatePassword(lastChanged time.Time, maxAge time.Duration) bool {
	if maxAge <= 0 {
		return false
	}
	return time.Since(lastChanged) > maxAge
}

func generateTOTP(key []byte, counter int64) int {
	var msg [8]byte
	for i := uint(0); i < 8; i++ {
		msg[7-i] = byte(counter >> (8 * i))
	}
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0F
	bin := (int(sum[offset])&0x7F)<<24 |
		(int(sum[offset+1])&0xFF)<<16 |
		(int(sum[offset+2])&0xFF)<<8 |
		(int(sum[offset+3]) & 0xFF)
	return bin % 1000000
}
