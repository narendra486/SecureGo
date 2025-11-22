package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Config defines memory-hard parameters.
type Argon2Config struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen int
}

// DefaultArgon2 returns sane defaults meant for server-side hashing.
func DefaultArgon2() Argon2Config {
	return Argon2Config{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
		SaltLen: 16,
	}
}

// HashPassword returns a PHC-style encoded argon2id hash.
func HashPassword(password string, cfg Argon2Config) (string, error) {
	salt, err := randomSalt(cfg.SaltLen)
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, cfg.Time, cfg.Memory, cfg.Threads, cfg.KeyLen)
	// Format: argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	encSalt := base64.RawStdEncoding.EncodeToString(salt)
	encHash := base64.RawStdEncoding.EncodeToString(hash)
	str := fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", cfg.Memory, cfg.Time, cfg.Threads, encSalt, encHash)
	return str, nil
}

// VerifyPassword verifies an encoded hash.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 {
		return false
	}
	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	recalc := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(hash)))
	return subtle.ConstantTimeCompare(hash, recalc) == 1
}

func randomSalt(n int) ([]byte, error) {
	salt := make([]byte, n)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}
