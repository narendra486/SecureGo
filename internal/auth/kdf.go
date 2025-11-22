package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// HashWithScrypt creates a scrypt hash for a password with PHC-like encoding.
func HashWithScrypt(password string, N, r, p, keyLen int) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(password), salt, N, r, p, keyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scrypt$N=%d$r=%d$p=%d$%s$%s", N, r, p, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}

// VerifyScrypt checks a scrypt hash produced by HashWithScrypt.
func VerifyScrypt(password, encoded string) bool {
	var N, r, p int
	var b64Salt, b64DK string
	if _, err := fmt.Sscanf(encoded, "scrypt$N=%d$r=%d$p=%d$%s$%s", &N, &r, &p, &b64Salt, &b64DK); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(b64Salt)
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(b64DK)
	if err != nil {
		return false
	}
	dk, err := scrypt.Key([]byte(password), salt, N, r, p, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, want) == 1
}

// HashWithArgon2ID returns an argon2id hash with custom parameters.
func HashWithArgon2ID(password string, time uint32, memory uint32, threads uint8, keyLen uint32) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, time, threads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}
