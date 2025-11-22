package auth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
)

// SAMLValidator wraps gosaml2 with strict audience/recipient/clock settings.
type SAMLValidator struct {
	ServiceProvider *saml2.SAMLServiceProvider
	ClockSkew       time.Duration
}

// ValidateAssertion validates a base64-encoded SAMLResponse with replay protection hook.
func (v SAMLValidator) ValidateAssertion(resp string, seen func(string) bool) (*saml2.AssertionInfo, error) {
	if v.ServiceProvider == nil {
		return nil, errors.New("service provider not configured")
	}
	asserted, err := v.ServiceProvider.RetrieveAssertionInfo(resp)
	if err != nil {
		return nil, fmt.Errorf("saml parse: %w", err)
	}
	if asserted.WarningInfo.InvalidTime {
		return nil, errors.New("assertion expired or not yet valid")
	}
	if asserted.WarningInfo.NotInAudience {
		return nil, errors.New("audience mismatch")
	}
	// Basic replay prevention hook: caller tracks IDs or digests externally (cache/db).
	digest := replayDigest(resp)
	if seen != nil && seen(digest) {
		return nil, errors.New("replayed assertion")
	}
	return asserted, nil
}

func replayDigest(input string) string {
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", h[:])
}
