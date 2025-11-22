package inputvalidation

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// CleanJoin ensures the target path stays under baseDir to prevent traversal.
func CleanJoin(baseDir, target string) (string, error) {
	return SanitizePath(baseDir, target)
}

// ASCIIOnly ensures string is ASCII; returns error otherwise.
func ASCIIOnly(s string) error {
	if !isASCII(s) {
		return errors.New("input must be ASCII")
	}
	return nil
}

// UTF8 ensures string is valid UTF-8.
func UTF8(s string) error {
	if !utf8.ValidString(s) {
		return errors.New("invalid UTF-8")
	}
	return nil
}

// LengthBetween enforces min/max length (bytes).
func LengthBetween(s string, min, max int) error {
	if len(s) < min || len(s) > max {
		return fmt.Errorf("length must be between %d and %d", min, max)
	}
	return nil
}

// MatchesRegex validates string against a compiled regex.
func MatchesRegex(s string, re *regexp.Regexp) error {
	if !re.MatchString(s) {
		return errors.New("input does not match required pattern")
	}
	return nil
}

// InAllowlist ensures value is one of the allowed options.
func InAllowlist(s string, allowed []string) error {
	for _, a := range allowed {
		if s == a {
			return nil
		}
	}
	return errors.New("value not allowed")
}

// SanitizePath cleans and ensures path stays within baseDir to prevent traversal.
func SanitizePath(baseDir, target string) (string, error) {
	baseClean := filepath.Clean(baseDir)
	targetClean := filepath.Clean(target)
	full := filepath.Join(baseClean, targetClean)
	basePrefix := ensureTrailingSep(baseClean)
	fullClean := ensureTrailingSep(filepath.Clean(full))
	if !strings.HasPrefix(fullClean, basePrefix) {
		return "", errors.New("path escapes base directory")
	}
	return filepath.Clean(full), nil
}

// ValidateURL enforces scheme allowlist and optional host allowlist.
func ValidateURL(raw string, allowedSchemes []string, allowedHosts []string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("invalid url")
	}
	if !stringInSlice(strings.ToLower(u.Scheme), allowedSchemes) {
		return errors.New("scheme not allowed")
	}
	if len(allowedHosts) > 0 && !stringInSlice(strings.ToLower(u.Hostname()), allowedHosts) {
		return errors.New("host not allowed")
	}
	return nil
}

func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if s == v {
			return true
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

func ensureTrailingSep(path string) string {
	if strings.HasSuffix(path, string(filepath.Separator)) {
		return path
	}
	return path + string(filepath.Separator)
}
