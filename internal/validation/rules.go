package validation

import (
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

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
	clean := filepath.Clean("/" + target)
	if strings.Contains(clean, "..") {
		return "", errors.New("invalid path segments")
	}
	full := filepath.Join(baseDir, clean)
	if !strings.HasPrefix(full, filepath.Clean(baseDir)) {
		return "", errors.New("path escapes base directory")
	}
	return full, nil
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

// ValidateFileUpload checks file size, extension, and MIME type prefix.
func ValidateFileUpload(fh *multipart.FileHeader, maxSize int64, allowedExts []string, allowedMIMEPrefixes []string) error {
	if fh.Size > maxSize {
		return errors.New("file too large")
	}
	ext := strings.ToLower(filepath.Ext(fh.Filename))
	if len(allowedExts) > 0 && !stringInSlice(ext, allowedExts) {
		return errors.New("file extension not allowed")
	}
	mime := fh.Header.Get("Content-Type")
	if len(allowedMIMEPrefixes) > 0 {
		ok := false
		for _, p := range allowedMIMEPrefixes {
			if strings.HasPrefix(strings.ToLower(mime), strings.ToLower(p)) {
				ok = true
				break
			}
		}
		if !ok {
			return errors.New("mime type not allowed")
		}
	}
	return nil
}

// ValidateMultipart enforces limits on multipart form size and parts count.
func ValidateMultipart(r *http.Request, maxBytes int64, maxParts int) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)
	if err := r.ParseMultipartForm(maxBytes); err != nil {
		return errors.New("invalid multipart form")
	}
	count := 0
	for _, vals := range r.MultipartForm.Value {
		count += len(vals)
	}
	for _, files := range r.MultipartForm.File {
		count += len(files)
	}
	if maxParts > 0 && count > maxParts {
		return errors.New("too many form parts")
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
