package filevalidation

import (
	"archive/zip"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

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

// SaveUploadedFile stores an uploaded file to destDir with a randomized name and safe permissions.
func SaveUploadedFile(fh *multipart.FileHeader, destDir string) (string, error) {
	src, err := fh.Open()
	if err != nil {
		return "", fmt.Errorf("open upload: %w", err)
	}
	defer src.Close()
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}
	ext := strings.ToLower(filepath.Ext(fh.Filename))
	name, err := randomHex(16)
	if err != nil {
		return "", fmt.Errorf("random name: %w", err)
	}
	dstPath := filepath.Join(destDir, name+ext)
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create file: %w", err)
	}
	defer dst.Close()
	// Limit copy to advertised size to avoid unexpected growth.
	if fh.Size > 0 {
		_, err = io.CopyN(dst, io.LimitReader(src, fh.Size), fh.Size)
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("copy upload: %w", err)
		}
	} else {
		if _, err := io.Copy(dst, src); err != nil {
			return "", fmt.Errorf("copy upload: %w", err)
		}
	}
	return dstPath, nil
}

// ExtractZipSafe extracts a zip file into destDir while preventing traversal/symlinks and limiting total bytes.
func ExtractZipSafe(zipPath, destDir string, maxTotalBytes int64) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer reader.Close()
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	var total int64
	base := ensureTrailingSep(filepath.Clean(destDir))
	for _, f := range reader.File {
		if f.FileInfo().Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink entry rejected: %s", f.Name)
		}
		destPath := filepath.Join(destDir, f.Name)
		destClean := filepath.Clean(destPath)
		if !strings.HasPrefix(ensureTrailingSep(destClean), base) {
			return fmt.Errorf("zip entry escapes base: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destClean, 0o700); err != nil {
				return fmt.Errorf("mkdir entry: %w", err)
			}
			continue
		}
		size := f.FileInfo().Size()
		if maxTotalBytes > 0 && total+size > maxTotalBytes {
			return errors.New("zip too large")
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open entry: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(destClean), 0o700); err != nil {
			rc.Close()
			return fmt.Errorf("mkdir file dir: %w", err)
		}
		dst, err := os.OpenFile(destClean, os.O_CREATE|os.O_WRONLY|os.O_EXCL, f.Mode().Perm()&0o666|0o600)
		if err != nil {
			rc.Close()
			return fmt.Errorf("create entry: %w", err)
		}
		limit := int64(^uint64(0) >> 1)
		if maxTotalBytes > 0 {
			limit = maxTotalBytes - total
		}
		written, err := io.CopyN(dst, rc, limit)
		rc.Close()
		dst.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("copy entry: %w", err)
		}
		total += written
	}
	return nil
}

// SetDownloadHeaders sets safe headers for file downloads.
func SetDownloadHeaders(w http.ResponseWriter, filename string) {
	safe := sanitizeFilename(filename)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", safe))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// DetectMIME detects MIME type from the first 512 bytes of data.
func DetectMIME(r io.Reader) (string, []byte, error) {
	buf := make([]byte, 512)
	n, err := io.ReadFull(r, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", nil, err
	}
	sniff := http.DetectContentType(buf[:n])
	return sniff, buf[:n], nil
}

// ScanAndSave hooks an AV scanner: saves upload then runs scan; deletes file on scan failure.
func ScanAndSave(fh *multipart.FileHeader, destDir string, scan func(path string) error) (string, error) {
	path, err := SaveUploadedFile(fh, destDir)
	if err != nil {
		return "", err
	}
	if scan != nil {
		if err := scan(path); err != nil {
			_ = os.Remove(path)
			return "", fmt.Errorf("scan failed: %w", err)
		}
	}
	return path, nil
}

func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if s == v {
			return true
		}
	}
	return false
}

func ensureTrailingSep(path string) string {
	if strings.HasSuffix(path, string(filepath.Separator)) {
		return path
	}
	return path + string(filepath.Separator)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(fmt.Sprintf("%x", b)), nil
}

func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "\"", "_")
	name = strings.ReplaceAll(name, "\n", "_")
	name = strings.ReplaceAll(name, "\r", "_")
	return name
}
