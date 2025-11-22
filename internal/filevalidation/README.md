# filevalidation

Purpose: validate uploads and multipart forms.
When to use: any time you accept file uploads or multipart forms.
Mitigates: oversized uploads, dangerous extensions, unexpected MIME types, multipart abuse.

- `ValidateFileUpload(fh, maxSize, allowedExts, allowedMIMEPrefixes)` checks size, extension allowlist, and MIME prefix allowlist.
- `ValidateMultipart(r, maxBytes, maxParts)` enforces overall multipart size and part-count limits.
- `SaveUploadedFile(fh, destDir)` writes to a dedicated dir with a randomized name and safe perms.
- `ScanAndSave(fh, destDir, scanFunc)` saves then runs an AV scan hook; deletes file on scan failure.
- `ExtractZipSafe(zipPath, destDir, maxTotalBytes)` extracts zips while rejecting traversal/symlinks and limiting total bytes.
- `SetDownloadHeaders(w, filename)` sets safe headers for downloads (attachment, nosniff).
- `DetectMIME(r)` sniffs the first bytes for content-based MIME detection (optional).
