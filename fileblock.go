package main

import (
	"fmt"
	"mime"
	"path"
	"strings"
	"sync"
)

// FileBlocker holds the set of file extensions to block.
// Extensions are normalised to lowercase with a leading dot (e.g. ".exe").
// All operations are safe for concurrent use.
type FileBlocker struct {
	mu         sync.RWMutex
	extensions map[string]bool
}

var fileBlocker = &FileBlocker{extensions: map[string]bool{}}

// defaultBlockedExts is loaded at startup when no config override is provided.
// Covers common Windows malware/script delivery formats.
var defaultBlockedExts = []string{
	".exe", ".dll", ".bat", ".cmd", ".ps1",
	".vbs", ".scr", ".msi", ".pif", ".com",
}

func (fb *FileBlocker) norm(ext string) string {
	ext = strings.ToLower(strings.TrimSpace(ext))
	if ext != "" && !strings.HasPrefix(ext, ".") {
		return "." + ext
	}
	return ext
}

func (fb *FileBlocker) Add(ext string) {
	ext = fb.norm(ext)
	if ext == "" || ext == "." {
		return
	}
	fb.mu.Lock()
	fb.extensions[ext] = true
	fb.mu.Unlock()
}

func (fb *FileBlocker) Remove(ext string) {
	ext = fb.norm(ext)
	fb.mu.Lock()
	delete(fb.extensions, ext)
	fb.mu.Unlock()
}

func (fb *FileBlocker) List() []string {
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	out := make([]string, 0, len(fb.extensions))
	for ext := range fb.extensions {
		out = append(out, ext)
	}
	return out
}

// ClearAll removes all blocked extensions. Used by config import "replace" mode.
func (fb *FileBlocker) ClearAll() {
	fb.mu.Lock()
	fb.extensions = map[string]bool{}
	fb.mu.Unlock()
}

func (fb *FileBlocker) Count() int {
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	return len(fb.extensions)
}

// CheckPath returns the blocked extension if urlPath ends with a blocked file
// extension, or empty string if the request is allowed.
// Pass r.URL.Path (not the full URL) to avoid matching query-string artefacts.
func (fb *FileBlocker) CheckPath(urlPath string) string {
	ext := strings.ToLower(path.Ext(urlPath))
	if ext == "" {
		return ""
	}
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	if fb.extensions[ext] {
		return ext
	}
	return ""
}

// CheckExt checks if a specific extension is in the block list.
// Extension should include the dot (e.g., ".exe").
func (fb *FileBlocker) CheckExt(ext string) string {
	ext = fb.norm(ext)
	if ext == "" {
		return ""
	}
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	if fb.extensions[ext] {
		return ext
	}
	return ""
}

// blockedMIMETypes maps dangerous Content-Type MIME types to their canonical
// file extension. Used by CheckContentType to detect renamed executables
// (e.g. malware.exe renamed to malware.txt still served as application/x-msdownload).
var blockedMIMETypes = map[string]string{
	"application/x-msdownload":                      ".exe",
	"application/x-msdos-program":                   ".exe",
	"application/x-dosexec":                          ".exe",
	"application/x-executable":                       ".exe",
	"application/vnd.microsoft.portable-executable":  ".exe",
	"application/x-msi":                              ".msi",
	"application/x-ms-installer":                     ".msi",
	"application/x-bat":                              ".bat",
	"application/x-powershell":                       ".ps1",
	"application/x-vbs":                              ".vbs",
}

// CheckContentType returns the blocked extension if the response Content-Type
// header matches a dangerous MIME type whose associated extension is in the
// block list. This prevents bypass by renaming files (e.g. malware.exe → malware.txt).
// The contentType parameter should be the raw Content-Type header value
// (e.g. "application/x-msdownload; charset=utf-8").
func (fb *FileBlocker) CheckContentType(contentType string) string {
	if contentType == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	ext, ok := blockedMIMETypes[mediaType]
	if !ok {
		return ""
	}
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	if fb.extensions[ext] {
		return ext
	}
	return ""
}

// CheckContentDisposition returns the blocked extension if the
// Content-Disposition response header carries a filename with a blocked
// extension (catches downloads that use a generic URL but declare the real
// file name in the header).
func (fb *FileBlocker) CheckContentDisposition(cd string) string {
	if cd == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return ""
	}
	filename := params["filename"]
	if filename == "" {
		return ""
	}
	ext := strings.ToLower(path.Ext(filename))
	if ext == "" {
		return ""
	}
	fb.mu.RLock()
	defer fb.mu.RUnlock()
	if fb.extensions[ext] {
		return ext
	}
	return ""
}

// fileBlockConn writes a synthetic HTTP/1.1 403 response to a raw connection
// (typically the client side of an SSL-inspected tunnel) when a file-blocking
// check fires inside handleTunnelInspect. Mirrors the scanBlockConn pattern.
func fileBlockConn(dst interface{ Write([]byte) (int, error) }, host, urlPath, ext, source string) {
	logger.Printf("FILE_BLOCKED (tunnel %s) -> %q%q (ext=%q)", source, sanitizeLog(host), sanitizeLog(urlPath), sanitizeLog(ext))
	body := fmt.Sprintf("Blocked: file type %s is not allowed (%s)\r\n", ext, source)
	fmt.Fprintf(dst, //nolint:errcheck
		"HTTP/1.1 403 Forbidden\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		len(body), body,
	)
}
