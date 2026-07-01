// Package fileblock is the file-type blocking engine: an extension/MIME/
// Content-Disposition blocklist (FileBlocker) and named file-type profiles
// (FileProfileStore, in fileprofile.go). It depends only on the shared seam
// (internal/obs for logging, internal/fileutil for atomic persistence) and the
// standard library — no dependency on the rest of Culvert (ADR-0002 leaf,
// unblocked by the ADR-0003 seam).
package fileblock

import (
	"encoding/json"
	"fmt"
	"mime"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// FileBlocker holds the set of file extensions to block.
// Extensions are normalised to lowercase with a leading dot (e.g. ".exe").
// All operations are safe for concurrent use. Persists to a JSON file when
// a path is configured via SetPath().
type FileBlocker struct {
	mu         sync.RWMutex
	extensions map[string]bool
	path       string // persistence file (e.g. /data/fileblock.json); "" = no persistence
}

// NewBlocker returns an empty, ready-to-use FileBlocker. package main holds the
// process-wide singleton (var fileBlocker = fileblock.NewBlocker()).
func NewBlocker() *FileBlocker {
	return &FileBlocker{extensions: map[string]bool{}}
}

// SetPath configures the persistence file and loads any previously saved
// extensions from it. If the file doesn't exist, the current in-memory
// state is kept (caller should load defaults before calling SetPath).
func (fb *FileBlocker) SetPath(p string) {
	fb.mu.Lock()
	fb.path = p
	fb.mu.Unlock()
	if p == "" {
		return
	}
	data, err := os.ReadFile(p) // #nosec G304 -- operator-configured persistence path
	if err != nil {
		return // file doesn't exist yet — keep current state
	}
	var exts []string
	if json.Unmarshal(data, &exts) != nil {
		return
	}
	fb.mu.Lock()
	fb.extensions = map[string]bool{}
	for _, ext := range exts {
		fb.extensions[fb.norm(ext)] = true
	}
	fb.mu.Unlock()
}

// save persists the current extension list to the configured file.
// Called internally after Add/Remove/ClearAll — no-op if no path is set.
func (fb *FileBlocker) save() {
	if fb.path == "" {
		return
	}
	exts := make([]string, 0, len(fb.extensions))
	for ext := range fb.extensions {
		exts = append(exts, ext)
	}
	data, _ := json.Marshal(exts)
	_ = fileutil.AtomicWrite(fb.path, data, 0o600)
}

// DefaultBlockedExts is loaded at startup when no config override is provided.
// Covers common Windows malware/script delivery formats.
var DefaultBlockedExts = []string{
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

// Add inserts a normalised extension into the block list and persists.
func (fb *FileBlocker) Add(ext string) {
	ext = fb.norm(ext)
	if ext == "" || ext == "." {
		return
	}
	fb.mu.Lock()
	fb.extensions[ext] = true
	fb.save()
	fb.mu.Unlock()
}

// ReplaceAll atomically replaces the in-memory extension set with
// the normalised contents of exts and persists once. Per-element
// semantics mirror Add exactly: lowercase + trim, leading-dot
// inserted if missing, empty / bare-dot entries skipped,
// duplicates collapsed by the set.
//
// CL-13: used by applyConfigSnapshot's FileBlockExtensions branch
// to replace the prior ClearAll + per-extension Add loop, which
// triggered N+1 atomicWriteFile syscalls per snapshot apply
// (cap 10_000 extensions per maxSnapFileBlockExtensions). ReplaceAll
// triggers exactly one save() call regardless of N.
//
// Save is invoked unconditionally — including when the new set is
// equal to the existing set. Skipping save on equal content would
// require deep-comparing maps under the lock and add a fast-path
// that could deviate from the long-term durability guarantee, which
// is out of CL-13 scope per the user brief.
func (fb *FileBlocker) ReplaceAll(exts []string) {
	newSet := make(map[string]bool, len(exts))
	for _, e := range exts {
		e = fb.norm(e)
		if e == "" || e == "." {
			continue
		}
		newSet[e] = true
	}
	fb.mu.Lock()
	fb.extensions = newSet
	fb.save()
	fb.mu.Unlock()
}

// Remove deletes an extension from the block list and persists.
func (fb *FileBlocker) Remove(ext string) {
	ext = fb.norm(ext)
	fb.mu.Lock()
	delete(fb.extensions, ext)
	fb.save()
	fb.mu.Unlock()
}

// List returns a snapshot of the blocked extensions.
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
	fb.save()
	fb.mu.Unlock()
}

// Count returns the number of blocked extensions.
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
	"application/x-dosexec":                         ".exe",
	"application/x-executable":                      ".exe",
	"application/vnd.microsoft.portable-executable": ".exe",
	"application/x-msi":                             ".msi",
	"application/x-ms-installer":                    ".msi",
	"application/x-bat":                             ".bat",
	"application/x-powershell":                      ".ps1",
	"application/x-vbs":                             ".vbs",
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

// ExtractCDFilename extracts the filename from a Content-Disposition header.
// Returns "" if no filename is found. Used by per-rule file profile checking
// when the download URL doesn't contain the file extension (e.g. SourceForge's
// /files/latest/download pattern).
func ExtractCDFilename(cd string) string {
	if cd == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return ""
	}
	return params["filename"]
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

// BlockConn writes a synthetic HTTP/1.1 403 response to a raw connection
// (typically the client side of an SSL-inspected tunnel) when a file-blocking
// check fires inside handleTunnelInspect. After writing the response, the
// connection is explicitly closed to prevent HTTP/1.1 connection reuse — a
// browser with a pipelined second request in the same TLS session could
// otherwise bypass the block on retry.
func BlockConn(dst interface {
	Write([]byte) (int, error)
	Close() error
}, host, urlPath, ext, source string) {
	obs.Printf("FILE_BLOCKED (tunnel %s) -> %q%q (ext=%q)", source, obs.Sanitize(host), obs.Sanitize(urlPath), obs.Sanitize(ext))
	body := fmt.Sprintf("Blocked: file type %s is not allowed (%s)\r\n", ext, source)
	fmt.Fprintf(dst, //nolint:errcheck // best-effort write of the 403 block response
		"HTTP/1.1 403 Forbidden\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		len(body), body,
	)
	dst.Close() //nolint:errcheck // force-close prevents pipelined-request bypass
}
