package main

import (
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
