package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// ─── DPI Content Scanner ──────────────────────────────────────────────────────
//
// ContentScanner applies regex signatures to HTTP response bodies flowing
// through SSL Inspect tunnels, enabling basic signature-based Deep Packet
// Inspection (DPI) of decrypted HTTPS traffic.
//
// Patterns are standard Go regex strings.  Matching is byte-level (patterns
// can match binary or text data).  For performance, only responses whose
// Content-Type indicates text or JSON are scanned; binary/media streams are
// passed through without scanning.
//
// Patterns can be managed dynamically via the /api/content-scan REST endpoint
// without restarting the proxy.  If a scan file path is configured, changes
// are persisted atomically (write-to-tmp + rename) so a crash mid-write never
// leaves a corrupt file.

// statDPIBlocked counts response bodies blocked by DPI signature matches.
var statDPIBlocked int64

// ContentScanner holds pre-compiled DPI regex patterns and applies them to
// HTTP response bodies.
type ContentScanner struct {
	mu       sync.RWMutex
	raw      []string         // raw strings — for listing and persistence
	compiled []*regexp.Regexp // pre-compiled for fast matching
	path     string           // optional JSON file path for persistence
	maxBytes int64            // max bytes buffered per response (default 1 MiB)
}

// dpiScanner is the global DPI pattern engine, shared across all inspected tunnels.
var dpiScanner = &ContentScanner{maxBytes: 1 << 20} // 1 MiB

// Enabled returns true when at least one pattern is loaded.
func (s *ContentScanner) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.compiled) > 0
}

// Set atomically replaces the full pattern list.  Returns an error if any
// pattern fails to compile; on error the existing patterns are unchanged.
func (s *ContentScanner) Set(patterns []string) error {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("invalid DPI pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}
	s.mu.Lock()
	s.raw = append([]string(nil), patterns...)
	s.compiled = compiled
	s.mu.Unlock()
	return nil
}

// Load reads a JSON array of regex strings from path.  If the file does not
// exist, Load succeeds (empty scanner — no patterns active).
func (s *ContentScanner) Load(path string) error {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()

	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("content-scan file read error: %w", err)
	}
	var patterns []string
	if err := json.Unmarshal(data, &patterns); err != nil {
		return fmt.Errorf("content-scan JSON parse error: %w", err)
	}
	return s.Set(patterns)
}

// Save persists the current pattern list to the configured file path.
// Uses an atomic write (tmp + rename) so a crash never leaves a partial file.
// No-op if no path is configured.
func (s *ContentScanner) Save() {
	s.mu.RLock()
	path := s.path
	data, _ := json.MarshalIndent(s.raw, "", "  ")
	s.mu.RUnlock()

	if path == "" || data == nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil { // #nosec G306
		return
	}
	os.Rename(tmp, path) //nolint:errcheck
}

// Add compiles and appends a single pattern.
func (s *ContentScanner) Add(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid DPI pattern %q: %w", pattern, err)
	}
	s.mu.Lock()
	s.raw = append(s.raw, pattern)
	s.compiled = append(s.compiled, re)
	s.mu.Unlock()
	return nil
}

// Remove deletes the first occurrence of pattern from the list.
// Returns true if a pattern was removed.
func (s *ContentScanner) Remove(pattern string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.raw {
		if p == pattern {
			s.raw = append(s.raw[:i], s.raw[i+1:]...)
			s.compiled = append(s.compiled[:i], s.compiled[i+1:]...)
			return true
		}
	}
	return false
}

// List returns a snapshot of all raw pattern strings.
func (s *ContentScanner) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.raw))
	copy(out, s.raw)
	return out
}

// Scan checks data against all compiled patterns.
// Returns the first matching raw pattern string and true, or ("", false).
func (s *ContentScanner) Scan(data []byte) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i, re := range s.compiled {
		if re.Match(data) {
			return s.raw[i], true
		}
	}
	return "", false
}

// isTextContentType reports whether a Content-Type header value indicates
// human-readable text that is worth regex-scanning.  Binary formats (images,
// video, compressed archives) are deliberately excluded — scanning them is
// expensive and rarely useful for signature-based detection.
func isTextContentType(ct string) bool {
	if ct == "" {
		return false
	}
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") ||
		strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/xml") ||
		strings.HasPrefix(ct, "application/xhtml") ||
		strings.HasPrefix(ct, "application/javascript") ||
		strings.HasPrefix(ct, "application/x-www-form-urlencoded")
}

// dpiBlock sends an HTTP 403 Forbidden response to dst and increments the
// DPI blocked counter.  It is called inside inspected tunnels after a
// signature match is detected in a buffered response body.
func dpiBlock(dst interface{ Write([]byte) (int, error) }, host, pattern string) {
	atomic.AddInt64(&statDPIBlocked, 1)
	logger.Printf("DPI_BLOCKED host=%s pattern=%q", host, pattern)
	const body = "Blocked by content inspection policy\r\n"
	fmt.Fprintf(dst,
		"HTTP/1.1 403 Forbidden\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		len(body), body,
	)
}
