package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

	// Tier 3.4: per-host DPI bypass list. Hosts in this map skip DPI regex
	// scanning entirely even when the scanner has patterns loaded. Used for
	// internal content mirrors, CI artifact servers, etc. where DPI false
	// positives would otherwise block legitimate traffic.
	bypassHosts map[string]bool
}

// dpiContentFile is the on-disk JSON envelope supporting both legacy
// (array-of-patterns) and new ({patterns, bypass_hosts}) formats.
type dpiContentFile struct {
	Patterns    []string `json:"patterns"`
	BypassHosts []string `json:"bypass_hosts,omitempty"`
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

// Load reads a JSON array of regex strings (legacy format) or a dpiContentFile
// envelope ({patterns, bypass_hosts}) from path. If the file does not exist,
// Load succeeds (empty scanner — no patterns active).
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
	// Detect envelope vs legacy array.
	trimmed := strings.TrimLeft(string(data), " \t\r\n")
	if strings.HasPrefix(trimmed, "{") {
		var env dpiContentFile
		if err := json.Unmarshal(data, &env); err != nil {
			return fmt.Errorf("content-scan JSON parse error: %w", err)
		}
		if err := s.Set(env.Patterns); err != nil {
			return err
		}
		s.SetBypassHosts(env.BypassHosts)
		return nil
	}
	var patterns []string
	if err := json.Unmarshal(data, &patterns); err != nil {
		return fmt.Errorf("content-scan JSON parse error: %w", err)
	}
	return s.Set(patterns)
}

// Save persists the current pattern list and bypass host list to the
// configured file path. Uses an atomic write (tmp + rename) so a crash never
// leaves a partial file. No-op if no path is configured. Writes the envelope
// format when bypass hosts are present, otherwise the legacy array format so
// existing tooling keeps working. Tier 3.4.
func (s *ContentScanner) Save() {
	s.mu.RLock()
	path := s.path
	bypass := make([]string, 0, len(s.bypassHosts))
	for h := range s.bypassHosts {
		bypass = append(bypass, h)
	}
	var data []byte
	if len(bypass) > 0 {
		env := dpiContentFile{
			Patterns:    append([]string(nil), s.raw...),
			BypassHosts: bypass,
		}
		data, _ = json.MarshalIndent(env, "", "  ")
	} else {
		data, _ = json.MarshalIndent(s.raw, "", "  ")
	}
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

// SetBypassHosts atomically replaces the DPI bypass host list. Hosts are
// lower-cased and trimmed. Tier 3.4.
func (s *ContentScanner) SetBypassHosts(hosts []string) {
	m := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			m[h] = true
		}
	}
	s.mu.Lock()
	s.bypassHosts = m
	s.mu.Unlock()
}

// BypassHosts returns a sorted copy of the current DPI bypass host list.
// Tier 3.4.
func (s *ContentScanner) BypassHosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.bypassHosts))
	for h := range s.bypassHosts {
		out = append(out, h)
	}
	// tiny insertion sort — list is short
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// IsBypassHost reports whether the given host is on the DPI bypass list.
// Hot path: called once per inspected tunnel response. Tier 3.4.
func (s *ContentScanner) IsBypassHost(host string) bool {
	if s == nil || host == "" {
		return false
	}
	if idx := strings.LastIndex(host, ":"); idx > 0 && !strings.Contains(host[idx:], "]") {
		host = host[:idx]
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bypassHosts[strings.ToLower(host)]
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

// dpiRegexTimeout limits how long a single DPI regex match may run.
// Prevents ReDoS from pathological patterns or crafted input.
const dpiRegexTimeout = 5 * time.Second

// Scan checks data against all compiled patterns.
// Returns the first matching raw pattern string and true, or ("", false).
// Each regex match is bounded by dpiRegexTimeout to prevent ReDoS hangs.
func (s *ContentScanner) Scan(data []byte) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i, re := range s.compiled {
		if matchDPIRegexWithTimeout(re, data, dpiRegexTimeout) {
			return s.raw[i], true
		}
	}
	return "", false
}

// matchDPIRegexWithTimeout runs re.Match(data) with a deadline.
// Returns false if the match does not complete in time (ReDoS prevention).
func matchDPIRegexWithTimeout(re *regexp.Regexp, data []byte, timeout time.Duration) bool {
	ch := make(chan bool, 1)
	go func() {
		ch <- re.Match(data)
	}()
	select {
	case matched := <-ch:
		return matched
	case <-time.After(timeout):
		logWarnf("DPI: regex timeout after %s on pattern %q", timeout, sanitizeLog(re.String()))
		return true // S17: fail-closed — treat timeout as suspicious match (Zero Trust)
	}
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
