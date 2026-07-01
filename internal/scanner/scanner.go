// Package scanner is the DPI content scanner: a set of pre-compiled regex
// signatures applied to HTTP response bodies flowing through SSL-Inspect
// tunnels, with a per-host bypass list and atomic persistence. It is extracted
// from the flat package main per ADR-0002; its only Culvert dependencies are
// the obs / fileutil / hostutil seams.
//
// Patterns are standard Go regex strings. Matching is byte-level. Each match is
// bounded by a timeout to prevent ReDoS from pathological patterns or input.
package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

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

// New returns a ContentScanner with the given per-response buffer cap and an
// empty bypass-host set.
func New(maxBytes int64) *ContentScanner {
	return &ContentScanner{maxBytes: maxBytes, bypassHosts: map[string]bool{}}
}

// MaxBytes returns the per-response buffering cap.
func (s *ContentScanner) MaxBytes() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxBytes
}

// Path returns the configured persistence file path ("" when unset).
func (s *ContentScanner) Path() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

// SetPath sets the persistence file path without loading from it. Used by the
// test suite (and any caller wanting Save to target a specific file) in place
// of reaching into the unexported field after the ADR-0002 extraction.
func (s *ContentScanner) SetPath(path string) {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
}

// dpiContentFile is the on-disk JSON envelope supporting both legacy
// (array-of-patterns) and new ({patterns, bypass_hosts}) formats.
type dpiContentFile struct {
	Patterns    []string `json:"patterns"`
	BypassHosts []string `json:"bypass_hosts,omitempty"`
}

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
	// Bucket-4 durability hardening: AtomicWrite gives unique tmp + chmod +
	// fsync(file) + rename + best-effort fsync(parent dir).
	_ = fileutil.AtomicWrite(path, data, 0o600)
}

// SetBypassHosts atomically replaces the DPI bypass host list. Hosts are
// lower-cased and trimmed. Tier 3.4.
func (s *ContentScanner) SetBypassHosts(hosts []string) {
	m := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		h = hostutil.StripHostPort(strings.TrimSpace(strings.ToLower(h)))
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
	host = hostutil.StripHostPort(host)
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
		if MatchRegexWithTimeout(re, data, dpiRegexTimeout) {
			return s.raw[i], true
		}
	}
	return "", false
}

// MatchRegexWithTimeout runs re.Match(data) with a deadline.
// Returns false if the match does not complete in time (ReDoS prevention);
// on timeout it fails closed (treats a timeout as a suspicious match).
func MatchRegexWithTimeout(re *regexp.Regexp, data []byte, timeout time.Duration) bool {
	ch := make(chan bool, 1)
	go func() {
		ch <- re.Match(data)
	}()
	select {
	case matched := <-ch:
		return matched
	case <-time.After(timeout):
		obs.Warnf("DPI: regex timeout after %s on pattern %q", timeout, obs.Sanitize(re.String()))
		return true // S17: fail-closed — treat timeout as suspicious match (Zero Trust)
	}
}
