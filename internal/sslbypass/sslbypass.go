// Package sslbypass is the SSL-inspection bypass matcher: a runtime-managed
// list of host patterns (FQDN globs via hostutil.MatchFQDN semantics, or
// "~"-prefixed regexes) that must always bypass SSL inspection regardless of
// what the PBAC policy says, with pre-compiled matching and JSON file
// persistence. Extracted from package main's policy.go per ADR-0002
// (policy.go decomposition Phase B).
//
// package main keeps the surfaces: the `sslBypass` singleton, the
// /api/ssl-bypass handlers, the inspection-rules startup slice, cluster
// sync, and config-version rollback — all through aliases. Matches sits on
// the per-CONNECT hot path (resolveSSLAction).
package sslbypass

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// pattern holds one compiled bypass entry.
// Glob patterns (e.g. "*.co.il") use hostutil.MatchFQDN semantics.
// Regex patterns are prefixed with "~" (e.g. "~^.*\.gov\.il$").
type pattern struct {
	raw  string
	norm string // hostutil.NormalizeHost(raw), precomputed for glob patterns ("" for regex)
	isRE bool
	re   *regexp.Regexp
}

// Matcher holds a list of host patterns that must always bypass SSL
// inspection, regardless of what the PBAC policy says. Patterns are managed
// at runtime via /api/ssl-bypass and persisted to a JSON file so they
// survive restarts without modifying config.yaml. The zero value is a valid
// empty matcher.
type Matcher struct {
	mu       sync.RWMutex
	raw      []string  // raw strings for persistence and API listing
	compiled []pattern // pre-compiled for fast matching
	path     string    // optional JSON file path for persistence
}

func compilePattern(p string) (pattern, error) {
	bp := pattern{raw: p}
	if strings.HasPrefix(p, "~") {
		re, err := regexp.Compile(p[1:])
		if err != nil {
			return pattern{}, fmt.Errorf("ssl bypass pattern %q: %w", p, err)
		}
		bp.isRE = true
		bp.re = re
		return bp, nil
	}
	// Normalize the glob pattern ONCE at compile time so Matches can use
	// MatchFQDNNorm — the same precompute the policy engine applies to rule
	// FQDNs (PolicyRule.normFQDN). NormalizeHost is pure/deterministic, so
	// this is byte-identical to normalizing per call inside MatchFQDN.
	bp.norm = hostutil.NormalizeHost(p)
	return bp, nil
}

// Set atomically replaces all bypass patterns.
func (m *Matcher) Set(patterns []string) error {
	compiled := make([]pattern, 0, len(patterns))
	for _, p := range patterns {
		bp, err := compilePattern(p)
		if err != nil {
			return err
		}
		compiled = append(compiled, bp)
	}
	m.mu.Lock()
	m.raw = append([]string(nil), patterns...)
	m.compiled = compiled
	m.mu.Unlock()
	return nil
}

// Load reads bypass patterns from a JSON file (array of strings).
// A missing file is treated as an empty list (not an error).
// Sets the persistence path so subsequent Save() calls write to this file.
func (m *Matcher) Load(path string) error {
	m.path = path
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var patterns []string
	if err := json.Unmarshal(data, &patterns); err != nil {
		return err
	}
	return m.Set(patterns)
}

// Save atomically persists the current patterns to the configured JSON file.
// A temporary file + rename ensures a crash mid-write never corrupts the list.
func (m *Matcher) Save() {
	if m.path == "" {
		return
	}
	m.mu.RLock()
	raw := make([]string, len(m.raw))
	copy(raw, m.raw)
	m.mu.RUnlock()

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return
	}
	// Bucket-4 durability hardening: fileutil.AtomicWrite gives unique
	// tmp + chmod + fsync(file) + rename + best-effort fsync(parent
	// dir) — replaces the previous os.WriteFile+os.Rename which was
	// atomic-via-rename but NOT fsynced.
	// CHAOS-27: tracked — a lost write silently restores the old bypass set,
	// changing which traffic is inspected after a restart.
	_ = fileutil.AtomicWriteTracked("ssl_bypass", m.path, data, 0o600)
}

// Add appends a single pattern. No-ops if the pattern is already present.
func (m *Matcher) Add(p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.raw {
		if existing == p {
			return nil // already present
		}
	}
	bp, err := compilePattern(p)
	if err != nil {
		return err
	}
	m.raw = append(m.raw, p)
	m.compiled = append(m.compiled, bp)
	return nil
}

// Remove deletes a pattern by exact string match. Returns true if removed.
func (m *Matcher) Remove(p string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, existing := range m.raw {
		if existing == p {
			m.raw = append(m.raw[:i], m.raw[i+1:]...)
			m.compiled = append(m.compiled[:i], m.compiled[i+1:]...)
			return true
		}
	}
	return false
}

// List returns a snapshot of all raw patterns.
func (m *Matcher) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.raw))
	copy(out, m.raw)
	return out
}

// Matches reports whether host matches any configured bypass pattern.
// Glob patterns follow hostutil.MatchFQDN semantics ("*.co.il" matches
// "www.co.il"). Regex patterns (prefix "~") are matched against the
// lower-cased bare host.
func (m *Matcher) Matches(host string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Fast path: no patterns configured (the default) — skip the IDNA
	// normalization entirely.
	if len(m.compiled) == 0 {
		return false
	}
	// Normalize the host ONCE; each glob compares against the pattern's
	// precomputed normalized form (MatchFQDNNorm). The previous per-pattern
	// MatchFQDN re-normalized BOTH arguments on every iteration — ~735 ns +
	// 4 allocs per pattern per inspected CONNECT.
	h := hostutil.NormalizeHost(host)
	// NormalizeHost is not idempotent for a host carrying an empty trailing
	// DNS label ("example.com.." — TrimSuffix strips one dot, IDNA keeps the
	// other), and such hosts pass the request path's NormalizeHostStrict gate.
	// The pre-optimization code re-normalized the host inside per-pattern
	// MatchFQDN — for GLOB patterns only — so "example.com.." matched the
	// bypass pattern "example.com" while regexes matched against the
	// single-pass form. Preserve those exact semantics: globs compare against
	// hg (a second pass paid ONLY on the pathological trailing-dot shape),
	// regexes keep h. The common path stays single-pass with hg == h
	// (Codex + Copilot reviews, PR #918).
	hg := h
	if strings.HasSuffix(hg, ".") {
		hg = hostutil.NormalizeHost(hg)
	}
	for _, p := range m.compiled {
		if p.isRE {
			if p.re.MatchString(h) {
				return true
			}
		} else {
			if hostutil.MatchFQDNNorm(p.norm, hg) {
				return true
			}
		}
	}
	return false
}

// Path reports the persistence path ("" = persistence disabled).
func (m *Matcher) Path() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.path
}

// SetPathForTest points persistence at path without loading.
func (m *Matcher) SetPathForTest(path string) {
	m.mu.Lock()
	m.path = path
	m.mu.Unlock()
}
