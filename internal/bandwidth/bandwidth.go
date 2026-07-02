// Package bandwidth is the per-node-group bandwidth/QoS policy engine: named
// policies with label selectors, priority-based matching (F10 overlap
// detection), token-bucket rate limiting, and atomic JSON persistence. It is
// extracted from package main per ADR-0002; the admin API handler and the
// globalBandwidth singleton stay in main (bandwidth.go shim).
package bandwidth

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// Policy defines rate limits for a node group or label match. Policies are
// evaluated against a node's labels; the highest-priority match wins. A
// MaxBytesPerSec of 0 means unlimited.
type Policy struct {
	Name           string            `json:"name"`
	LabelSelector  map[string]string `json:"label_selector"`    // matches nodes by labels
	MaxBytesPerSec int64             `json:"max_bytes_per_sec"` // 0 = unlimited
	Priority       int               `json:"priority"`          // higher = more important (for QoS ordering)
	CreatedAt      string            `json:"created_at"`
}

// PolicyInfo extends Policy with a human-readable rate.
type PolicyInfo struct {
	Policy
	HumanRate string `json:"human_rate"` // e.g. "10 MB/s", "1 GB/s", "unlimited"
}

// Manager manages bandwidth policies and their token buckets.
type Manager struct {
	mu       sync.RWMutex
	policies []Policy
	path     string
	limiters map[string]*tokenBucket // keyed by policy name
}

// tokenBucket implements a simple token bucket for bandwidth limiting.
type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second = maxBytesPerSec
	lastRefill time.Time
}

// newTokenBucket creates a token bucket with the given bytes-per-second rate.
func newTokenBucket(maxBytesPerSec int64) *tokenBucket {
	return &tokenBucket{
		tokens:     float64(maxBytesPerSec),
		maxTokens:  float64(maxBytesPerSec),
		refillRate: float64(maxBytesPerSec),
		lastRefill: time.Now(),
	}
}

// consume attempts to take n tokens from the bucket. Returns true if the
// tokens were available and consumed, false otherwise.
func (tb *tokenBucket) consume(n int64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.lastRefill = now

	// Refill tokens based on elapsed time.
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}

	if tb.tokens >= float64(n) {
		tb.tokens -= float64(n)
		return true
	}
	return false
}

// NewManager loads or creates a bandwidth policy store at the given path.
func NewManager(path string) *Manager {
	m := &Manager{
		path:     path,
		limiters: make(map[string]*tokenBucket),
	}

	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured store path
	if err == nil {
		if jerr := json.Unmarshal(data, &m.policies); jerr != nil {
			obs.Printf("Bandwidth: failed to parse %s: %v", path, jerr)
			m.policies = nil
		}
	}
	if m.policies == nil {
		m.policies = []Policy{}
	}
	// D1.1h: surface policies missing required fields. Loader keeps the
	// entry; warn so operators can spot match-nothing policies.
	for i, p := range m.policies {
		if p.Name == "" || len(p.LabelSelector) == 0 {
			obs.Printf("Loader: bandwidth.json: policy[%d] missing required field(s) at %q — keeping (D1.2-flag-F6)", i, obs.Sanitize(path))
		}
	}

	// Build token buckets for loaded policies.
	for i := range m.policies {
		p := &m.policies[i]
		if p.MaxBytesPerSec > 0 {
			m.limiters[p.Name] = newTokenBucket(p.MaxBytesPerSec)
		}
	}

	obs.Printf("Bandwidth: loaded %d policies from %s", len(m.policies), path)
	return m
}

// List returns a copy of all policies.
func (m *Manager) List() []Policy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Policy, len(m.policies))
	copy(out, m.policies)
	return out
}

// Add validates and appends a new policy, persists, and returns it.
func (m *Manager) Add(p Policy) (Policy, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return Policy{}, fmt.Errorf("name is required")
	}
	if p.MaxBytesPerSec < 0 {
		return Policy{}, fmt.Errorf("max_bytes_per_sec must be >= 0")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicates.
	for _, existing := range m.policies {
		if existing.Name == name {
			return Policy{}, fmt.Errorf("policy %q already exists", name)
		}
	}

	// F10: Check for priority conflicts with overlapping selectors.
	for _, existing := range m.policies {
		if existing.Priority == p.Priority && selectorsOverlap(existing.LabelSelector, p.LabelSelector) {
			return Policy{}, fmt.Errorf("priority %d conflicts with policy %q (overlapping label selectors)", p.Priority, existing.Name)
		}
	}

	p.Name = name
	if p.CreatedAt == "" {
		p.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	m.policies = append(m.policies, p)
	if p.MaxBytesPerSec > 0 {
		m.limiters[p.Name] = newTokenBucket(p.MaxBytesPerSec)
	}
	m.saveLocked()
	return p, nil
}

// Delete removes a policy by name and persists. Returns true if found.
func (m *Manager) Delete(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, p := range m.policies {
		if p.Name == name {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			delete(m.limiters, name)
			m.saveLocked()
			return true
		}
	}
	return false
}

// Save persists the current policies to disk.
func (m *Manager) Save() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.saveLocked()
}

// saveLocked writes policies to disk. Caller must hold at least a read lock.
func (m *Manager) saveLocked() {
	data, err := json.MarshalIndent(m.policies, "", "  ")
	if err != nil {
		obs.Printf("Bandwidth: marshal error: %v", err)
		return
	}
	if err := fileutil.AtomicWrite(m.path, data, 0o600); err != nil {
		obs.Printf("Bandwidth: failed to write %s: %v", m.path, err)
	}
}

// FindPolicy returns the highest-priority policy whose LabelSelector is a
// subset of the given labels. Returns nil if no policy matches.
func (m *Manager) FindPolicy(labels map[string]string) *Policy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var best *Policy
	for i := range m.policies {
		p := &m.policies[i]
		if matchLabels(p.LabelSelector, labels) {
			if best == nil || p.Priority > best.Priority {
				best = p
			}
		}
	}
	if best == nil {
		return nil
	}
	// Return a copy so the caller can't mutate internal state.
	cp := *best
	return &cp
}

// selectorsOverlap returns true if two label selectors could match the same node.
// Two selectors overlap when their shared keys have matching values (or when one
// is a subset of the other). This detects potential priority ambiguity (F10).
func selectorsOverlap(a, b map[string]string) bool {
	// If either is empty, it matches everything — always overlaps.
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	// Check if any shared key has a conflicting value.
	for k, va := range a {
		if vb, ok := b[k]; ok && va != vb {
			return false // disjoint on this key
		}
	}
	return true
}

// matchLabels returns true if every key-value pair in selector exists in labels.
func matchLabels(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// AllowBytes checks the token bucket for the named policy. Returns true if n
// bytes are available (and consumes them). Returns true for unknown policies
// or unlimited (0 rate) policies.
func (m *Manager) AllowBytes(policyName string, n int64) bool {
	m.mu.RLock()
	tb, ok := m.limiters[policyName]
	m.mu.RUnlock()

	if !ok {
		return true // no limiter = unlimited
	}
	return tb.consume(n)
}

// ReplaceAll atomically replaces all policies (used for config sync from CP).
func (m *Manager) ReplaceAll(policies []Policy) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.policies = make([]Policy, len(policies))
	copy(m.policies, policies)

	// Rebuild limiters.
	m.limiters = make(map[string]*tokenBucket, len(policies))
	for i := range m.policies {
		p := &m.policies[i]
		if p.MaxBytesPerSec > 0 {
			m.limiters[p.Name] = newTokenBucket(p.MaxBytesPerSec)
		}
	}
	m.saveLocked()
	obs.Printf("Bandwidth: replaced all policies (%d total)", len(m.policies))
}

// HumanRate converts bytes/sec to a human-readable string.
func HumanRate(bytesPerSec int64) string {
	if bytesPerSec <= 0 {
		return "unlimited"
	}
	const (
		kb = 1024
		mb = 1024 * 1024
		gb = 1024 * 1024 * 1024
	)
	switch {
	case bytesPerSec >= gb:
		val := float64(bytesPerSec) / float64(gb)
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d GB/s", int64(val))
		}
		return fmt.Sprintf("%.1f GB/s", val)
	case bytesPerSec >= mb:
		val := float64(bytesPerSec) / float64(mb)
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d MB/s", int64(val))
		}
		return fmt.Sprintf("%.1f MB/s", val)
	case bytesPerSec >= kb:
		val := float64(bytesPerSec) / float64(kb)
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d KB/s", int64(val))
		}
		return fmt.Sprintf("%.1f KB/s", val)
	default:
		return fmt.Sprintf("%d B/s", bytesPerSec)
	}
}
