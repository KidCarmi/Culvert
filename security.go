package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// normalizeHost and stripHostPort moved to internal/hostutil (ADR-0002/0003).
// These thin wrappers keep the unqualified package-main call sites (policy,
// store, catdb, scanner, security_scan) and the existing tests unchanged.
func normalizeHost(host string) string { return hostutil.NormalizeHost(host) }
func stripHostPort(host string) string { return hostutil.StripHostPort(host) }

// normalizeHostStrict is the fail-closed variant used by the request-path
// dispatch gates (handleRequest, SOCKS5): ok=false means the host cannot be
// IDNA-canonicalized and the request must be REJECTED rather than evaluated
// against policy/blocklist with an un-normalized host (RISK-013).
func normalizeHostStrict(host string) (string, bool) { return hostutil.NormalizeHostStrict(host) }

// ─── SSRF guard (moved to internal/ssrf, ADR-0002) ──────────────────────────
// The CIDR table, DNS-cached host check, and connect-time dialer control live
// in internal/ssrf. These thin wrappers keep every unqualified call site (and
// the CodeQL inline-guard convention at those sites) unchanged.

// isPrivateIP reports whether ip falls within any private/internal range.
func isPrivateIP(ip net.IP) bool { return ssrf.PrivateIP(ip) }

// isPrivateHost resolves host (host or host:port) and returns an error if any
// resolved IP falls within a private/internal range (30s-TTL DNS cache;
// fail-closed on resolution errors).
func isPrivateHost(hostport string) error { return ssrf.PrivateHost(hostport) }

// ssrfControl is the connect-time guard (net.Dialer.Control) — rejects dials
// whose resolved address is private/internal. Re-exposed for the CONNECT and
// SOCKS5 paths, which build their own dialers.
var ssrfControl = ssrf.Control

// ssrfSafeDialContext is a net.Dialer.DialContext replacement that rejects
// connections to private/internal IPs at connect time (DNS-rebinding safe).
//
// Declared as a variable so that tests can temporarily replace it with a
// plain dialer that permits localhost webhook targets.
var ssrfSafeDialContext = ssrf.SafeDialContext

// ─── IP Filter ────────────────────────────────────────────────────────────────

// IPFilter supports allowlist and blocklist mode with CIDR ranges.
// Mode "allow"  → only IPs in the list are permitted (default: allow all).
// Mode "block"  → IPs in the list are denied.
type IPFilter struct {
	mu     sync.RWMutex
	mode   string // "allow" | "block" | "" (disabled)
	nets   []*net.IPNet
	single map[string]bool
}

var ipf = &IPFilter{single: map[string]bool{}}

// SetMode sets the IP-filter mode. Valid values are "allow" (allowlist),
// "block" (blocklist), and "" (disabled). The mode is stored verbatim — the
// fail-closed handling lives in Allowed(), which denies ALL traffic for any
// unrecognized (corrupt) mode. This is safer than coercing a corrupt value to
// "block" here, which would silently convert a corrupted *allowlist*
// deployment into a permissive blocklist (admitting every non-listed IP). The
// validated admin API path only ever passes "allow"/"block"; the raw
// persistence/snapshot paths (config reload, admin_settings restore,
// config-version rollback, cluster ConfigSnapshot) may carry corruption, and
// Allowed() fails closed on it.
func (f *IPFilter) SetMode(mode string) {
	f.mu.Lock()
	f.mode = mode
	f.mu.Unlock()
}

func (f *IPFilter) Mode() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mode
}

// Add accepts plain IPs ("1.2.3.4") or CIDR ("10.0.0.0/8").
func (f *IPFilter) Add(entry string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, cidr, err := net.ParseCIDR(entry); err == nil {
		f.nets = append(f.nets, cidr)
		return nil
	}
	if ip := net.ParseIP(entry); ip != nil {
		f.single[ip.String()] = true
		return nil
	}
	return &net.AddrError{Err: "invalid IP or CIDR", Addr: entry}
}

func (f *IPFilter) Remove(entry string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.single, entry)
	// Remove from nets slice.
	filtered := f.nets[:0]
	for _, n := range f.nets {
		if n.String() != entry {
			filtered = append(filtered, n)
		}
	}
	f.nets = filtered
}

// ClearAll removes all IP filter entries. Used by config import "replace" mode.
func (f *IPFilter) ClearAll() {
	f.mu.Lock()
	f.nets = nil
	f.single = map[string]bool{}
	f.mu.Unlock()
}

func (f *IPFilter) List() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]string, 0, len(f.single)+len(f.nets))
	for ip := range f.single {
		out = append(out, ip)
	}
	for _, n := range f.nets {
		out = append(out, n.String())
	}
	return out
}

// contains returns true if the given IP string matches any entry.
func (f *IPFilter) contains(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if f.single[ip.String()] {
		return true
	}
	for _, n := range f.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Allowed returns true when the IP should be allowed through.
//
// Mode semantics: "allow" = allowlist (only listed IPs pass), "block" =
// blocklist (listed IPs are denied), "" = disabled (filter off, all pass).
// ANY OTHER value is treated as corruption and DENIES ALL traffic (fail
// closed). Coercing a corrupt mode to "block" instead would be unsafe: a
// corrupted *allowlist* deployment (mode was "allow" with a list of the only
// trusted IPs) would become a blocklist that admits every IP not on the list —
// fail open. When we cannot trust the mode, we cannot reason about the list, so
// we deny everything until an operator restores a valid config.
func (f *IPFilter) Allowed(ipStr string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	switch f.mode {
	case "allow":
		return f.contains(ipStr)
	case "block":
		return !f.contains(ipStr)
	case "":
		return true // filter disabled
	default:
		return false // corrupt/unknown mode — deny all (fail closed)
	}
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

// RateLimiter is a per-IP sliding-window rate limiter using sharded locks to
// minimise contention in the hot path. 64 shards are chosen so that concurrent
// requests from different IPs almost never compete for the same lock.

const rlShardCount = 64

type rlShard struct {
	mu      sync.Mutex
	clients map[string]*clientBucket
}

// RateLimiter is a per-IP sliding-window rate limiter.
type RateLimiter struct {
	shards  [rlShardCount]rlShard
	limit   atomic.Int64
	window  atomic.Int64 // nanoseconds
	enabled atomic.Bool

	// Whitelist — exempt IPs/CIDRs that bypass rate limiting (e.g. monitoring).
	exemptMu   sync.RWMutex
	exemptNets []*net.IPNet
	exemptIPs  map[string]bool
}

type clientBucket struct {
	timestamps []time.Time
	lastSeen   time.Time
}

var rl = newRateLimiter()

func newRateLimiter() *RateLimiter {
	r := &RateLimiter{exemptIPs: map[string]bool{}}
	for i := range r.shards {
		r.shards[i].clients = make(map[string]*clientBucket)
	}
	return r
}

// IsExempt returns true if the IP is in the rate-limit exempt list.
func (r *RateLimiter) IsExempt(ip string) bool {
	r.exemptMu.RLock()
	defer r.exemptMu.RUnlock()
	if r.exemptIPs[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range r.exemptNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// AddExemption adds an IP or CIDR to the rate-limit exempt list.
func (r *RateLimiter) AddExemption(entry string) error {
	r.exemptMu.Lock()
	defer r.exemptMu.Unlock()
	if _, cidr, err := net.ParseCIDR(entry); err == nil {
		r.exemptNets = append(r.exemptNets, cidr)
		return nil
	}
	if ip := net.ParseIP(entry); ip != nil {
		r.exemptIPs[ip.String()] = true
		return nil
	}
	return &net.AddrError{Err: "invalid IP or CIDR", Addr: entry}
}

// RemoveExemption removes an IP or CIDR from the rate-limit exempt list.
func (r *RateLimiter) RemoveExemption(entry string) {
	r.exemptMu.Lock()
	defer r.exemptMu.Unlock()
	delete(r.exemptIPs, entry)
	filtered := r.exemptNets[:0]
	for _, n := range r.exemptNets {
		if n.String() != entry {
			filtered = append(filtered, n)
		}
	}
	r.exemptNets = filtered
}

// ReplaceExemptions atomically replaces the entire rate-limit exempt list.
// Invalid entries are skipped; a nil or empty slice clears the exempt list.
// The new IP/CIDR structures are built OUTSIDE the lock and swapped under a
// single Lock, so a concurrent IsExempt reader never observes a partial or
// stale-mixed state. Used by applyConfigBackup for config-version rollback
// (the missing clear/replace primitive for the RateLimitExempt surface).
func (r *RateLimiter) ReplaceExemptions(entries []string) {
	ips := make(map[string]bool, len(entries))
	var nets []*net.IPNet
	for _, entry := range entries {
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, cidr)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			ips[ip.String()] = true
		}
	}
	r.exemptMu.Lock()
	r.exemptIPs = ips
	r.exemptNets = nets
	r.exemptMu.Unlock()
}

// ListExemptions returns all rate-limit exempt list entries.
func (r *RateLimiter) ListExemptions() []string {
	r.exemptMu.RLock()
	defer r.exemptMu.RUnlock()
	out := make([]string, 0, len(r.exemptIPs)+len(r.exemptNets))
	for ip := range r.exemptIPs {
		out = append(out, ip)
	}
	for _, n := range r.exemptNets {
		out = append(out, n.String())
	}
	return out
}

func (r *RateLimiter) shard(ip string) *rlShard {
	// FNV-1a inspired hash — fast, good distribution.
	h := uint64(14695981039346656037)
	for i := 0; i < len(ip); i++ {
		h ^= uint64(ip[i])
		h *= 1099511628211
	}
	return &r.shards[h%rlShardCount]
}

func (r *RateLimiter) Configure(limit int, window time.Duration) {
	r.limit.Store(int64(limit))
	r.window.Store(int64(window))
	r.enabled.Store(limit > 0)
}

func (r *RateLimiter) Enabled() bool {
	return r.enabled.Load()
}

// Allow returns true if the IP is within its rate limit or is exempt.
func (r *RateLimiter) Allow(ip string) bool {
	if !r.enabled.Load() {
		return true
	}
	if r.IsExempt(ip) {
		return true
	}
	limit := int(r.limit.Load())
	window := time.Duration(r.window.Load())
	now := time.Now()
	cutoff := now.Add(-window)

	s := r.shard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.clients[ip]
	if !ok {
		b = &clientBucket{}
		s.clients[ip] = b
	}
	b.lastSeen = now

	// Evict old timestamps.
	valid := b.timestamps[:0]
	for _, t := range b.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	b.timestamps = valid

	if len(b.timestamps) >= limit {
		return false
	}
	b.timestamps = append(b.timestamps, now)
	return true
}

// Cleanup removes stale client entries (call periodically).
func (r *RateLimiter) Cleanup() {
	window := time.Duration(r.window.Load())
	cutoff := time.Now().Add(-window * 2)
	for i := range r.shards {
		s := &r.shards[i]
		s.mu.Lock()
		for ip, b := range s.clients {
			if b.lastSeen.Before(cutoff) {
				delete(s.clients, ip)
			}
		}
		s.mu.Unlock()
	}
}

func (r *RateLimiter) Limit() int {
	return int(r.limit.Load())
}

func (r *RateLimiter) Window() time.Duration {
	return time.Duration(r.window.Load())
}

// ─── Distributed rate limiting (gossip-based) ────────────────────────────────
//
// Each Data Plane node tracks local per-IP request counts. Periodically, "hot"
// IPs (those exceeding hotThresholdPct of the limit) are reported as deltas to
// the Control Plane. The CP aggregates cluster-wide totals and broadcasts them
// back. Each DP node's Allow() checks: localCount + clusterRemoteCount >= limit.
//
// This avoids Redis: counters stay in-memory, only delta gossip crosses the
// wire, and only for IPs that actually matter.

// hotThresholdPct is the percentage of the rate limit an IP must reach before
// its counts are synced to the Control Plane. Keeps gossip traffic minimal.
const hotThresholdPct = 50

// RateLimitDelta is a per-IP request count delta sent from DP → CP.
type RateLimitDelta struct {
	IP    string `json:"ip"`
	Count int    `json:"count"` // requests since last sync
}

// RateLimitGossip is the DP → CP message containing hot-IP deltas.
type RateLimitGossip struct {
	NodeID string           `json:"node_id"`
	Deltas []RateLimitDelta `json:"deltas"`
}

// RateLimitBroadcast is the CP → DP response with cluster-wide totals
// (excluding the requesting node's own counts, so the DP can add them locally).
type RateLimitBroadcast struct {
	// RemoteCounts maps IP → total requests from OTHER nodes in the current window.
	RemoteCounts map[string]int `json:"remote_counts"`
}

// clusterCounts holds per-IP request totals received from the Control Plane
// (other nodes' aggregated counts). Protected by its own mutex to avoid
// contention with the hot-path Allow() sharded locks.
type clusterCountStore struct {
	mu     sync.RWMutex
	counts map[string]int // IP → remote cluster count in current window
}

var clusterCounts = &clusterCountStore{counts: map[string]int{}}

// Get returns the cluster-remote count for an IP.
func (c *clusterCountStore) Get(ip string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.counts[ip]
}

// Apply replaces the cluster-remote counts with a new broadcast.
func (c *clusterCountStore) Apply(remote map[string]int) {
	c.mu.Lock()
	c.counts = remote
	c.mu.Unlock()
}

// Count returns the number of IPs tracked.
func (c *clusterCountStore) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.counts)
}

// ExportHotDeltas returns per-IP request count deltas for IPs that have
// reached at least hotThresholdPct of the configured limit since the last
// call. Counts are reset after export (delta, not absolute).
func (r *RateLimiter) ExportHotDeltas() []RateLimitDelta {
	if !r.enabled.Load() {
		return nil
	}
	limit := int(r.limit.Load())
	if limit <= 0 {
		return nil
	}
	threshold := limit * hotThresholdPct / 100
	if threshold < 1 {
		threshold = 1
	}
	window := time.Duration(r.window.Load())
	cutoff := time.Now().Add(-window)

	var deltas []RateLimitDelta
	for i := range r.shards {
		s := &r.shards[i]
		s.mu.Lock()
		for ip, b := range s.clients {
			// Count only in-window timestamps.
			count := 0
			for _, t := range b.timestamps {
				if t.After(cutoff) {
					count++
				}
			}
			if count >= threshold {
				deltas = append(deltas, RateLimitDelta{IP: ip, Count: count})
			}
		}
		s.mu.Unlock()
	}
	return deltas
}

// clusterRateLimitEnabled is set to true when this node is a Data Plane
// receiving cluster-wide rate limit gossip. Checked by AllowAuto().
var clusterRateLimitEnabled atomic.Bool

// AllowAuto dispatches to AllowClusterAware when cluster rate limiting is
// active, or plain Allow when running standalone. This is the method that
// proxy.go and socks5.go should call.
func (r *RateLimiter) AllowAuto(ip string) bool {
	if clusterRateLimitEnabled.Load() {
		return r.AllowClusterAware(ip)
	}
	return r.Allow(ip)
}

// AllowClusterAware is like Allow but also considers cluster-remote counts.
// Used when the node is operating as a Data Plane in a cluster.
func (r *RateLimiter) AllowClusterAware(ip string) bool {
	if !r.enabled.Load() {
		return true
	}
	if r.IsExempt(ip) {
		return true
	}
	limit := int(r.limit.Load())
	window := time.Duration(r.window.Load())
	now := time.Now()
	cutoff := now.Add(-window)

	s := r.shard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.clients[ip]
	if !ok {
		b = &clientBucket{}
		s.clients[ip] = b
	}
	b.lastSeen = now

	// Evict old timestamps.
	valid := b.timestamps[:0]
	for _, t := range b.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	b.timestamps = valid

	// Check local + remote cluster count against limit.
	localCount := len(b.timestamps)
	remoteCount := clusterCounts.Get(ip)
	if localCount+remoteCount >= limit {
		return false
	}
	b.timestamps = append(b.timestamps, now)
	return true
}
