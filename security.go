package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ─── SSRF-safe dialer ────────────────────────────────────────────────────────

// ssrfSafeDialContext is a net.Dialer.DialContext replacement that resolves
// DNS and rejects connections to private/internal IP addresses. Use as the
// DialContext in an http.Transport to prevent SSRF at the network level,
// independent of URL validation.
//
// Declared as a variable so that tests can temporarily replace it with a
// plain dialer that permits localhost webhook targets.
var ssrfSafeDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ssrf dial: invalid address %q: %w", addr, err)
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("ssrf dial: DNS resolution failed for %s: %w", host, err)
	}
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil && isPrivateIP(ip) {
			return nil, fmt.Errorf("ssrf dial: %s resolves to private address %s", host, ipStr)
		}
	}
	// All resolved IPs are public — dial the original address.
	return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, net.JoinHostPort(host, port))
}

// ─── DNS result cache for SSRF checks ────────────────────────────────────────
// Avoids repeated DNS lookups in isPrivateHost() for the same host within a
// short window. Entries expire after dnsSSRFCacheTTL. Negative results (DNS
// errors) are NOT cached so that transient failures remain fail-closed.

const dnsSSRFCacheTTL = 30 * time.Second

type dnsSSRFEntry struct {
	private bool // true if any resolved IP was private
	expires time.Time
}

type dnsSSRFCache struct {
	mu      sync.RWMutex
	entries map[string]dnsSSRFEntry
}

var ssrfDNSCache = &dnsSSRFCache{entries: make(map[string]dnsSSRFEntry)}

// Lookup returns (isPrivate, found). If found is false the caller must do a
// live DNS lookup and call Store.
func (c *dnsSSRFCache) Lookup(host string) (bool, bool) {
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return false, false
	}
	return e.private, true
}

// Store records a positive (resolved) result. DNS errors are not stored.
func (c *dnsSSRFCache) Store(host string, private bool) {
	c.mu.Lock()
	c.entries[host] = dnsSSRFEntry{
		private: private,
		expires: time.Now().Add(dnsSSRFCacheTTL),
	}
	c.mu.Unlock()
}

// Cleanup evicts expired entries (called periodically from main tick loop).
func (c *dnsSSRFCache) Cleanup() {
	c.mu.Lock()
	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()
}

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
func (f *IPFilter) Allowed(ipStr string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	switch f.mode {
	case "allow":
		return f.contains(ipStr)
	case "block":
		return !f.contains(ipStr)
	default:
		return true
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
}

type clientBucket struct {
	timestamps []time.Time
	lastSeen   time.Time
}

var rl = newRateLimiter()

func newRateLimiter() *RateLimiter {
	r := &RateLimiter{}
	for i := range r.shards {
		r.shards[i].clients = make(map[string]*clientBucket)
	}
	return r
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

// Allow returns true if the IP is within its rate limit.
func (r *RateLimiter) Allow(ip string) bool {
	if !r.enabled.Load() {
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
