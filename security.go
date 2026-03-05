package main

import (
	"net"
	"sync"
	"time"
)

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

// RateLimiter is a per-IP sliding-window rate limiter.
type RateLimiter struct {
	mu      sync.Mutex
	limit   int           // max requests per window
	window  time.Duration // window size
	clients map[string]*clientBucket
	enabled bool
}

type clientBucket struct {
	timestamps []time.Time
	lastSeen   time.Time
}

var rl = &RateLimiter{
	clients: map[string]*clientBucket{},
}

func (r *RateLimiter) Configure(limit int, window time.Duration) {
	r.mu.Lock()
	r.limit = limit
	r.window = window
	r.enabled = limit > 0
	r.mu.Unlock()
}

func (r *RateLimiter) Enabled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enabled
}

// Allow returns true if the IP is within its rate limit.
func (r *RateLimiter) Allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enabled {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-r.window)

	b, ok := r.clients[ip]
	if !ok {
		b = &clientBucket{}
		r.clients[ip] = b
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

	if len(b.timestamps) >= r.limit {
		return false
	}
	b.timestamps = append(b.timestamps, now)
	return true
}

// Cleanup removes stale client entries (call periodically).
func (r *RateLimiter) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-r.window * 2)
	for ip, b := range r.clients {
		if b.lastSeen.Before(cutoff) {
			delete(r.clients, ip)
		}
	}
}

func (r *RateLimiter) Limit() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.limit
}

func (r *RateLimiter) Window() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.window
}
