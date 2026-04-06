package main

// connlimit.go — Per-IP connection limiting and request tracing.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
)

// ─── Request ID generation ──────────────────────────────────────────────────

// generateRequestID creates a random 16-char hex string for request tracing.
func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

// generateTraceparent creates a W3C Trace Context traceparent header value.
// Format: "00-{trace-id}-{parent-id}-01"  (version 00, sampled flag 01)
// See https://www.w3.org/TR/trace-context/
func generateTraceparent() string {
	var buf [24]byte // 16 (trace-id) + 8 (parent-id)
	if _, err := rand.Read(buf[:]); err != nil {
		return "00-00000000000000000000000000000000-0000000000000000-01"
	}
	return fmt.Sprintf("00-%s-%s-01", hex.EncodeToString(buf[:16]), hex.EncodeToString(buf[16:]))
}

// ─── Per-IP connection limiter ──────────────────────────────────────────────
// Prevents a single IP from consuming all proxy resources via many concurrent
// connections (e.g. HTTP flood, slow-read attacks).

const defaultMaxConnsPerIP = 1024

// ConnLimiter tracks active connections per client IP.
type ConnLimiter struct {
	mu       sync.Mutex
	conns    map[string]*int64
	maxPerIP int
	enabled  atomic.Bool
}

var connLimiter = &ConnLimiter{
	conns:    make(map[string]*int64),
	maxPerIP: defaultMaxConnsPerIP,
}

// Enable turns on connection limiting.
func (cl *ConnLimiter) Enable(maxPerIP int) {
	if maxPerIP <= 0 {
		maxPerIP = defaultMaxConnsPerIP
	}
	cl.maxPerIP = maxPerIP
	cl.enabled.Store(true)
}

// Disable turns off connection limiting.
func (cl *ConnLimiter) Disable() { cl.enabled.Store(false) }

// MaxPerIP returns the current per-IP limit.
func (cl *ConnLimiter) MaxPerIP() int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.maxPerIP
}

// ActiveIPs returns the number of IPs currently tracked.
func (cl *ConnLimiter) ActiveIPs() int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return len(cl.conns)
}

// Acquire increments the connection count for ip. Returns false if the limit
// is exceeded (caller should reject the request).
func (cl *ConnLimiter) Acquire(ip string) bool {
	if !cl.enabled.Load() {
		return true // disabled, always allow
	}
	cl.mu.Lock()
	ctr, ok := cl.conns[ip]
	if !ok {
		v := int64(0)
		ctr = &v
		cl.conns[ip] = ctr
	}
	cl.mu.Unlock()

	n := atomic.AddInt64(ctr, 1)
	if n > int64(cl.maxPerIP) {
		atomic.AddInt64(ctr, -1)
		return false
	}
	return true
}

// Release decrements the connection count for ip.
func (cl *ConnLimiter) Release(ip string) {
	if !cl.enabled.Load() {
		return
	}
	cl.mu.Lock()
	ctr, ok := cl.conns[ip]
	cl.mu.Unlock()
	if ok {
		if atomic.AddInt64(ctr, -1) <= 0 {
			cl.mu.Lock()
			if atomic.LoadInt64(ctr) <= 0 {
				delete(cl.conns, ip)
			}
			cl.mu.Unlock()
		}
	}
}

// ActiveConns returns the current connection count for an IP (testing).
func (cl *ConnLimiter) ActiveConns(ip string) int64 {
	cl.mu.Lock()
	ctr, ok := cl.conns[ip]
	cl.mu.Unlock()
	if !ok {
		return 0
	}
	return atomic.LoadInt64(ctr)
}
