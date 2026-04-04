package main

// connlimit.go — Per-IP connection limiting and request tracing.

import (
	"crypto/rand"
	"encoding/hex"
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
