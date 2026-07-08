// Package connlimit provides per-IP connection limiting. It prevents a single
// client IP from consuming all proxy resources via many concurrent connections
// (e.g. HTTP flood, slow-read attacks). It is a self-contained leaf (stdlib
// only, no Culvert coupling) extracted from the flat package main per ADR-0002.
package connlimit

import (
	"sync"
	"sync/atomic"
)

const defaultMaxConnsPerIP = 1024

// ConnLimiter tracks active connections per client IP.
type ConnLimiter struct {
	mu       sync.Mutex
	conns    map[string]*int64
	maxPerIP int
	enabled  atomic.Bool
}

// New returns a ConnLimiter with the default per-IP cap, initially disabled.
func New() *ConnLimiter {
	return &ConnLimiter{
		conns:    make(map[string]*int64),
		maxPerIP: defaultMaxConnsPerIP,
	}
}

// Enable turns on connection limiting.
func (cl *ConnLimiter) Enable(maxPerIP int) {
	if maxPerIP <= 0 {
		maxPerIP = defaultMaxConnsPerIP
	}
	// Enable is called at runtime (admin API, config import, CP snapshot
	// sync) while Acquire reads maxPerIP on the proxy hot path — the write
	// must happen under the same lock.
	cl.mu.Lock()
	cl.maxPerIP = maxPerIP
	cl.mu.Unlock()
	cl.enabled.Store(true)
}

// Disable turns off connection limiting.
func (cl *ConnLimiter) Disable() { cl.enabled.Store(false) }

// Enabled reports whether connection limiting is currently active.
func (cl *ConnLimiter) Enabled() bool { return cl.enabled.Load() }

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
	// Hold lock through the increment to prevent TOCTOU race with Release().
	n := atomic.AddInt64(ctr, 1)
	// Snapshot the limit under the lock — Enable() may rewrite it at runtime.
	limit := int64(cl.maxPerIP)
	cl.mu.Unlock()

	if n > limit {
		cl.mu.Lock()
		// Re-check that the counter still exists in the map before decrementing.
		if cur, exists := cl.conns[ip]; exists && cur == ctr {
			atomic.AddInt64(ctr, -1)
		}
		cl.mu.Unlock()
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
