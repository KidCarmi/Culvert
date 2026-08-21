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
	rejected atomic.Int64
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

// Rejected returns the cumulative count of connections refused because the
// client IP was over its per-IP cap (process lifetime; never reset). This is
// the only signal an admin has that a configured limit is actually rejecting
// live traffic rather than sitting unused — the reject path (proxy.go,
// socks5.go) has no other counter or metric.
func (cl *ConnLimiter) Rejected() int64 {
	return cl.rejected.Load()
}

// Acquire records a connection from ip and reports whether it is admitted
// (false ⇒ the per-IP limit is exceeded and the caller should reject).
//
// The per-IP counter is ALWAYS maintained, even while the limiter is disabled;
// the enabled flag gates only the rejection decision, not the accounting. This
// keeps Acquire and Release symmetric across a runtime disable/re-enable: every
// admitted connection is counted exactly once and released exactly once. If
// Acquire skipped counting while disabled (the historical behavior), a
// connection admitted during the disabled window would later be Released
// unconditionally and decrement a DIFFERENT, still-counted connection's slot —
// letting a subsequent re-enable admit past the cap (fail-open). Conversely,
// gating Release on enabled leaks the slot of a connection counted while
// enabled and released after disable, wedging that IP over-limit forever
// (the #503 fail-closed bug). Counting unconditionally closes both.
func (cl *ConnLimiter) Acquire(ip string) bool {
	cl.mu.Lock()
	ctr, ok := cl.conns[ip]
	if !ok {
		v := int64(0)
		ctr = &v
		cl.conns[ip] = ctr
	}
	// Hold lock through the increment to prevent TOCTOU race with Release().
	n := atomic.AddInt64(ctr, 1)
	// Snapshot enabled + the limit under the lock — Enable()/Disable() may
	// rewrite them at runtime.
	enabled := cl.enabled.Load()
	limit := int64(cl.maxPerIP)
	cl.mu.Unlock()

	if enabled && n > limit {
		// Over the cap: this connection is NOT admitted, so it will never be
		// Released — undo its count now (and drop the entry if it was the last).
		cl.mu.Lock()
		if cur, exists := cl.conns[ip]; exists && cur == ctr {
			if atomic.AddInt64(ctr, -1) <= 0 {
				delete(cl.conns, ip)
			}
		}
		cl.mu.Unlock()
		cl.rejected.Add(1)
		return false
	}
	return true
}

// Release decrements the connection count for ip. It does NOT gate on enabled:
// Acquire counts every admitted connection unconditionally (see its doc), so
// Release must mirror that exactly. The decrement is guarded by map-entry
// presence, and the ≤0 delete prevents underflow, so releasing an IP with no
// live count is a safe no-op.
func (cl *ConnLimiter) Release(ip string) {
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
