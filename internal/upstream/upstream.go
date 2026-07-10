// Package upstream implements parent-proxy chaining with failover and
// circuit-breaker protection (ADR-0002 extraction; engine was upstream.go in
// package main).
//
// Culvert can route traffic through one or more parent HTTP proxies with
// automatic failover. When all upstreams are down the proxy falls back to
// direct connections. The package owns the pool state machine (round-robin
// selection, health flags, per-proxy circuit breakers) and the health-check
// loop; package main keeps the singleton, the transport wiring
// (applyUpstreamProxy), and persistence via admin_settings.
//
// Configuration (config.yaml):
//
//	upstream:
//	  proxies:
//	    - url: "http://parent1.corp.com:3128"
//	    - url: "http://parent2.corp.com:3128"
//	  health_interval: "30s"
//	  circuit_breaker:
//	    threshold: 5      # failures before opening circuit
//	    timeout: "60s"    # how long circuit stays open before half-open probe
package upstream

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// ─── Circuit breaker states ──────────────────────────────────────────────────

type circuitState int32

const (
	circuitClosed   circuitState = 0 // normal — requests flow through
	circuitOpen     circuitState = 1 // tripped — reject immediately
	circuitHalfOpen circuitState = 2 // probing — allow one request
)

// CircuitBreaker tracks consecutive failures for an upstream proxy.
type CircuitBreaker struct {
	state     atomic.Int32
	failures  atomic.Int64
	threshold int64
	timeout   time.Duration
	openedAt  atomic.Int64 // UnixMilli when circuit was opened
}

func newCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &CircuitBreaker{
		threshold: int64(threshold),
		timeout:   timeout,
	}
}

// Allow returns true if the circuit permits a request.
func (cb *CircuitBreaker) Allow() bool {
	st := circuitState(cb.state.Load())
	switch st {
	case circuitClosed:
		return true
	case circuitOpen:
		// Check if timeout has elapsed → transition to half-open.
		opened := time.UnixMilli(cb.openedAt.Load())
		if time.Since(opened) > cb.timeout {
			cb.state.CompareAndSwap(int32(circuitOpen), int32(circuitHalfOpen))
			return true
		}
		return false
	case circuitHalfOpen:
		return true // allow the probe request
	}
	return false
}

// RecordSuccess resets the failure count and closes the circuit.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.failures.Store(0)
	cb.state.Store(int32(circuitClosed))
}

// RecordFailure increments the failure count and opens the circuit if threshold is reached.
func (cb *CircuitBreaker) RecordFailure() {
	n := cb.failures.Add(1)
	if n >= cb.threshold {
		cb.state.Store(int32(circuitOpen))
		cb.openedAt.Store(time.Now().UnixMilli())
	}
}

// Params returns the breaker's configured threshold and timeout. Exported for
// the main-side persistence-contract tests (SetProxies must inherit
// Configure's params) and for diagnostics; not used on the request path.
func (cb *CircuitBreaker) Params() (threshold int, timeout time.Duration) {
	return int(cb.threshold), cb.timeout
}

// Failures returns the current consecutive-failure count. Exported for admin
// API / diagnostics surfacing; not used on the request path.
func (cb *CircuitBreaker) Failures() int64 {
	return cb.failures.Load()
}

// OpenedAt returns when the circuit last tripped open (zero Time if it has
// never opened, or has since been reset by RecordSuccess). Exported for admin
// API / diagnostics surfacing; not used on the request path.
func (cb *CircuitBreaker) OpenedAt() time.Time {
	if circuitState(cb.state.Load()) == circuitClosed {
		return time.Time{}
	}
	ms := cb.openedAt.Load()
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// State returns the current circuit state name.
func (cb *CircuitBreaker) State() string {
	switch circuitState(cb.state.Load()) {
	case circuitClosed:
		return "closed"
	case circuitOpen:
		return "open"
	case circuitHalfOpen:
		return "half-open"
	}
	return "unknown"
}

// ─── Upstream proxy entry ────────────────────────────────────────────────────

// Proxy represents one parent proxy in the chain.
type Proxy struct {
	URL     *url.URL
	Healthy atomic.Bool
	CB      *CircuitBreaker
}

// Pool manages a set of parent proxies with failover. The zero value is a
// usable empty pool.
type Pool struct {
	mu      sync.RWMutex
	proxies []*Proxy
	// entries mirrors proxies as the raw accepted Entry values (a proxy URL
	// may embed inline credentials, which *url.URL redacts for display).
	// Kept so the admin-settings snapshot can round-trip the pool faithfully
	// across restarts.
	entries []Entry
	// cbThreshold/cbTimeout are remembered from the last Configure so API
	// mutations (SetProxies) inherit the operator-configured circuit-breaker
	// parameters instead of hardcoded defaults.
	cbThreshold int
	cbTimeout   time.Duration
	idx         atomic.Int64 // round-robin counter
}

// Configure sets the list of upstream proxies and the circuit-breaker
// parameters (startup / YAML-reload / import path).
func (p *Pool) Configure(entries []Entry, cbThreshold int, cbTimeout time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cbThreshold = cbThreshold
	p.cbTimeout = cbTimeout
	p.setProxiesLocked(entries)
}

// SetProxies replaces the proxy list while keeping the circuit-breaker
// parameters from the last Configure (admin API / persisted-settings path).
func (p *Pool) SetProxies(entries []Entry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setProxiesLocked(entries)
}

func (p *Pool) setProxiesLocked(entries []Entry) {
	p.proxies = nil
	p.entries = nil
	for _, e := range entries {
		u, err := url.Parse(e.URL)
		if err != nil {
			obs.Printf("Upstream: invalid URL %q: %v", obs.Sanitize(e.URL), err)
			continue
		}
		if u.Host == "" {
			// "host:port" without a scheme parses as opaque (no Host) and can
			// never be dialed by the transport — reject instead of persisting.
			obs.Printf("Upstream: skipping URL %q: missing host (need scheme://host:port)", obs.Sanitize(e.URL))
			continue
		}
		up := &Proxy{
			URL: u,
			CB:  newCircuitBreaker(p.cbThreshold, p.cbTimeout),
		}
		up.Healthy.Store(true)
		p.proxies = append(p.proxies, up)
		p.entries = append(p.entries, e)
		obs.Printf("Upstream: added parent proxy %s", u.Redacted())
	}
}

// CBParams returns the circuit-breaker parameters remembered from the last
// Configure. Exported for the main-side snapshot/restore test helper and for
// diagnostics; not used on the request path.
func (p *Pool) CBParams() (threshold int, timeout time.Duration) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cbThreshold, p.cbTimeout
}

// Entries returns a copy of the raw accepted entries. URLs may embed inline
// credentials — this is for persistence (admin_settings.json, mode 0600)
// only; use List() for anything user-facing.
func (p *Pool) Entries() []Entry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Entry, len(p.entries))
	copy(out, p.entries)
	return out
}

// Enabled returns true if any upstream proxies are configured.
func (p *Pool) Enabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies) > 0
}

// Next returns the next healthy upstream proxy using round-robin selection.
// Returns nil if no healthy proxy is available (caller should fall back to direct).
func (p *Pool) Next() *Proxy {
	p.mu.RLock()
	proxies := p.proxies
	p.mu.RUnlock()

	n := len(proxies)
	if n == 0 {
		return nil
	}
	start := int(p.idx.Add(1)) % n
	for i := 0; i < n; i++ {
		up := proxies[(start+i)%n]
		if up.Healthy.Load() && up.CB.Allow() {
			return up
		}
	}
	return nil // all upstreams down — fall back to direct
}

// List returns the current upstream proxy statuses for the UI/API.
// URLs are redacted (inline credentials stripped).
func (p *Pool) List() []Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Status, len(p.proxies))
	for i, up := range p.proxies {
		st := Status{
			URL:      up.URL.Redacted(),
			Healthy:  up.Healthy.Load(),
			Circuit:  up.CB.State(),
			Failures: up.CB.Failures(),
		}
		if opened := up.CB.OpenedAt(); !opened.IsZero() {
			st.OpenedAtMs = opened.UnixMilli()
			_, timeout := up.CB.Params()
			if remaining := timeout - time.Since(opened); remaining > 0 {
				st.RetryAfterMs = remaining.Milliseconds()
			}
		}
		out[i] = st
	}
	return out
}

// ProxyFunc returns an http.Transport-compatible proxy selector.
// When upstreams are configured, it returns the next healthy proxy URL.
// Falls back to nil (direct connection) when no upstream is available.
func (p *Pool) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(_ *http.Request) (*url.URL, error) {
		if up := p.Next(); up != nil {
			return up.URL, nil
		}
		return nil, nil // direct connection
	}
}

// healthCheckURL is the probe target: a stable, minimal, plain-HTTP endpoint
// reachable THROUGH the parent proxy under test.
const healthCheckURL = "http://detectportal.firefox.com/success.txt"

// HealthCheck runs a connectivity check against each upstream proxy.
// Called periodically from a background goroutine.
func (p *Pool) HealthCheck() {
	p.mu.RLock()
	proxies := p.proxies
	p.mu.RUnlock()

	for _, up := range proxies {
		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy:             http.ProxyURL(up.URL),
				DisableKeepAlives: true,
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, healthCheckURL, http.NoBody)
		if err != nil {
			cancel()
			up.Healthy.Store(false)
			continue
		}
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			was := up.Healthy.Swap(false)
			if was {
				obs.Printf("Upstream: %s marked unhealthy: %v", up.URL.Redacted(), err)
			}
			continue
		}
		resp.Body.Close()
		was := up.Healthy.Swap(true)
		if !was {
			obs.Printf("Upstream: %s recovered (healthy)", up.URL.Redacted())
		}
	}
}

// RunHealthCheckLoop runs pool.HealthCheck at the given interval until ctx is
// cancelled, stopping the underlying ticker on exit. Extracted so the
// shutdown invariant — "the loop must exit on context cancellation" — is
// unit-testable without spinning up the rest of initUpstreamPool.
//
// Defensive contract: returns immediately for a nil pool or a non-positive
// interval. The production caller (initUpstreamPool) already validates these,
// but the standalone helper guards itself so future callers cannot panic
// (nil-deref) or wedge on a zero-interval ticker. P1.3 / S4.UpstreamHealth.
func RunHealthCheckLoop(ctx context.Context, pool *Pool, interval time.Duration) {
	if pool == nil || interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pool.HealthCheck()
		}
	}
}

// ─── Config types ────────────────────────────────────────────────────────────

// Entry is one parent proxy from config.yaml.
type Entry struct {
	URL string `yaml:"url" json:"url"`
}

// Config is the "upstream" section of config.yaml.
type Config struct {
	Proxies        []Entry `yaml:"proxies" json:"proxies"`
	HealthInterval string  `yaml:"health_interval" json:"healthInterval"` // Go duration
	CircuitBreaker struct {
		Threshold int    `yaml:"threshold" json:"threshold"` // failures before open
		Timeout   string `yaml:"timeout" json:"timeout"`     // Go duration
	} `yaml:"circuit_breaker" json:"circuitBreaker"`
}

// Status is returned by the admin API.
type Status struct {
	URL     string `json:"url"`
	Healthy bool   `json:"healthy"`
	Circuit string `json:"circuit"`
	// Failures is the current consecutive-failure count tracked by the
	// circuit breaker (resets to 0 on RecordSuccess).
	Failures int64 `json:"failures"`
	// OpenedAtMs is when the circuit last tripped open, as Unix
	// milliseconds; 0 when the circuit is closed.
	OpenedAtMs int64 `json:"openedAtMs,omitempty"`
	// RetryAfterMs is the remaining time (ms) until the breaker allows a
	// half-open probe; 0 when the circuit is not open.
	RetryAfterMs int64 `json:"retryAfterMs,omitempty"`
}

// FormatSummary returns a log-friendly summary like "2 proxies (parent1:3128, parent2:3128)".
func FormatSummary(entries []Entry) string {
	if len(entries) == 0 {
		return "direct"
	}
	hosts := make([]string, len(entries))
	for i, e := range entries {
		if u, err := url.Parse(e.URL); err == nil {
			hosts[i] = u.Host
		} else {
			hosts[i] = e.URL
		}
	}
	return fmt.Sprintf("%d proxies (%s)", len(entries), strings.Join(hosts, ", "))
}
