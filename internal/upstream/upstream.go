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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
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

// RecordFailure increments the failure count and opens the circuit if the
// threshold is reached. It returns true exactly when this call transitioned
// the circuit into the open state (closed/half-open → open), so callers can
// log/alert once per trip instead of once per failure. Failures recorded
// while already open refresh openedAt (extending the open window) and
// return false.
func (cb *CircuitBreaker) RecordFailure() bool {
	n := cb.failures.Add(1)
	if n >= cb.threshold {
		// openedAt is stored before the state flips so a concurrent Allow()
		// observing the open state never reads a stale trip timestamp.
		cb.openedAt.Store(time.Now().UnixMilli())
		return cb.state.Swap(int32(circuitOpen)) != int32(circuitOpen)
	}
	return false
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

	// Direct-fallback visibility (CHAOS-11): before this existed the
	// all-upstreams-down → direct-egress fail-open (PX-2 posture) was
	// completely silent — no log, no alert, no counter. The posture itself
	// is unchanged; these only make it observable.
	fallbackActive atomic.Bool  // pool is currently failing open to direct
	fallbackTotal  atomic.Int64 // requests that fell back to direct since start
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
	// Replacing the pool resets the direct-fallback transition state (Codex
	// P2): a wiped pool makes direct egress the intentional operating mode
	// again (the flag would otherwise report an active failed-chain bypass
	// forever), and a repopulated pool re-derives — and re-alerts — on the
	// next request if the new parents are also down.
	p.fallbackActive.Store(false)
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
		// Pool not configured — direct egress is the normal mode, never a
		// fallback. Also clear any stale fallback flag: the shared transport
		// can still hold this pool's ProxyFunc after an admin wiped the last
		// parent (applyUpstreamProxy early-returns for a disabled pool).
		// Load-before-Store keeps this hot path read-only in the common case.
		if p.fallbackActive.Load() {
			p.fallbackActive.Store(false)
		}
		return nil
	}
	start := int(p.idx.Add(1)) % n
	for i := 0; i < n; i++ {
		up := proxies[(start+i)%n]
		if up.Healthy.Load() && up.CB.Allow() {
			p.noteUpstreamAvailable()
			return up
		}
	}
	// All upstreams down — fall back to direct (PX-2 fail-open posture,
	// unchanged). CHAOS-11: count every fallback and alert once per
	// transition so the bypassed parent-proxy chain is never silent.
	p.noteDirectFallback()
	return nil
}

// fireFallbackAlert delivers the upstream_pool_down alert on a fallback
// transition. Package-level seam so tests can capture transitions
// SYNCHRONOUSLY instead of listening on the process-global alerts sink —
// any pool-exhausting test spawns the async production goroutine, and a
// straggler landing in a later test's sink is exactly the -count/-shuffle
// determinism failure the CI gate caught. The production value fires async
// because the transition edge sits on the request path and alerts Dispatch
// can hit a synchronous retry-queue disk write when the webhook semaphore
// is full (same rationale as secscan's clamScanError).
var fireFallbackAlert = func(detail string) {
	go alerts.Fire("upstream_pool_down", alerts.Payload{
		Detail: detail,
		Source: "upstream",
	})
}

// noteDirectFallback records that a request needed a parent proxy but none
// was available (all unhealthy or circuit-open). The counter increments per
// request; the log line + webhook alert fire once per transition INTO the
// fallback state (noteUpstreamAvailable logs the recovery transition).
func (p *Pool) noteDirectFallback() {
	p.fallbackTotal.Add(1)
	if !p.fallbackActive.Swap(true) {
		obs.Printf("Upstream: ALL parent proxies down — failing open to DIRECT egress (parent-proxy chain bypassed)")
		const detail = "all parent proxies unhealthy or circuit-open; egress is DIRECT (parent-proxy chain bypassed)"
		if h := FallbackAlertHook; h != nil {
			h(detail)
		} else {
			fireFallbackAlert(detail)
		}
	}
}

// noteUpstreamAvailable clears the direct-fallback state when a usable proxy
// reappears. The Load-before-Swap keeps the common path (fallback inactive)
// read-only — no cache-line write per request.
func (p *Pool) noteUpstreamAvailable() {
	if p.fallbackActive.Load() && p.fallbackActive.Swap(false) {
		obs.Printf("Upstream: parent proxy available again — direct-egress fallback ended")
	}
}

// DirectFallback reports whether the pool is currently failing open to
// direct egress (all parents down) and how many requests have done so since
// startup. Exported for the admin API and /metrics.
func (p *Pool) DirectFallback() (active bool, total int64) {
	return p.fallbackActive.Load(), p.fallbackTotal.Load()
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
//
// If the request context carries an Attribution slot (WithAttribution), the
// selected proxy is recorded there so the caller can feed the request's
// outcome back into that proxy's circuit breaker (CHAOS-11).
func (p *Pool) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		up := p.Next()
		if req != nil {
			if a, ok := req.Context().Value(attributionKey{}).(*Attribution); ok {
				a.proxy.Store(up) // nil when falling back to direct — Record then no-ops
			}
		}
		if up != nil {
			return up.URL, nil
		}
		return nil, nil // direct connection
	}
}

// ─── Request-outcome attribution (CHAOS-11) ──────────────────────────────────
//
// Before this existed the circuit breaker was dead code on the request path:
// nothing production ever called RecordFailure/RecordSuccess, so a broken
// parent proxy kept receiving (and failing) live traffic until the next
// health-check tick — and the breaker state shown in the admin UI never
// moved. Attribution threads the transport's per-request proxy selection
// back to the caller so real request outcomes drive the breaker.

// attributionKey is the context key carrying the per-request attribution slot.
type attributionKey struct{}

// Attribution records which pool proxy the transport selected for one
// request. Create with WithAttribution; ProxyFunc fills it during RoundTrip.
type Attribution struct {
	proxy atomic.Pointer[Proxy]
}

// WithAttribution returns a child context carrying a fresh attribution slot,
// plus the slot itself. Attach it to the request before it enters the
// transport; after the request completes, call Record with the outcome.
func WithAttribution(ctx context.Context) (context.Context, *Attribution) {
	a := &Attribution{}
	return context.WithValue(ctx, attributionKey{}, a), a
}

// Record feeds a completed request's outcome into the selected proxy's
// circuit breaker. Nil-safe on both the receiver (pool disabled — no slot
// was created) and the slot's proxy (the transport fell back to direct).
//
// A context.Canceled error is deliberately NOT charged to the proxy: it
// means OUR client went away mid-request, which says nothing about the
// parent's health — charging it would let a flaky client population trip
// breakers on a healthy chain. Timeouts (context.DeadlineExceeded) DO count:
// a parent that cannot complete requests within the client budget is failing
// for our purposes; misattribution of a slow origin is bounded by the
// consecutive-failure threshold and healed by the half-open probe.
func (a *Attribution) Record(err error) {
	if a == nil {
		return
	}
	up := a.proxy.Load()
	if up == nil {
		return
	}
	switch {
	case err == nil:
		up.CB.RecordSuccess()
	case errors.Is(err, context.Canceled):
		// client abort — not evidence about the parent proxy
	default:
		if up.CB.RecordFailure() {
			threshold, timeout := up.CB.Params()
			obs.Printf("Upstream: circuit OPEN for %s after %d consecutive request failures (retry in %s; last error: %v)",
				up.URL.Redacted(), threshold, timeout, err)
		}
	}
}

// healthCheckURL is the probe target: a stable, minimal, plain-HTTP endpoint
// reachable THROUGH the parent proxy under test.
const healthCheckURL = "http://detectportal.firefox.com/success.txt"

// ProbeTransport is a TEST-ONLY seam: when non-nil it supplies the
// round-tripper the health probe uses for a given parent proxy, so a test
// can inject a deterministic probe outcome (a 407, a dial error carrying a
// secret, a timeout) without a network. Production leaves it nil.
var ProbeTransport func(proxyURL *url.URL) http.RoundTripper

// FallbackAlertHook is a TEST-ONLY seam: when non-nil it receives the
// direct-fallback transition instead of the asynchronous production alert,
// so a test can count transitions deterministically. Production leaves it nil.
var FallbackAlertHook func(detail string)

func probeTransportFor(proxyURL *url.URL) http.RoundTripper {
	if h := ProbeTransport; h != nil {
		return h(proxyURL)
	}
	return &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		DisableKeepAlives: true,
	}
}

// HealthCheck runs a connectivity check against each upstream proxy.
// Called periodically from a background goroutine.
func (p *Pool) HealthCheck() {
	p.mu.RLock()
	proxies := p.proxies
	p.mu.RUnlock()

	for _, up := range proxies {
		client := &http.Client{
			Timeout:   5 * time.Second,
			Transport: probeTransportFor(up.URL),
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
			// CHAOS-24: contain the ROUND. This loop is what closes a tripped
			// breaker, so if it dies the pool can never recover a parent proxy
			// and egress stays on the direct fail-open path indefinitely.
			obs.SafeCall("upstream_health", pool.HealthCheck)
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
