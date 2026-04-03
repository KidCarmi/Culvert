package main

// upstream.go — Upstream proxy chaining with failover and circuit breaker.
//
// Culvert can route traffic through one or more parent HTTP proxies with
// automatic failover and circuit-breaker protection. When all upstreams are
// down the proxy falls back to direct connections.
//
// Configuration (config.yaml):
//
//   upstream:
//     proxies:
//       - url: "http://parent1.corp.com:3128"
//       - url: "http://parent2.corp.com:3128"
//     health_interval: "30s"
//     circuit_breaker:
//       threshold: 5      # failures before opening circuit
//       timeout: "60s"    # how long circuit stays open before half-open probe

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
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

// UpstreamProxy represents one parent proxy in the chain.
type UpstreamProxy struct {
	URL     *url.URL
	Healthy atomic.Bool
	CB      *CircuitBreaker
}

// UpstreamPool manages a set of parent proxies with failover.
type UpstreamPool struct {
	mu      sync.RWMutex
	proxies []*UpstreamProxy
	idx     atomic.Int64 // round-robin counter
}

var upstreamPool = &UpstreamPool{}

// Configure sets the list of upstream proxies from config.
func (p *UpstreamPool) Configure(entries []UpstreamEntry, cbThreshold int, cbTimeout time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proxies = nil
	for _, e := range entries {
		u, err := url.Parse(e.URL)
		if err != nil {
			logger.Printf("Upstream: invalid URL %q: %v", sanitizeLog(e.URL), err)
			continue
		}
		up := &UpstreamProxy{
			URL: u,
			CB:  newCircuitBreaker(cbThreshold, cbTimeout),
		}
		up.Healthy.Store(true)
		p.proxies = append(p.proxies, up)
		logger.Printf("Upstream: added parent proxy %s", u.Redacted())
	}
}

// Enabled returns true if any upstream proxies are configured.
func (p *UpstreamPool) Enabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies) > 0
}

// Next returns the next healthy upstream proxy using round-robin selection.
// Returns nil if no healthy proxy is available (caller should fall back to direct).
func (p *UpstreamPool) Next() *UpstreamProxy {
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
func (p *UpstreamPool) List() []UpstreamStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]UpstreamStatus, len(p.proxies))
	for i, up := range p.proxies {
		out[i] = UpstreamStatus{
			URL:     up.URL.Redacted(),
			Healthy: up.Healthy.Load(),
			Circuit: up.CB.State(),
		}
	}
	return out
}

// ProxyFunc returns an http.Transport-compatible proxy selector.
// When upstreams are configured, it returns the next healthy proxy URL.
// Falls back to nil (direct connection) when no upstream is available.
func (p *UpstreamPool) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(_ *http.Request) (*url.URL, error) {
		if up := p.Next(); up != nil {
			return up.URL, nil
		}
		return nil, nil // direct connection
	}
}

// HealthCheck runs a connectivity check against each upstream proxy.
// Called periodically from a background goroutine.
func (p *UpstreamPool) HealthCheck() {
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
		req, err := http.NewRequestWithContext(
			ctx, http.MethodHead, "http://detectportal.firefox.com/success.txt", nil,
		)
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
				logger.Printf("Upstream: %s marked unhealthy: %v", up.URL.Redacted(), err)
			}
			continue
		}
		resp.Body.Close()
		was := up.Healthy.Swap(true)
		if !was {
			logger.Printf("Upstream: %s recovered (healthy)", up.URL.Redacted())
		}
	}
}

// ─── Config types ────────────────────────────────────────────────────────────

// UpstreamEntry is one parent proxy from config.yaml.
type UpstreamEntry struct {
	URL string `yaml:"url" json:"url"`
}

// UpstreamConfig is the "upstream" section of config.yaml.
type UpstreamConfig struct {
	Proxies        []UpstreamEntry `yaml:"proxies" json:"proxies"`
	HealthInterval string          `yaml:"health_interval" json:"healthInterval"` // Go duration
	CircuitBreaker struct {
		Threshold int    `yaml:"threshold" json:"threshold"` // failures before open
		Timeout   string `yaml:"timeout" json:"timeout"`     // Go duration
	} `yaml:"circuit_breaker" json:"circuitBreaker"`
}

// UpstreamStatus is returned by the admin API.
type UpstreamStatus struct {
	URL     string `json:"url"`
	Healthy bool   `json:"healthy"`
	Circuit string `json:"circuit"`
}

// formatUpstreamSummary returns a log-friendly summary like "2 proxies (parent1:3128, parent2:3128)".
func formatUpstreamSummary(entries []UpstreamEntry) string {
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
	return fmt.Sprintf("%d proxies (%s)", len(entries), joinStrings(hosts, ", "))
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += sep + s
	}
	return out
}
