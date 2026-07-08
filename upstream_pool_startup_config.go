package main

// upstream_pool_startup_config.go — resolved config for the upstream-pool
// slice. Pure DTO + a single side-effect-free resolver invoked from the
// initUpstreamPool shim. No globals are read or written here (slice
// convention pinned by startup_slice_contract_test.go).

import "time"

// upstreamPoolDefaultCBTimeout is the circuit-breaker open→half-open timeout
// applied when the config omits or mis-specifies one.
const upstreamPoolDefaultCBTimeout = 60 * time.Second

// upstreamPoolStartupConfig carries the resolved upstream-chaining inputs.
// The loader consumes this struct and owns the pool configuration, the
// transport rewire (applyUpstreamProxy), and the health-check goroutine.
type upstreamPoolStartupConfig struct {
	// Proxies are the parent proxies from config.yaml (may be empty —
	// direct egress).
	Proxies []UpstreamEntry

	// CBThreshold / CBTimeout parameterise each proxy's circuit breaker.
	// Timeout: "" / unparseable inputs collapse to upstreamPoolDefaultCBTimeout.
	CBThreshold int
	CBTimeout   time.Duration

	// HealthInterval is the round-robin health-check cadence. Zero when the
	// config omits it or supplies an unparseable / non-positive duration —
	// the loader then skips the health-check goroutine entirely.
	HealthInterval time.Duration
}

// resolveUpstreamPoolStartupConfig is the single startup-time reader of
// fc.Upstream. Pure and deterministic; safe on a zero-value *FileConfig.
func resolveUpstreamPoolStartupConfig(fc *FileConfig) upstreamPoolStartupConfig {
	cbTimeout := upstreamPoolDefaultCBTimeout
	if fc.Upstream.CircuitBreaker.Timeout != "" {
		if d, err := time.ParseDuration(fc.Upstream.CircuitBreaker.Timeout); err == nil {
			cbTimeout = d
		}
	}
	var health time.Duration
	if hi := fc.Upstream.HealthInterval; hi != "" {
		if d, err := time.ParseDuration(hi); err == nil && d > 0 {
			health = d
		}
	}
	return upstreamPoolStartupConfig{
		Proxies:        fc.Upstream.Proxies,
		CBThreshold:    fc.Upstream.CircuitBreaker.Threshold,
		CBTimeout:      cbTimeout,
		HealthInterval: health,
	}
}
