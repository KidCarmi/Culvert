package main

// connlimit_startup.go — startup-time loader for the
// connection-limit + IP-filter + rate-limit slice (P4.2 / S1).
// Mirrors the pre-extraction body of initConnAndRateLimit
// (main.go:696–735) byte-for-byte except parameterized.
//
// Behaviour invariants preserved:
//   - connLimiter.Enable only when MaxConnsPerIP > 0 (no Enable call
//     otherwise — connLimiter starts disabled by default)
//   - ipf.SetMode + ipf.Add only when IPMode != "" ; invalid IP-list
//     entries are logged at warn level and skipped (NOT fatal)
//   - rl.Configure(N, time.Minute) only when RateLimitRPM > 0
//   - 5-minute cleanup goroutine spawned ONLY when RateLimitRPM > 0
//   - cleanup goroutine ticks rl.Cleanup() + ssrf.CacheCleanup()
//   - log strings unchanged so operators see the same startup banner
//   - Loader returns the cleanup-goroutine cancel func so the caller
//     can store it on s.rlCleanupCancel. Returns nil when rate-limit
//     is disabled — the early-phase `rate-limit-cleanup-cancel`
//     shutdown hook (main.go:1428–1430) nil-checks before calling.

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// loadConnAndRateLimit applies cfg to the package-global connLimiter,
// ipf, and rl, and (when cfg.RateLimitRPM > 0) spawns the 5-minute
// rate-limit + DNS cache cleanup goroutine. Returns the goroutine's
// cancel func so the caller can store it on startupState; returns
// nil if no goroutine was spawned.
//
// parentCtx parents the cleanup goroutine. Production passes
// appLifecycleCtx so the existing early-phase `app-lifecycle-cancel`
// shutdown hook (order 40) also stops it; tests pass per-test
// cancellable ctx.
func loadConnAndRateLimit(cfg connAndRateLimitStartupConfig, parentCtx context.Context) context.CancelFunc {
	if cfg.MaxConnsPerIP > 0 {
		connLimiter.Enable(cfg.MaxConnsPerIP)
		logger.Printf("ConnLimit: max %d connections per IP", cfg.MaxConnsPerIP)
	}

	if cfg.IPMode != "" {
		ipf.SetMode(cfg.IPMode)
		for _, entry := range cfg.IPList {
			if err := ipf.Add(entry); err != nil {
				logger.Printf("IP filter: invalid entry %q: %v", entry, err)
			}
		}
		logger.Printf("IPFilter: mode=%s entries=%d", cfg.IPMode, len(cfg.IPList))
	}

	if cfg.RateLimitRPM <= 0 {
		return nil
	}
	rl.Configure(cfg.RateLimitRPM, time.Minute)
	logger.Printf("RateLimit: %d req/min per IP", cfg.RateLimitRPM)
	rlCtx, cancel := context.WithCancel(parentCtx)
	go rateLimitCleanupLoop(rlCtx)
	return cancel
}

// rateLimitCleanupLoop runs the periodic rl + SSRF DNS-cache cleanup
// pass every 5 minutes until ctx is cancelled. Extracted from the
// inline goroutine in the pre-extraction body so the loader stays
// flat (avoids the linter's nestif trigger) and so the cancellation
// invariant can be unit-tested directly without waiting on a real
// tick.
func rateLimitCleanupLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rl.Cleanup()
			ssrf.CacheCleanup()
		}
	}
}
