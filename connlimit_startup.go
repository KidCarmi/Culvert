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
//   - 5-minute security-limiter cleanup goroutine spawned UNCONDITIONALLY
//     (the login-lockout + admin-API limiters are always active and must be
//     swept even when RateLimitRPM is 0; see loadConnAndRateLimit)
//   - cleanup goroutine ticks rl.Cleanup() + ssrf.CacheCleanup() +
//     loginLimiter.Cleanup() + apiLimiter.Cleanup() +
//     enrollRateLimitCleanup()
//   - log strings unchanged so operators see the same startup banner
//   - Loader returns the cleanup-goroutine cancel func (always non-nil now)
//     so the caller can store it on s.rlCleanupCancel. The early-phase
//     `rate-limit-cleanup-cancel` shutdown hook (main.go) nil-checks before
//     calling, so a non-nil value is safe.

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

	if cfg.RateLimitRPM > 0 {
		rl.Configure(cfg.RateLimitRPM, time.Minute)
		logger.Printf("RateLimit: %d req/min per IP", cfg.RateLimitRPM)
	}

	// The security-limiter cleanup janitor runs UNCONDITIONALLY. The IP rate
	// limiter (rl) is optional, but the login account-lockout and admin-API
	// rate limiters — both keyed by attacker-controllable input (username /
	// client IP) — are ALWAYS active, so their maps must be swept even when
	// RateLimitRPM is 0. rl.Cleanup on an unconfigured limiter is a harmless
	// empty-shard walk, and the SSRF DNS cache is always in use. Previously the
	// janitor spawned only when RateLimitRPM > 0, so with rate limiting off the
	// lockout/API maps grew without bound (memory-exhaustion DoS).
	rlCtx, cancel := context.WithCancel(parentCtx)
	go rateLimitCleanupLoop(rlCtx)
	return cancel
}

// rateLimitCleanupLoop runs the periodic security-limiter cleanup pass every
// 5 minutes until ctx is cancelled: the IP rate limiter, SSRF DNS cache, login
// account-lockout, admin-API rate limiter, and cluster-enrollment rate limiter.
// Extracted from the inline
// goroutine in the pre-extraction body so the loader stays flat (avoids the
// linter's nestif trigger) and so the cancellation invariant can be unit-tested
// directly without waiting on a real tick.
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
			loginLimiter.Cleanup()
			apiLimiter.Cleanup()
			enrollRateLimitCleanup()
		}
	}
}
