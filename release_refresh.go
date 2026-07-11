package main

// Production HTTP catalog refresh (M1-2, design v2 §2/§9).
//
// A background loop that periodically re-runs the SAME verified refresh seam the
// manual admin endpoint uses (rm.runRefresh → rm.refresh → auto-seed + reload),
// so appliances converge on newly published or re-signed catalogs without a
// restart. The loop adds NO trust logic of its own: verification, freshness, the
// rollback floor, and fail-closed behavior all live in the auto-seed path it
// calls; a failed tick leaves the current catalog untouched.
//
// Started from loadReleaseManagement (after the manager, its refresh seam, and
// the alert webhooks exist — RT-M1) on the app lifecycle context, and ONLY when a
// catalog origin is configured in enforce mode (RT-L2). The first tick fires
// after one full jittered interval: startup auto-seed already covers t=0.

import (
	"context"
	"math/rand"
	"time"
)

// refreshJitterFrac spreads ticks ±10% so a fleet sharing a start time does not
// synchronize its origin fetches.
const refreshJitterFrac = 0.10

// jitteredInterval returns base ±refreshJitterFrac, re-randomized per call.
func jitteredInterval(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	span := float64(base) * refreshJitterFrac
	off := (rand.Float64()*2 - 1) * span // #nosec G404 -- jitter, not crypto
	return base + time.Duration(off)
}

// runCatalogRefreshLoop ticks every jittered interval until ctx is cancelled,
// invoking the shared refresh wrapper. getRM is resolved PER TICK (the manager
// pointer is a startup singleton, but resolving late tolerates rm == nil and
// keeps the loop testable). Failures are logged (redacted upstream) and counted
// in the shared refreshStatus; alerting on transitions is M1-3.
func runCatalogRefreshLoop(ctx context.Context, interval time.Duration, getRM func() *releaseManager) {
	if interval <= 0 {
		return
	}
	timer := time.NewTimer(jitteredInterval(interval))
	defer timer.Stop()
	// Each tick body is recover-guarded (refreshLoopTick): this loop is the
	// SOLE runtime driver of both catalog refresh and the M1-3 freshness
	// watchdog (evaluateCatalogFreshness runs inside runRefresh), so a panic
	// anywhere in the fetch/verify/reload path must cost one tick, not kill
	// refresh + stale-alerting for the rest of the process lifetime
	// (CHAOS-R1, 2026-07-10 review). Every lock on the runRefresh path
	// (refreshRunMu, and the statusMu sections in recordRefreshOutcome /
	// evaluateCatalogFreshness) releases via defer, so recovery here cannot
	// strand a mutex.
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		refreshLoopTick(ctx, getRM)
		timer.Reset(jitteredInterval(interval))
	}
}

// refreshLoopTick runs ONE refresh attempt with panic containment. A recovered
// panic is logged and counted as nothing more than a missed tick — the existing
// catalog is untouched (the auto-seed path only swaps on full success) and the
// next tick runs normally.
func refreshLoopTick(ctx context.Context, getRM func() *releaseManager) {
	defer func() {
		if r := recover(); r != nil {
			if logger != nil {
				logger.Printf("release catalog: periodic refresh tick panicked (recovered, loop continues): %v", r)
			}
		}
	}()
	if rm := getRM(); rm != nil && rm.refresh != nil {
		if err := rm.runRefresh(ctx, "loop"); err != nil {
			if logger != nil {
				logger.Printf("release catalog: periodic refresh failed (existing catalog untouched): %s", sanitizeLog(err.Error()))
			}
		}
	}
}
