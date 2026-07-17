package main

// autoexclude_surge.go — abnormal learning-rate detection (F4). The per-promotion
// audit + alert (recordAutoExclude) is the wrong granularity for spotting a
// POISONING CAMPAIGN: 50 promotions produce 50 individual alerts, none flagged as
// anomalous, and the aggregate signal drowns. This adds a latched, fire-once
// surge alert on the RATE of promotions, mirroring the release-catalog
// threshold-latch precedent (release_alerts.go): it fires once when a window
// accumulates >= threshold promotions and re-arms on the next window, so a
// sustained flood produces a steady one-alert-per-window heartbeat rather than
// either silence or spam.
//
// Detection is deliberately node-local and volatile, exactly like the cache it
// watches. Thresholds are compile-time constants for now (recorded deferral —
// they become per-deployment tunables under the F10 GUI-parity work, alongside
// confirmN/TTL); they are intentionally conservative so a legitimate staged
// rollout does not false-fire while a deliberate campaign does.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// surgeWindow is the fixed rate window. A poisoning campaign concentrates
	// promotions in time; a legitimate rollout spreads them out.
	surgeWindow = 5 * time.Minute
	// surgeThreshold is the promotions-per-window count that trips the alert.
	// Each promotion is itself confirm-count-gated (>=2 distinct clients), so a
	// sustained 4/min of DISTINCT hosts going dark is already well outside a
	// normal staged rollout and worth a single loud aggregate alert.
	surgeThreshold = 20
)

// autoExcludeSurgeDetector is a fixed-window latched rate gate over promotion
// events. Zero value is not ready; use the package singleton or newSurgeDetector.
type autoExcludeSurgeDetector struct {
	mu          sync.Mutex
	windowStart time.Time
	count       int
	latched     bool // fired for the current window already
	now         func() time.Time
}

func newSurgeDetector(now func() time.Time) *autoExcludeSurgeDetector {
	if now == nil {
		now = time.Now
	}
	return &autoExcludeSurgeDetector{now: now}
}

// autoExcludeSurge is the process-wide promotion-rate detector. Volatile and
// node-local (like the cache). Tests swap it via swapAutoExcludeSurge.
var autoExcludeSurge = newSurgeDetector(time.Now)

// observePromotion records one promotion and reports whether THIS promotion
// tripped the surge threshold (the caller fires the aggregate audit + alert +
// metric on a true return). It fires at most once per window; the next window
// re-arms. count is the promotions-in-window tally at this event (for the alert
// detail). O(1), bounded memory (a counter, not an event log).
func (d *autoExcludeSurgeDetector) observePromotion() (fire bool, count int) {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.windowStart.IsZero() || now.Sub(d.windowStart) >= surgeWindow {
		// Roll into a fresh window (also re-arms the latch).
		d.windowStart = now
		d.count = 0
		d.latched = false
	}
	d.count++
	if !d.latched && d.count >= surgeThreshold {
		d.latched = true
		return true, d.count
	}
	return false, d.count
}

// autoExcludeSurgeCounter counts surge ALERTS fired (once per window crossing),
// exposed as culvert_decrypt_autoexclude_surge_total (metrics.go). A non-zero,
// rising value is the SOC's poisoning-campaign indicator.
var autoExcludeSurgeCounter int64

// maybeFireAutoExcludeSurge is called on every promotion (from recordAutoExclude).
// On a threshold crossing it emits the aggregate surge observability triple.
func maybeFireAutoExcludeSurge(scopeName string) {
	fire, count := autoExcludeSurge.observePromotion()
	if !fire {
		return
	}
	atomic.AddInt64(&autoExcludeSurgeCounter, 1)
	safeScope := auditSafe(scopeName)
	logger.Printf("SSL_AUTOEXCLUDE_SURGE %d exclusions learned within %s (last scope=%q) — possible decryption-exclusion poisoning; review the Decryption Exclusions panel",
		count, surgeWindow, sanitizeLog(safeScope))
	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  "system",
		Action: "decryption.autoexclude.surge",
		Object: fmt.Sprintf("%d-in-%s", count, surgeWindow),
		Detail: fmt.Sprintf("abnormal learning rate: %d SSL-inspection exclusions promoted within %s — investigate for cache poisoning", count, surgeWindow),
	})
	go fireAlert("decryption_autoexclude_surge", AlertPayload{
		Detail: fmt.Sprintf("Abnormal decryption-exclusion learning rate: %d hosts auto-excluded within %s — possible poisoning campaign", count, surgeWindow),
		Source: "proxy",
	})
}
