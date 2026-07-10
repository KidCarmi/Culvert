package main

// Release-catalog detection / canary / alerting (M1-3, design §3 Slice C).
//
// Operators learn about catalog problems from alerts, not outages. Three alert
// events ride the existing fireAlert seam:
//
//   release_catalog_stale           — the INSTALLED catalog's expires_at is
//                                     within releaseCatalogStaleThreshold (30d)
//                                     of now: the 180-day freshness watchdog.
//                                     The backstop for a silently-failing weekly
//                                     re-sign (M1-4) — fires with ~5 weekly
//                                     retries left before the catalog lapses.
//   release_catalog_refresh_failing — releaseRefreshFailingThreshold (3)
//                                     CONSECUTIVE refresh failures.
//   release_catalog_recovered       — the first refresh success after a
//                                     refresh_failing alert.
//
// RT-H2 (§10): each alert fires ONCE PER THRESHOLD CROSSING, not per evaluation
// — the engine's 30s dedup would otherwise re-fire stale every 6h tick for a
// month. Latches live on releaseManager under statusMu (no new stores); they
// reset on restart, so a restart re-fires an still-active alert once (accepted
// + documented — an operator restarting a stale appliance gets one reminder,
// not silence). Thresholds are constants for M1 (recorded deferral: no
// env/GUI knob until a deployment needs one — not a config option, so the
// GUI-parity rule does not apply).
//
// Alerts fire through releaseAlertFire (test seam). The default is
// deferStartupAlert: before loadPersistentAdminState flushes the queue it
// buffers (webhooks are not loaded yet at release-wiring time), after the
// flush it degrades to a plain fireAlert passthrough; Dispatch itself is
// always non-blocking, so calling it under a caller's goroutine is safe.
//
// Prometheus (RT-L1, hand-written per the metrics.go pattern):
//   culvert_release_catalog_refresh_total{result="success"|"failure"}
//   culvert_release_catalog_expires_in_seconds (scrape-time, from the holder)

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// releaseCatalogStaleThreshold: fire release_catalog_stale when the
	// installed catalog expires within this window (design §3: default 30d).
	releaseCatalogStaleThreshold = 30 * 24 * time.Hour
	// releaseRefreshFailingThreshold: fire release_catalog_refresh_failing on
	// the Nth CONSECUTIVE refresh failure (design §3: default 3).
	releaseRefreshFailingThreshold = 3
)

// releaseAlertFire is the alert-emission seam (tests swap in a recorder).
// deferStartupAlert queues until the webhook store is loaded, then passes
// through to fireAlert; Dispatch is non-blocking either way.
var releaseAlertFire = deferStartupAlert

// Refresh-outcome counters for culvert_release_catalog_refresh_total.
// Process-lifetime, not persisted (refresh cadence makes restarts visible
// anyway; the catalog state itself is the durable record).
var (
	statReleaseRefreshSuccess int64
	statReleaseRefreshFailure int64
)

// evaluateRefreshTransitions computes the failing/recovered latch transitions
// for one refresh outcome. MUST be called with rm.statusMu held (it reads the
// just-folded ConsecutiveFailures and mutates the latch); it returns the
// events to fire so the caller can emit them AFTER releasing the lock.
func (rm *releaseManager) evaluateRefreshTransitions(err error) []AlertPayload {
	var out []AlertPayload
	if err != nil {
		if rm.refreshStatus.ConsecutiveFailures >= releaseRefreshFailingThreshold && !rm.refreshFailingLatched {
			rm.refreshFailingLatched = true
			out = append(out, AlertPayload{
				Event: "release_catalog_refresh_failing",
				Host:  rm.catalogOrigin,
				Detail: fmt.Sprintf("%d consecutive release-catalog refresh failures (last: %s)",
					rm.refreshStatus.ConsecutiveFailures, rm.refreshStatus.LastErr),
				Source: "release",
			})
		}
		return out
	}
	// Success: recovered pairs with a fired refresh_failing — a single blip
	// failure→success below the threshold stays silent (RT-H2: transitions
	// only, no per-evaluation noise).
	if rm.refreshFailingLatched {
		rm.refreshFailingLatched = false
		out = append(out, AlertPayload{
			Event:  "release_catalog_recovered",
			Host:   rm.catalogOrigin,
			Detail: "release-catalog refresh succeeded after repeated failures",
			Source: "release",
		})
	}
	return out
}

// evalStale computes the stale-latch transition for one freshness evaluation
// against the given expiry. Pure over (expiresAt, now) so the RT-H2 latch is
// unit-testable without a fake clock plumbed through the manager. MUST be
// called with rm.statusMu held; returns the events to fire after unlock.
//
//   - stale (expires within threshold, incl. already expired) + not latched
//     ⇒ latch + fire once. Further stale evaluations are silent.
//   - fresh ⇒ re-arm the latch (crossing back re-enables the next crossing).
func (rm *releaseManager) evalStale(expiresAt, now time.Time) []AlertPayload {
	remaining := expiresAt.Sub(now)
	if remaining >= releaseCatalogStaleThreshold {
		rm.staleLatched = false
		return nil
	}
	if rm.staleLatched {
		return nil
	}
	rm.staleLatched = true
	return []AlertPayload{{
		Event: "release_catalog_stale",
		Host:  rm.catalogOrigin,
		Detail: fmt.Sprintf("release catalog expires %s (%.1f days remaining; threshold %.0f days) — re-sign pipeline may be failing",
			expiresAt.UTC().Format(time.RFC3339), remaining.Hours()/24, releaseCatalogStaleThreshold.Hours()/24),
		Source: "release",
	}}
}

// evaluateCatalogFreshness runs one stale evaluation against the currently
// INSTALLED catalog (the holder-published one — a failed refresh leaves it in
// place, which is exactly the catalog whose expiry matters). No catalog ⇒ no
// evaluation and the latch is left untouched (reads degrade to
// available:false; staleness of nothing is meaningless). Called from
// runRefresh (every loop tick — incl. 304 no-ops — and every manual refresh)
// and once at startup wiring.
func (rm *releaseManager) evaluateCatalogFreshness() {
	if rm.svc == nil {
		return
	}
	cat := rm.svc.catalog()
	if cat == nil {
		return
	}
	exp := cat.ExpiresAt()
	if exp.IsZero() {
		// Permissive/legacy catalogs may carry no expiry — nothing to watch.
		return
	}
	rm.statusMu.Lock()
	events := rm.evalStale(exp, time.Now())
	rm.statusMu.Unlock()
	for _, p := range events {
		releaseAlertFire(p.Event, p)
	}
}

// releaseCatalogWritePrometheus appends the M1-3 release-catalog metrics
// (called from handleMetrics). The expiry gauge is computed at scrape time
// from the installed catalog and omitted when no catalog (or no expiry) is
// published — an absent series is a clearer "nothing installed" signal than a
// fake zero (which Prometheus would read as "expired").
func releaseCatalogWritePrometheus(w *strings.Builder) {
	w.WriteString("\n# HELP culvert_release_catalog_refresh_total Release-catalog refresh outcomes (startup, loop, and manual)\n")
	w.WriteString("# TYPE culvert_release_catalog_refresh_total counter\n")
	fmt.Fprintf(w, "culvert_release_catalog_refresh_total{result=\"success\"} %d\n", atomic.LoadInt64(&statReleaseRefreshSuccess))
	fmt.Fprintf(w, "culvert_release_catalog_refresh_total{result=\"failure\"} %d\n", atomic.LoadInt64(&statReleaseRefreshFailure))

	rm := currentReleaseManager()
	if rm == nil || rm.svc == nil {
		return
	}
	cat := rm.svc.catalog()
	if cat == nil {
		return
	}
	if exp := cat.ExpiresAt(); !exp.IsZero() {
		w.WriteString("\n# HELP culvert_release_catalog_expires_in_seconds Seconds until the installed release catalog expires (negative = already expired)\n")
		w.WriteString("# TYPE culvert_release_catalog_expires_in_seconds gauge\n")
		fmt.Fprintf(w, "culvert_release_catalog_expires_in_seconds %.0f\n", time.Until(exp).Seconds())
	}
}
