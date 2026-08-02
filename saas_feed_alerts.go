package main

// saas_feed_alerts.go — F3b-4: latched operational alerts for the signed SaaS feed.
//
// Mirrors the release-catalog latched-alert pattern (release_alerts.go): each alert fires
// ONCE per threshold crossing, guarded by a status mutex, computed under the lock and
// fired AFTER the unlock (no dispatch under a mutex). Latches reset on restart (a restart
// re-fires a still-active condition once — accepted + documented). The emission seam is a
// package var so tests swap in a recorder, and it routes through deferStartupAlert so an
// alert raised before the webhook store loads is queued, not dropped.

import "sync"

// saasFeedRefreshFailingThreshold is the consecutive-failure count that trips the
// refresh-failing alert (matches the release-catalog convention).
const saasFeedRefreshFailingThreshold = 3

// saasFeedAlertFire is the emission seam (tests swap in a recorder).
var saasFeedAlertFire = deferStartupAlert

// saasFeedAlertLatch holds the once-per-crossing latches, guarded by mu.
type saasFeedAlertLatch struct {
	mu               sync.Mutex
	refreshFailing   bool
	stale            bool
	critical         bool
	waitingAuthority bool
}

var globalSaaSFeedAlerts saasFeedAlertLatch

// evaluateSaaSFeedAlerts folds a status snapshot into the latched alerts. Called after
// every refresh attempt AND after startup recovery. It computes the events to fire under
// the lock, then fires them after releasing it.
func evaluateSaaSFeedAlerts(snap saasFeedStatusSnapshot) {
	events := func() []AlertPayload {
		globalSaaSFeedAlerts.mu.Lock()
		defer globalSaaSFeedAlerts.mu.Unlock()
		var out []AlertPayload
		out = append(out, globalSaaSFeedAlerts.evalRefreshLocked(snap)...)
		out = append(out, globalSaaSFeedAlerts.evalStaleLocked(snap)...)
		out = append(out, globalSaaSFeedAlerts.evalCriticalLocked(snap)...)
		out = append(out, globalSaaSFeedAlerts.evalWaitingLocked(snap)...)
		return out
	}()
	for _, p := range events {
		saasFeedAlertFire(p.Event, p)
	}
}

// evaluateSaaSFeedStartupAlerts is the boot-time evaluation (an already-stale/critical/
// waiting appliance alerts immediately, not after the first refresh interval).
func evaluateSaaSFeedStartupAlerts(snap saasFeedStatusSnapshot) { evaluateSaaSFeedAlerts(snap) }

func (l *saasFeedAlertLatch) evalRefreshLocked(snap saasFeedStatusSnapshot) []AlertPayload {
	if snap.ConsecutiveFailures >= saasFeedRefreshFailingThreshold {
		if l.refreshFailing {
			return nil
		}
		l.refreshFailing = true
		return []AlertPayload{{
			Event: "saas_feed_refresh_failing", Host: saasFeedOfficialHost, Source: "saasfeed",
			Detail: "signed SaaS feed refresh failing (" + snap.LastErrorClass + "); serving last-known-good",
		}}
	}
	if snap.ConsecutiveFailures == 0 && l.refreshFailing {
		l.refreshFailing = false
		return []AlertPayload{{
			Event: "saas_feed_recovered", Host: saasFeedOfficialHost, Source: "saasfeed",
			Detail: "signed SaaS feed refresh recovered",
		}}
	}
	return nil
}

func (l *saasFeedAlertLatch) evalStaleLocked(snap saasFeedStatusSnapshot) []AlertPayload {
	stale := snap.Stale && snap.ActiveFeedVersion > 0
	if stale {
		if l.stale {
			return nil
		}
		l.stale = true
		return []AlertPayload{{
			Event: "saas_feed_stale", Host: saasFeedOfficialHost, Source: "saasfeed",
			Detail: "signed SaaS feed serving an expired last-known-good snapshot (never fail-closed on age)",
		}}
	}
	l.stale = false
	return nil
}

func (l *saasFeedAlertLatch) evalCriticalLocked(snap saasFeedStatusSnapshot) []AlertPayload {
	if snap.Critical {
		if l.critical {
			return nil
		}
		l.critical = true
		return []AlertPayload{{
			Event: "saas_feed_recovery_degraded", Host: saasFeedOfficialHost, Source: "saasfeed",
			Detail: "signed SaaS feed degraded to a critical state (" + snap.CriticalReason + "); operator action required",
		}}
	}
	if l.critical {
		l.critical = false
		return []AlertPayload{{
			Event: "saas_feed_recovered", Host: saasFeedOfficialHost, Source: "saasfeed",
			Detail: "signed SaaS feed recovered from a degraded state",
		}}
	}
	return nil
}

func (l *saasFeedAlertLatch) evalWaitingLocked(snap saasFeedStatusSnapshot) []AlertPayload {
	if snap.WaitingForAuthority {
		if l.waitingAuthority {
			return nil
		}
		l.waitingAuthority = true
		return []AlertPayload{{
			Event: "saas_feed_missing_authority", Host: saasFeedOfficialHost, Source: "saasfeed",
			Detail: "managed data plane has no valid authoritative SaaS feed configuration; awaiting a control-plane snapshot",
		}}
	}
	l.waitingAuthority = false
	return nil
}
