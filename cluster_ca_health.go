package main

// cluster_ca_health.go — cluster-CA usability health plane (CHAOS-29, register
// row CA-13).
//
// Register row CA-13 recorded the shape of this gap exactly: "cluster CA
// rotation mirrors CA-2: every failure branch logs-and-returns with no alert or
// metric." Auto-rotation is the ONLY automatic recovery the cluster CA has, it
// runs on a 24-hour tick, and the window it operates in is 30 days wide. A
// rotation that fails every tick — a read-only CA directory, a full volume, a
// KEK that no longer decrypts — therefore had thirty chances to fail silently
// and then took the whole cluster's mTLS trust with it. The one signal was a
// log line among the day's other log lines, plus a `lastRotationError` field on
// an admin API nobody reads while things look fine.
//
// This file is the sink. It mirrors ca_health.go, which mirrors
// storage_health.go, because the failure shape is the same in all three (an
// external condition that fires from arbitrary goroutines at arbitrary rates,
// for as long as the condition lasts):
//
//   - count every event, so magnitude is never lost to rate limiting;
//   - rate-limit the LOG and the ALERT on independent gates;
//   - never spawn a delivery goroutine when nothing subscribes to the event;
//   - report recovery on EVIDENCE, never on elapsed time.
//
// It departs from those files in one place, deliberately. They carry a
// "degraded until a success is OBSERVED" latch for the FAULT itself, because
// there is no way to ask a disk whether it is healthy without writing to it —
// silence is genuinely ambiguous there. Cluster-CA usability is not: it is a
// free, exact, side-effect-free comparison against the loaded certificate
// (Usable()), so the live predicate IS the current state and a latch mirroring
// it would be a second source of truth that can only drift. The latch is kept
// for exactly the state that CANNOT be re-derived — whether the last rotation
// attempt produced a persisted replacement — because nothing in the process can
// answer that by looking.

import (
	"fmt"
	"sync"
	"time"
)

// clusterCAUnusableAlertInterval rate-limits the log line and the alert emitted
// for an unusable cluster CA.
//
// The rate that has to be survived here is a reconnect storm, not steady state:
// enrollment and renewal are rare on a healthy cluster, but a fleet that has
// just lost mTLS trust retries — every DP renewal loop wakes on its own timer
// and every one of them fails. The counters carry the magnitude; one signal per
// interval carries the page.
const clusterCAUnusableAlertInterval = 5 * time.Minute

// clusterCAHealth is the process-wide record of cluster-CA faults.
type clusterCAHealth struct {
	mu sync.Mutex

	// refusals is every CSR signing the CA refused because it was outside its
	// own validity window. Unlike the inspection CA there is no second
	// "dispatcher blocked it first" counter: SignCSR is the single chokepoint
	// for both enrollment (controlplane_server.go Enroll) and renewal
	// (RenewCert), so one counter covers the whole surface.
	refusals   int64
	last       time.Time
	lastReason string

	// rotationFailures counts auto-rotation attempts that did not produce a
	// persisted replacement CA. CUMULATIVE — the right shape for a Prometheus
	// counter and the wrong shape for a status row, so the current state is
	// tracked separately by lastRotFail/lastRotOK. An operator who fixes the
	// volume and sees the next tick succeed must stop being told the rotation
	// is broken; a row keyed on the cumulative counter would keep contradicting
	// them until the process restarts.
	rotationFailures int64
	lastRotErr       string
	lastRotFail      time.Time
	lastRotOK        time.Time

	logAt   time.Time
	alertAt time.Time
}

var clusterCAUsability clusterCAHealth

// fireClusterCAAlert delivers a cert_expiry alert for the cluster CA. It is the
// SINGLE delivery point for both cluster-CA producers (unusable-CA refusals and
// rotation failures) — they differ only in the detail text, and funnelling them
// through one seam keeps the host/source/event triple in one place.
//
// Package-level seam so tests observe the transition synchronously instead of
// racing the process-global alerts sink. That is not a stylistic preference: a
// test that instead swaps globalAlertStore races the in-flight delivery
// goroutine this function spawns, which the race detector catches — the
// -count/-shuffle determinism class the CI gate exists for.
//
// Host is "culvert-cluster-ca", distinct from the inspection CA's "culvert-ca":
// the two failures have different blast radii and different runbooks, and an
// operator paged at 3am must be able to tell from the payload which CA died
// without opening the appliance.
var fireClusterCAAlert = func(detail string) {
	// Nobody subscribed → do nothing at all, and in particular do not spawn a
	// goroutine. Per the per-request alert-producer contract: this producer is
	// reached from the enrollment/renewal RPC path, which a reconnect storm
	// drives hard exactly when the fault is live.
	if !globalAlertStore.HasSubscriber("cert_expiry") {
		return
	}
	go fireAlert("cert_expiry", AlertPayload{
		Host:   "culvert-cluster-ca",
		Detail: detail,
		Source: "cluster-ca",
	})
}

// noteClusterCAUnusable records a CSR signing refused because the cluster CA is
// outside its validity window. Runs synchronously on the RPC's goroutine (and
// under the CA's read lock), so it does memory-only work and hands the alert off.
func noteClusterCAUnusable(reason string) {
	safe := sanitizeLog(reason)
	now := time.Now()

	clusterCAUsability.mu.Lock()
	clusterCAUsability.refusals++
	clusterCAUsability.last = now
	clusterCAUsability.lastReason = safe
	refusals := clusterCAUsability.refusals
	doLog := clusterCAUsability.logAt.IsZero() || now.Sub(clusterCAUsability.logAt) >= clusterCAUnusableAlertInterval
	if doLog {
		clusterCAUsability.logAt = now
	}
	doAlert := clusterCAUsability.alertAt.IsZero() || now.Sub(clusterCAUsability.alertAt) >= clusterCAUnusableAlertInterval
	if doAlert {
		clusterCAUsability.alertAt = now
	}
	clusterCAUsability.mu.Unlock()

	// logger may be nil: this is reachable before setupLogger in tests.
	if doLog && logger != nil {
		logger.Printf("ClusterCA: node enrollment and certificate renewal are BLOCKED — the cluster CA "+
			"cannot sign a certificate peers will accept: %q (%d signings refused since boot). "+
			"Rotate or import a replacement cluster CA; enrolled nodes will need to re-enroll.", safe, refusals)
	}
	if doAlert {
		fireClusterCAAlert(fmt.Sprintf(
			"Cluster CA is outside its validity window — node enrollment and cert renewal are BLOCKED: %s "+
				"(%d signings refused since boot)", safe, refusals))
	}
}

// noteClusterCARotationFailure records an auto-rotation attempt that produced no
// persisted replacement CA (register row CA-13).
//
// Always logged and always alerted, with no rate gate: RotateIfNeeded runs at
// most once per rotation check (a 24h cadence), so this is bounded by
// construction — the case the per-request alert-producer contract explicitly
// exempts. The HasSubscriber gate is still honoured because it costs nothing and
// keeps every producer in the codebase reading the same way.
func noteClusterCARotationFailure(reason string) {
	safe := sanitizeLog(reason)
	now := time.Now()
	clusterCAUsability.mu.Lock()
	clusterCAUsability.rotationFailures++
	clusterCAUsability.lastRotErr = safe
	clusterCAUsability.lastRotFail = now
	n := clusterCAUsability.rotationFailures
	clusterCAUsability.mu.Unlock()

	if logger != nil {
		logger.Printf("ClusterCA: auto-rotation FAILED (%d since boot): %q — the cluster CA is still "+
			"the expiring one; when it expires, every enrolled node loses mTLS trust and must re-enroll", n, safe)
	}
	fireClusterCAAlert(fmt.Sprintf(
		"Cluster CA auto-rotation failed (%d failures since boot): %s — "+
			"the CA is still the expiring one; at expiry every enrolled node loses mTLS trust", n, safe))
}

// noteClusterCARotated records an OBSERVED successful rotation or import. This
// is what clears the rotation warning — see clusterCARotationDegraded. The
// cumulative counter is deliberately NOT decremented: it feeds a Prometheus
// counter, which must never go backwards.
func noteClusterCARotated() {
	now := time.Now()
	clusterCAUsability.mu.Lock()
	clusterCAUsability.lastRotOK = now
	clusterCAUsability.mu.Unlock()
}

// clusterCAUsabilitySnapshot is a consistent read of the fault record.
// RotationFailures is CUMULATIVE (the counter); RotationDegraded is the CURRENT
// state (the status row) — see noteClusterCARotationFailure for why the two must
// not be conflated.
type clusterCAUsabilitySnapshot struct {
	Refusals         int64
	Last             time.Time
	Reason           string
	RotationFailures int64
	RotationErr      string
	RotationDegraded bool
}

func clusterCAUsabilityFailures() clusterCAUsabilitySnapshot {
	clusterCAUsability.mu.Lock()
	defer clusterCAUsability.mu.Unlock()
	return clusterCAUsabilitySnapshot{
		Refusals:         clusterCAUsability.refusals,
		Last:             clusterCAUsability.last,
		Reason:           clusterCAUsability.lastReason,
		RotationFailures: clusterCAUsability.rotationFailures,
		RotationErr:      clusterCAUsability.lastRotErr,
		RotationDegraded: !clusterCAUsability.lastRotFail.IsZero() &&
			!clusterCAUsability.lastRotOK.After(clusterCAUsability.lastRotFail),
	}
}

// clusterCARotationDegraded reports whether cluster-CA auto-rotation is CURRENTLY
// failing: an attempt has failed and no successful rotation has been observed
// since.
func clusterCARotationDegraded() bool {
	clusterCAUsability.mu.Lock()
	defer clusterCAUsability.mu.Unlock()
	if clusterCAUsability.lastRotFail.IsZero() {
		return false
	}
	return !clusterCAUsability.lastRotOK.After(clusterCAUsability.lastRotFail)
}

// resetClusterCAHealthForTest clears the record. Test-only helper kept beside
// the state it resets, mirroring resetCAUsabilityHealthForTest. The cluster-CA
// test harness swaps globalClusterCA per test (swapEnrollFixture); the health
// record is process-global and has to be reset alongside it or a fault recorded
// by one test leaks into the next under -count=2 -shuffle=on.
func resetClusterCAHealthForTest() {
	clusterCAUsability.mu.Lock()
	defer clusterCAUsability.mu.Unlock()
	clusterCAUsability.refusals = 0
	clusterCAUsability.last = time.Time{}
	clusterCAUsability.lastReason = ""
	clusterCAUsability.rotationFailures = 0
	clusterCAUsability.lastRotErr = ""
	clusterCAUsability.lastRotFail = time.Time{}
	clusterCAUsability.lastRotOK = time.Time{}
	clusterCAUsability.logAt = time.Time{}
	clusterCAUsability.alertAt = time.Time{}
}
