package main

// cluster_ca_health.go — cluster-CA usability health plane (CHAOS-50, register
// row CA-13).
//
// Sink for the cluster-CA observers, mirroring ca_health.go's contract because
// the failure shape is identical: an external condition that fires from
// arbitrary goroutines at arbitrary rates, for as long as the condition lasts.
//
//   - count every event, so magnitude is never lost to rate limiting;
//   - rate-limit the LOG and the ALERT on independent gates;
//   - never spawn a delivery goroutine when nothing subscribes to the event;
//   - report recovery on EVIDENCE (a CA observed usable again), never on
//     elapsed time.
//
// The last rule matters as much here as it did for the inspection CA, and for
// the same reason: a still-expired cluster CA is indistinguishable from a
// healthy one on a quiet cluster, where nothing enrolls or renews for days. An
// elapsed-time heuristic would clear the degraded row without a single
// successful issuance behind it.
//
// The alert reuses the existing `cert_expiry` event rather than introducing a
// new one. Operators already route it for the inspection CA and for DP node
// certs (CHAOS-12); a cluster-CA-specific event name would need a new
// subscription in every existing deployment to be seen at all, and the
// normalizeEventNames migration exists precisely because renames are expensive.
// The Source field ("cluster-ca") carries the distinction.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// clusterCAUnusableAlertInterval rate-limits the log line and the alert emitted
// for an unusable cluster CA. Enrollment and renewal are ordinarily low-rate,
// but a fleet-wide reconnect storm (the exact thing an expired cluster CA
// causes) drives every node into a retry loop at once, so an ungated producer
// would flood the log and overflow the webhook queue at the moment the operator
// most needs it to work. The counters carry the magnitude.
const clusterCAUnusableAlertInterval = 5 * time.Minute

// clusterCAHealth is the process-wide record of cluster-CA usability faults.
type clusterCAHealth struct {
	mu sync.Mutex

	// signRefusals counts CSR signings refused because the CA was outside its
	// validity window. Every refusal is one node that could not enroll or renew.
	signRefusals int64

	// clamps counts node certificates whose validity had to be shortened to fit
	// inside the issuer's. Non-zero is not a fault — it is the early-warning
	// that the CA is inside one node-cert lifetime of its own expiry, which is
	// exactly when the fleet must still be renewing normally.
	clamps int64

	last       time.Time // most recent observed fault
	lastReason string    // sanitised detail (never key material)
	lastOK     time.Time // most recent OBSERVED usable verification

	// rotationFailures is CUMULATIVE (Prometheus counter shape). The CURRENT
	// state lives on clusterCA.lastRotationErr, which ImportCA clears on the
	// next success — the same split ca_health.go draws between persistFailures
	// and persistDegraded, for the same reason: a warning keyed on a cumulative
	// counter keeps contradicting an operator who has already fixed the fault.
	rotationFailures int64

	logAt   time.Time
	alertAt time.Time
}

var clusterCAUsability clusterCAHealth

// clusterCAEverUnusable short-circuits the recovery observer so the healthy path
// stays a single relaxed atomic load.
var clusterCAEverUnusable atomic.Bool

// fireClusterCAAlert delivers the cert_expiry alert for a cluster-CA fault.
// Package-level seam so tests observe the transition synchronously instead of
// racing the process-global alerts sink.
var fireClusterCAAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("cert_expiry") {
		return
	}
	go fireAlert("cert_expiry", AlertPayload{
		Host:   "culvert-cluster-ca",
		Detail: detail,
		Source: "cluster-ca",
	})
}

// noteClusterCASignRefused records a CSR signing refused because the cluster CA
// was outside its validity window. Runs synchronously on the RPC goroutine, so
// it does memory-only work and hands the alert off.
func noteClusterCASignRefused(reason string) {
	safe := sanitizeLog(reason)
	now := time.Now()
	clusterCAEverUnusable.Store(true)

	clusterCAUsability.mu.Lock()
	clusterCAUsability.signRefusals++
	clusterCAUsability.last = now
	clusterCAUsability.lastReason = safe
	refusals := clusterCAUsability.signRefusals
	doLog := clusterCAUsability.logAt.IsZero() || now.Sub(clusterCAUsability.logAt) >= clusterCAUnusableAlertInterval
	if doLog {
		clusterCAUsability.logAt = now
	}
	doAlert := clusterCAUsability.alertAt.IsZero() || now.Sub(clusterCAUsability.alertAt) >= clusterCAUnusableAlertInterval
	if doAlert {
		clusterCAUsability.alertAt = now
	}
	clusterCAUsability.mu.Unlock()

	if doLog && logger != nil {
		logger.Printf("ClusterCA: node-certificate issuance is DOWN — the cluster CA cannot sign a usable "+
			"certificate: %q (%d enrollments/renewals refused since boot). Import or rotate the cluster CA; "+
			"data-plane nodes cannot enroll or renew until then.", safe, refusals)
	}
	if doAlert {
		fireClusterCAAlert(fmt.Sprintf(
			"Cluster node-certificate issuance is DOWN — the cluster CA cannot sign a usable certificate: %s "+
				"(%d enrollments/renewals refused since boot)", safe, refusals))
	}
}

// noteClusterCACertClamped records a node certificate whose validity was
// shortened to its issuer's. Counted, not logged per event: on a fleet renewing
// inside the overlap window this fires once per node and the useful signal is
// the count, not the individual lines.
func noteClusterCACertClamped() {
	clusterCAUsability.mu.Lock()
	clusterCAUsability.clamps++
	clusterCAUsability.mu.Unlock()
}

// noteClusterCARotationFailure records an auto-rotation attempt that failed.
// Always logged and always alerted: it fires at most once per rotation round
// (a 24h cadence), so it is bounded by construction and needs no gate.
//
// This is the signal CA-13 was recorded for. Auto-rotation is the ONLY thing
// standing between a cluster CA and a fleet-wide mTLS outage 30 days later, and
// before this every failure branch logged-and-returned into a log nobody greps
// until the outage has already happened.
func noteClusterCARotationFailure(stage string, err error) {
	safe := sanitizeLog(err.Error())
	clusterCAUsability.mu.Lock()
	clusterCAUsability.rotationFailures++
	n := clusterCAUsability.rotationFailures
	clusterCAUsability.mu.Unlock()

	if logger != nil {
		logger.Printf("ClusterCA: auto-rotation FAILED at %q (%d failures since boot): %q — the cluster CA "+
			"still expires on schedule and data-plane mTLS will break at that point; the next attempt is in 24h",
			sanitizeLog(stage), n, safe)
	}
	if globalAlertStore.HasSubscriber("cert_expiry") {
		go fireAlert("cert_expiry", AlertPayload{
			Host: "culvert-cluster-ca",
			Detail: fmt.Sprintf("Cluster CA auto-rotation failed at %s (%d failures since boot): %s — "+
				"the CA still expires on schedule; data-plane enrollment and mTLS break at expiry",
				sanitizeLog(stage), n, safe),
			Source: "cluster-ca",
		})
	}
}

// noteClusterCAUsable records an OBSERVED successful usability verification.
// The only thing that clears the degraded state — silence is not recovery.
func noteClusterCAUsable() {
	if !clusterCAEverUnusable.Load() {
		return
	}
	now := time.Now()
	clusterCAUsability.mu.Lock()
	clusterCAUsability.lastOK = now
	clusterCAUsability.mu.Unlock()
}

// clusterCAIssuanceUsable is the single live predicate for "can this node issue
// a node certificate right now". Every caller that asks the question also
// contributes the evidence that clears a past fault.
func clusterCAIssuanceUsable() bool {
	if err := globalClusterCA.Usable(); err != nil {
		return false
	}
	noteClusterCAUsable()
	return true
}

// clusterCAUsabilityDegraded reports whether cluster-CA issuance should be
// treated as broken RIGHT NOW: a refusal has been observed and no successful
// verification has been seen since.
func clusterCAUsabilityDegraded() bool {
	clusterCAUsability.mu.Lock()
	defer clusterCAUsability.mu.Unlock()
	if clusterCAUsability.signRefusals == 0 {
		return false
	}
	return !clusterCAUsability.lastOK.After(clusterCAUsability.last)
}

// clusterCAHealthSnapshot is a consistent read of the fault record.
type clusterCAHealthSnapshot struct {
	SignRefusals     int64
	Clamps           int64
	RotationFailures int64
	Last             time.Time
	Reason           string
}

func clusterCAUsabilityFailures() clusterCAHealthSnapshot {
	clusterCAUsability.mu.Lock()
	defer clusterCAUsability.mu.Unlock()
	return clusterCAHealthSnapshot{
		SignRefusals:     clusterCAUsability.signRefusals,
		Clamps:           clusterCAUsability.clamps,
		RotationFailures: clusterCAUsability.rotationFailures,
		Last:             clusterCAUsability.last,
		Reason:           clusterCAUsability.lastReason,
	}
}

// resetClusterCAHealthForTest clears the record. Test-only helper kept beside
// the state it resets, mirroring resetCAUsabilityHealthForTest.
func resetClusterCAHealthForTest() {
	clusterCAUsability.mu.Lock()
	defer clusterCAUsability.mu.Unlock()
	clusterCAUsability.signRefusals = 0
	clusterCAUsability.clamps = 0
	clusterCAUsability.rotationFailures = 0
	clusterCAUsability.last = time.Time{}
	clusterCAUsability.lastReason = ""
	clusterCAUsability.lastOK = time.Time{}
	clusterCAUsability.logAt = time.Time{}
	clusterCAUsability.alertAt = time.Time{}
	clusterCAEverUnusable.Store(false)
}
