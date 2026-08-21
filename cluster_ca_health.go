package main

// cluster_ca_health.go — cluster-CA usability health plane (CHAOS-50, register
// row CA-13).
//
// The inspection CA got this plane in CHAOS-28. The cluster CA had none of it:
// an auto-rotation failure was recorded on Info() only (so it was visible if,
// and only if, an operator happened to open the Cluster CA panel), and the CA's
// own validity moved nothing at all — no gauge, no counter, no probe row, no
// alert. A CP whose CA directory had gone read-only was indistinguishable from
// a healthy one, on every surface, right up to the moment the whole fleet lost
// mTLS trust.
//
// It mirrors ca_health.go and storage_health.go exactly, because the failure
// shape is the same (an external condition that fires from arbitrary goroutines
// at arbitrary rates, for as long as the condition lasts):
//
//   - count every event, so magnitude is never lost to rate limiting;
//   - rate-limit the LOG and the ALERT on independent gates;
//   - never spawn a delivery goroutine when nothing subscribes to the event;
//   - report recovery on EVIDENCE (a CA that verifies usable again, a rotation
//     that actually landed), never on elapsed time.
//
// It reuses the existing cert_expiry alert event rather than minting a new one.
// A new event name would be silently unsubscribed on every already-configured
// webhook — an operator who is paged for Root-CA expiry today plainly wants to
// be paged for cluster-CA expiry too, and Host distinguishes the two.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// clusterCAAlertHost is the alert Host that distinguishes cluster-CA events
// from the inspection CA's culvert-ca on the shared cert_expiry event.
const clusterCAAlertHost = "culvert-cluster-ca"

// clusterCAUnusableAlertInterval rate-limits the cert_expiry alert and the log
// line for an unusable cluster CA. Enrollment and cert renewal are not
// per-request paths, but a fleet in a renewal storm (every node's cert clamped
// into its renewal window, retrying every 6h) can still produce thousands of
// refusals per interval. The counters carry the magnitude; one signal per
// interval carries the page. Matches caUnusableAlertInterval.
const clusterCAUnusableAlertInterval = 5 * time.Minute

// clusterCAHealthRecord is the process-wide record of cluster-CA faults.
type clusterCAHealthRecord struct {
	mu sync.Mutex

	// signRefusals is every node-certificate issuance refused because the CA
	// was outside its own validity window (enrollment and renewal alike).
	signRefusals int64

	// clampedIssuances counts node certs whose validity was narrowed to the
	// issuer's. Non-zero means the CA is inside its final window and rotation
	// has not happened — a leading indicator, distinct from a refusal, which is
	// the cliff itself.
	clampedIssuances int64

	last       time.Time // most recent observed fault
	lastReason string    // sanitised, key-material-free detail
	lastOK     time.Time // most recent OBSERVED usable verification

	// rotationFailures is CUMULATIVE — the right shape for a Prometheus counter
	// and the wrong shape for a status row, so the two are tracked separately.
	// lastRotationFail/lastRotationOK carry the CURRENT state: an operator who
	// restores write access to the CA directory and imports a replacement has
	// fixed the problem, and a warning keyed on the cumulative counter would
	// keep contradicting them until process restart.
	rotationFailures int64
	lastRotationErr  string
	lastRotationFail time.Time
	lastRotationOK   time.Time

	logAt   time.Time
	alertAt time.Time
}

var clusterCAHealth clusterCAHealthRecord

// clusterCAEverUnusable short-circuits the recovery observer, so the healthy
// path stays a single relaxed atomic load.
var clusterCAEverUnusable atomic.Bool

// fireClusterCAAlert delivers a cert_expiry alert for the cluster CA.
// Package-level seam so tests observe the transition synchronously instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI gate catches).
var fireClusterCAAlert = func(detail string) {
	// Nobody subscribed → do nothing at all, and in particular do not spawn a
	// goroutine (the per-request alert-producer contract in CLAUDE.md; this
	// producer is reached from the enrollment RPC path).
	if !globalAlertStore.HasSubscriber("cert_expiry") {
		return
	}
	go fireAlert("cert_expiry", AlertPayload{
		Host:   clusterCAAlertHost,
		Detail: detail,
		Source: "ca",
	})
}

// noteClusterCASignRefused records a node-certificate issuance refused because
// the cluster CA was outside its validity window. Runs synchronously on the
// enrollment RPC's goroutine, so it does memory-only work and hands the alert
// off.
func noteClusterCASignRefused(reason string) {
	safeReason := sanitizeLog(reason)
	now := time.Now()
	clusterCAEverUnusable.Store(true)

	clusterCAHealth.mu.Lock()
	clusterCAHealth.signRefusals++
	clusterCAHealth.last = now
	clusterCAHealth.lastReason = safeReason
	refusals := clusterCAHealth.signRefusals
	doLog := clusterCAHealth.logAt.IsZero() || now.Sub(clusterCAHealth.logAt) >= clusterCAUnusableAlertInterval
	if doLog {
		clusterCAHealth.logAt = now
	}
	doAlert := clusterCAHealth.alertAt.IsZero() || now.Sub(clusterCAHealth.alertAt) >= clusterCAUnusableAlertInterval
	if doAlert {
		clusterCAHealth.alertAt = now
	}
	clusterCAHealth.mu.Unlock()

	if doLog && logger != nil {
		logger.Printf("ClusterCA: node-certificate issuance REFUSED — the cluster CA cannot sign a certificate "+
			"peers will accept: %q (%d refusals since boot). Enrolled nodes cannot complete mTLS; "+
			"import a replacement cluster CA to restore the control plane.", safeReason, refusals)
	}
	if doAlert {
		fireClusterCAAlert(fmt.Sprintf(
			"Cluster CA is UNUSABLE — node enrollment and certificate renewal are refused: %s "+
				"(%d refusals since boot). Enrolled data-plane nodes cannot complete mTLS with the control plane.",
			safeReason, refusals))
	}
}

// noteClusterCAClamped records a node cert whose validity was narrowed to the
// issuer's. Log-only and rate-limited on the same gate as a refusal: it is the
// warning shoulder of the same cliff, and pairing them on one gate means a CA
// that crosses from clamping into refusing does not double the operator's
// signal volume for one underlying condition.
func noteClusterCAClamped(notAfter time.Time) {
	now := time.Now()
	clusterCAHealth.mu.Lock()
	clusterCAHealth.clampedIssuances++
	n := clusterCAHealth.clampedIssuances
	doLog := clusterCAHealth.logAt.IsZero() || now.Sub(clusterCAHealth.logAt) >= clusterCAUnusableAlertInterval
	if doLog {
		clusterCAHealth.logAt = now
	}
	clusterCAHealth.mu.Unlock()

	if doLog && logger != nil {
		logger.Printf("ClusterCA: node certificate validity CLAMPED to the cluster CA's own expiry %s "+
			"(%d clamped since boot) — the cluster CA is inside its final window and has not rotated. "+
			"Nodes will renew repeatedly until it does.",
			notAfter.UTC().Format(time.RFC3339), n)
	}
}

// noteClusterCARotationFailure records an auto-rotation that could not complete
// (keygen, serial, cert creation, key marshal, or the ImportCA persist).
// Always logged and always alerted: unlike the refusal path it fires at most
// once per rotation attempt (a 24h cadence), so it is bounded by construction
// and needs no gate.
//
// This is the signal whose absence made row CA-13 a silent failure. Rotation is
// the ONLY recovery the cluster CA has, so a rotation that keeps failing is the
// single most important thing an operator can be told about this subsystem, and
// before this it was told nothing an alerting rule could see.
func noteClusterCARotationFailure(reason string) {
	safe := sanitizeLog(reason)
	now := time.Now()
	clusterCAHealth.mu.Lock()
	clusterCAHealth.rotationFailures++
	clusterCAHealth.lastRotationErr = safe
	clusterCAHealth.lastRotationFail = now
	n := clusterCAHealth.rotationFailures
	clusterCAHealth.mu.Unlock()

	if logger != nil {
		logger.Printf("ClusterCA: auto-rotation FAILED (%d since boot): %q — the cluster CA is not being "+
			"replaced. At its expiry every enrolled node loses mTLS trust with the control plane.", n, safe)
	}
	if globalAlertStore.HasSubscriber("cert_expiry") {
		go fireAlert("cert_expiry", AlertPayload{
			Host: clusterCAAlertHost,
			Detail: fmt.Sprintf("Cluster CA auto-rotation failed (%d failures since boot): %s — "+
				"the CA will not be replaced and the whole fleet loses mTLS trust at its expiry", n, safe),
			Source: "ca",
		})
	}
}

// noteClusterCARotated records an OBSERVED successful rotation/import. It is
// what clears the rotation warning — see clusterCARotationDegraded. The
// cumulative counter is deliberately NOT decremented: it feeds a Prometheus
// counter, which must never go backwards, and the historical fact that rotation
// once failed stays worth knowing.
func noteClusterCARotated() {
	now := time.Now()
	clusterCAHealth.mu.Lock()
	clusterCAHealth.lastRotationOK = now
	clusterCAHealth.mu.Unlock()
}

// noteClusterCAUsable records an OBSERVED successful usability verification.
// This is the only thing that clears the degraded state: silence is not
// recovery. A CA that is still expired looks exactly like a healthy one if
// nothing happens to need a certificate, so an elapsed-time heuristic would
// report a control plane recovered without a single successful issuance behind
// it — and on a settled fleet, where no node enrolls for weeks, that heuristic
// would fire almost immediately and always be wrong.
func noteClusterCAUsable() {
	if !clusterCAEverUnusable.Load() {
		return
	}
	now := time.Now()
	clusterCAHealth.mu.Lock()
	clusterCAHealth.lastOK = now
	clusterCAHealth.mu.Unlock()
}

// clusterCAHealthSnapshot is a consistent read of the fault record.
// RotationFailures is CUMULATIVE (the counter); RotationDegraded is the CURRENT
// state (the status row) — see clusterCARotationDegraded for why they must not
// be conflated.
type clusterCAHealthSnapshot struct {
	SignRefusals     int64
	ClampedIssuances int64
	Last             time.Time
	Reason           string
	RotationFailures int64
	RotationErr      string
	RotationDegraded bool
}

func clusterCAFailures() clusterCAHealthSnapshot {
	clusterCAHealth.mu.Lock()
	defer clusterCAHealth.mu.Unlock()
	return clusterCAHealthSnapshot{
		SignRefusals:     clusterCAHealth.signRefusals,
		ClampedIssuances: clusterCAHealth.clampedIssuances,
		Last:             clusterCAHealth.last,
		Reason:           clusterCAHealth.lastReason,
		RotationFailures: clusterCAHealth.rotationFailures,
		RotationErr:      clusterCAHealth.lastRotationErr,
		RotationDegraded: !clusterCAHealth.lastRotationFail.IsZero() &&
			!clusterCAHealth.lastRotationOK.After(clusterCAHealth.lastRotationFail),
	}
}

// clusterCAUsableNow is the single live predicate for "can this control plane
// issue node identities right now". It also feeds the recovery observer, so
// every caller that asks the question contributes the evidence that clears a
// past fault.
func clusterCAUsableNow() bool {
	if globalClusterCA.Usable() != nil {
		return false
	}
	noteClusterCAUsable()
	return true
}

// clusterCARotationDegraded reports whether cluster-CA rotation is CURRENTLY
// broken: a rotation has failed and no successful one has been observed since.
// This is what the diagnostics row, GET /api/cluster/ca and the admin panel key
// on — not the cumulative counter, which would latch the warning for the life of
// the process even after the operator fixed the volume and imported a new CA.
func clusterCARotationDegraded() bool {
	clusterCAHealth.mu.Lock()
	defer clusterCAHealth.mu.Unlock()
	if clusterCAHealth.lastRotationFail.IsZero() {
		return false
	}
	return !clusterCAHealth.lastRotationOK.After(clusterCAHealth.lastRotationFail)
}

// clusterCAUsabilityDegraded reports whether the cluster CA should be treated as
// broken RIGHT NOW: a refusal has been observed and no successful verification
// has been seen since. Used by the operator contract, /healthz, /readyz and
// /metrics.
func clusterCAUsabilityDegraded() bool {
	clusterCAHealth.mu.Lock()
	defer clusterCAHealth.mu.Unlock()
	if clusterCAHealth.signRefusals == 0 {
		return false
	}
	return !clusterCAHealth.lastOK.After(clusterCAHealth.last)
}

// resetClusterCAHealthForTest clears the record. Test-only helper kept beside
// the state it resets, mirroring resetCAUsabilityHealthForTest.
func resetClusterCAHealthForTest() {
	clusterCAHealth.mu.Lock()
	defer clusterCAHealth.mu.Unlock()
	clusterCAHealth.signRefusals = 0
	clusterCAHealth.clampedIssuances = 0
	clusterCAHealth.last = time.Time{}
	clusterCAHealth.lastReason = ""
	clusterCAHealth.lastOK = time.Time{}
	clusterCAHealth.rotationFailures = 0
	clusterCAHealth.lastRotationErr = ""
	clusterCAHealth.lastRotationFail = time.Time{}
	clusterCAHealth.lastRotationOK = time.Time{}
	clusterCAHealth.logAt = time.Time{}
	clusterCAHealth.alertAt = time.Time{}
	clusterCAEverUnusable.Store(false)
}
