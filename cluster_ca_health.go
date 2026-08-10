package main

// cluster_ca_health.go — cluster-CA usability + rotation health plane
// (CHAOS-29, register row CA-13).
//
// Sink for the faults cluster_ca_validity.go detects and for the auto-rotation
// failures that used to be log-only. It mirrors ca_health.go's contract exactly,
// because the failure shape is the same — an external condition that fires from
// arbitrary goroutines, for as long as the condition lasts:
//
//   - count every event, so magnitude is never lost to rate limiting;
//   - rate-limit the LOG and the ALERT on independent gates;
//   - never spawn a delivery goroutine when nothing subscribes to the event;
//   - report recovery on EVIDENCE (a CA observed usable again), never on
//     elapsed time.
//
// The rotation half is what register row CA-13 named: every failure branch in
// RotateIfNeeded logged and returned. lastRotationErr already put the most
// recent one on the admin API, which is a real improvement over nothing, but it
// is a PULL surface — it tells an operator who is already looking at the Cluster
// CA panel. Nothing pushed, nothing counted, and nothing an alerting rule could
// evaluate. A cluster CA that quietly stops rotating is discovered when the
// fleet loses mTLS trust, which is the one moment an operator cannot afford to
// be finding out.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// clusterCAUnusableAlertInterval rate-limits the cert_expiry alert and the log
// line emitted for an unusable cluster CA. Enrollment and renewal are far lower
// volume than CONNECT, but a fleet-wide reconnect storm against an expired CA
// puts one signing attempt per node per retry through this path — so the gate
// is the same shape as the inspection CA's, for the same reason. The counters
// carry magnitude; one signal per interval carries the page.
const clusterCAUnusableAlertInterval = 5 * time.Minute

// Cluster-CA fault counters. Label-free, per the CA-2 metrics contract: no node
// ID, subject, serial, fingerprint, or key material — counts only.
var (
	statClusterCASignRefused     atomic.Int64 // CSR signings refused: CA outside its validity window
	statClusterCARotationFailure atomic.Int64 // auto-rotation attempts that did not install a new CA
)

// clusterCAHealthRecord is the process-wide record of cluster-CA faults.
type clusterCAHealthRecord struct {
	mu sync.Mutex

	last       time.Time // most recent observed usability fault
	lastReason string    // sanitised, key-material-free detail
	lastOK     time.Time // most recent OBSERVED usable verification

	// Rotation state is tracked separately from the cumulative counter for the
	// same reason ca_health.go splits persistFailures from lastPersistOK: the
	// counter is the right shape for Prometheus and the wrong shape for a
	// status row. An operator who fixes the CA directory and sees the next
	// rotation succeed must stop being told rotation is broken.
	lastRotationFail time.Time
	lastRotationOK   time.Time

	logAt   time.Time
	alertAt time.Time
}

var clusterCAHealth clusterCAHealthRecord

// clusterCAEverUnusable short-circuits the recovery observer so the healthy
// signing path stays a single relaxed atomic load.
var clusterCAEverUnusable atomic.Bool

// fireClusterCAUnusableAlert delivers the cert_expiry alert for an unusable
// cluster CA. Package-level seam so tests observe the transition synchronously
// instead of racing the process-global alerts sink (the -count/-shuffle
// determinism class the CI gate catches).
var fireClusterCAUnusableAlert = func(detail string) {
	// Nobody subscribed → do nothing at all, and in particular do not spawn a
	// goroutine (the per-request alert-producer contract in CLAUDE.md).
	if !globalAlertStore.HasSubscriber("cert_expiry") {
		return
	}
	go fireAlert("cert_expiry", AlertPayload{
		Host:   "culvert-cluster-ca",
		Detail: detail,
		Source: "cluster-ca",
	})
}

// fireClusterCARotationAlert delivers the cert_expiry alert for a failed
// auto-rotation. Separate seam from the usability alert because the two carry
// different operator actions and fire at wildly different rates.
var fireClusterCARotationAlert = func(detail string) {
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
// outside its validity window. Runs synchronously on the enrolling node's RPC
// goroutine, so it does memory-only work and hands the alert off.
func noteClusterCAUnusable(reason string) {
	safe := sanitizeLog(reason)
	now := time.Now()
	clusterCAEverUnusable.Store(true)

	clusterCAHealth.mu.Lock()
	clusterCAHealth.last = now
	clusterCAHealth.lastReason = safe
	doLog := clusterCAHealth.logAt.IsZero() || now.Sub(clusterCAHealth.logAt) >= clusterCAUnusableAlertInterval
	if doLog {
		clusterCAHealth.logAt = now
	}
	doAlert := clusterCAHealth.alertAt.IsZero() || now.Sub(clusterCAHealth.alertAt) >= clusterCAUnusableAlertInterval
	if doAlert {
		clusterCAHealth.alertAt = now
	}
	clusterCAHealth.mu.Unlock()

	refused := statClusterCASignRefused.Load()
	// The observer can be reached before setupLogger on an early enrollment.
	if doLog && logger != nil {
		logger.Printf("ClusterCA: node enrollment/renewal is DOWN — the cluster CA cannot sign a usable "+
			"node certificate: %q (%d signings refused since boot). Import a replacement cluster CA; "+
			"every Data Plane node must then re-enroll.", safe, refused)
	}
	if doAlert {
		// Deliberately not worded "outside its validity window": the same
		// refusal also covers a CA that never loaded (InitOrLoad failed), and
		// an alert that names the wrong cause sends the operator to check a
		// certificate date when the actual fault is a read-only volume. The
		// reason string carries the specific cause either way.
		fireClusterCAUnusableAlert(fmt.Sprintf(
			"Cluster CA cannot sign a usable node certificate — Data Plane enrollment and cert renewal are "+
				"BLOCKED: %s (%d signings refused since boot)", safe, refused))
	}
}

// noteClusterCAUsable records an OBSERVED successful usability verification.
// This is the only thing that clears the degraded state: silence is not
// recovery. A cluster CA that is still expired looks exactly like a healthy one
// if no node happens to enroll, so an elapsed-time heuristic would report a node
// recovered without a single successful signing behind it.
func noteClusterCAUsable() {
	if !clusterCAEverUnusable.Load() {
		return
	}
	now := time.Now()
	clusterCAHealth.mu.Lock()
	clusterCAHealth.lastOK = now
	clusterCAHealth.mu.Unlock()
}

// noteClusterCARotationFailure records an auto-rotation round that did not
// install a new CA. Always logged and always alerted: it fires at most once per
// rotation check (a 24h cadence), so it is bounded by construction and needs no
// gate — the same reasoning ca_health.go applies to the persist-failure path.
func noteClusterCARotationFailure(reason string) {
	safe := sanitizeLog(reason)
	now := time.Now()
	n := statClusterCARotationFailure.Add(1)

	clusterCAHealth.mu.Lock()
	clusterCAHealth.lastRotationFail = now
	clusterCAHealth.mu.Unlock()

	if logger != nil {
		logger.Printf("ClusterCA: auto-rotation FAILED (%d since boot): %q — the cluster CA is inside its "+
			"30-day expiry window and did not renew. At expiry every Data Plane node loses mTLS trust "+
			"and cannot re-enroll.", n, safe)
	}
	fireClusterCARotationAlert(fmt.Sprintf(
		"Cluster CA auto-rotation failed (%d failures since boot): %s — the CA expires within 30 days and "+
			"did not renew; at expiry the whole fleet loses mTLS trust", n, safe))
}

// noteClusterCARotated records an OBSERVED successful rotation/import. It is
// what clears the rotation warning — see clusterCARotationDegraded. The
// cumulative counter is deliberately NOT decremented: it feeds a Prometheus
// counter, which must never go backwards.
func noteClusterCARotated() {
	now := time.Now()
	clusterCAHealth.mu.Lock()
	clusterCAHealth.lastRotationOK = now
	clusterCAHealth.mu.Unlock()
}

// clusterCARotationDegraded reports whether auto-rotation is CURRENTLY known to
// be failing: a rotation attempt has failed and no successful one has been
// observed since. Status rows and the admin panel key on this, not on the
// cumulative counter, which would latch the warning for the life of the process
// even after the operator fixed the directory and the next rotation succeeded.
func clusterCARotationDegraded() bool {
	clusterCAHealth.mu.Lock()
	defer clusterCAHealth.mu.Unlock()
	if clusterCAHealth.lastRotationFail.IsZero() {
		return false
	}
	return !clusterCAHealth.lastRotationOK.After(clusterCAHealth.lastRotationFail)
}

// clusterCAHealthSnapshot is a consistent read of the fault record.
// RotationFailures is CUMULATIVE (the counter); RotationDegraded is the CURRENT
// state (the status row) — see clusterCARotationDegraded for why the two must
// not be conflated.
type clusterCAHealthSnapshot struct {
	SignRefusals     int64
	Last             time.Time
	Reason           string
	RotationFailures int64
	RotationDegraded bool
}

func clusterCAHealthFailures() clusterCAHealthSnapshot {
	clusterCAHealth.mu.Lock()
	snap := clusterCAHealthSnapshot{
		SignRefusals:     statClusterCASignRefused.Load(),
		Last:             clusterCAHealth.last,
		Reason:           clusterCAHealth.lastReason,
		RotationFailures: statClusterCARotationFailure.Load(),
	}
	degraded := !clusterCAHealth.lastRotationFail.IsZero() &&
		!clusterCAHealth.lastRotationOK.After(clusterCAHealth.lastRotationFail)
	clusterCAHealth.mu.Unlock()
	snap.RotationDegraded = degraded
	return snap
}

// resetClusterCAHealthForTest isolates the process-global record between tests.
// Mirrors the reset seams the other health planes expose — without it, a fault
// recorded by one test leaks into the next under -count=2 -shuffle=on.
func resetClusterCAHealthForTest() {
	statClusterCASignRefused.Store(0)
	statClusterCARotationFailure.Store(0)
	clusterCAEverUnusable.Store(false)
	// Fields are reset individually rather than by assigning a zero struct:
	// overwriting the record would replace the mutex itself while it is held,
	// and the subsequent Unlock would then release a different (unlocked) lock.
	clusterCAHealth.mu.Lock()
	clusterCAHealth.last = time.Time{}
	clusterCAHealth.lastReason = ""
	clusterCAHealth.lastOK = time.Time{}
	clusterCAHealth.lastRotationFail = time.Time{}
	clusterCAHealth.lastRotationOK = time.Time{}
	clusterCAHealth.logAt = time.Time{}
	clusterCAHealth.alertAt = time.Time{}
	clusterCAHealth.mu.Unlock()
}

// clusterCAWriteUsabilityPrometheus appends the CHAOS-29 cluster-CA series.
//
// The gap these close: before them, an expired or non-rotating cluster CA moved
// NOTHING an operator could scrape. culvert_cluster_ca_rotations_total counts
// only successes, so a CA that stopped rotating produced a FLAT counter — which
// is indistinguishable from a healthy CA nowhere near its window. There was no
// expiry series at all. culvert_cluster_ca_expires_in_seconds is the one to
// alert on well before the cliff; the rest confirm the cliff was hit.
//
// Label-free, per the CA-2 metrics contract.
func clusterCAWriteUsabilityPrometheus(w *strings.Builder) {
	snap := clusterCAHealthFailures()

	// Both gauges are omitted entirely when no cluster CA is loaded. An absent
	// series is honest; a 0 is not. Most Culvert deployments are standalone
	// proxies with no cluster CA at all, and `culvert_cluster_ca_usable 0` on
	// every one of them would read as a fleet-wide CA outage — the alerting
	// rule an operator writes against this metric has to be safe to deploy
	// without first enumerating which nodes are Control Planes.
	if exp := globalClusterCA.Expiry(); !exp.IsZero() {
		w.WriteString("\n# HELP culvert_cluster_ca_usable Whether the cluster CA can currently sign a node cert peers will accept (1 = yes)\n")
		w.WriteString("# TYPE culvert_cluster_ca_usable gauge\n")
		usable := 0
		if globalClusterCA.Usable() == nil {
			usable = 1
		}
		fmt.Fprintf(w, "culvert_cluster_ca_usable %d\n", usable)

		w.WriteString("\n# HELP culvert_cluster_ca_expires_in_seconds Seconds until the cluster CA certificate expires (negative once expired)\n")
		w.WriteString("# TYPE culvert_cluster_ca_expires_in_seconds gauge\n")
		fmt.Fprintf(w, "culvert_cluster_ca_expires_in_seconds %d\n", int64(time.Until(exp).Seconds()))
	}

	w.WriteString("\n# HELP culvert_cluster_ca_sign_refused_total Node-cert signings refused because the cluster CA was outside its validity window\n")
	w.WriteString("# TYPE culvert_cluster_ca_sign_refused_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_ca_sign_refused_total %d\n", snap.SignRefusals)

	w.WriteString("\n# HELP culvert_cluster_ca_rotation_failures_total Cluster CA auto-rotation attempts that did not install a new CA\n")
	w.WriteString("# TYPE culvert_cluster_ca_rotation_failures_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_ca_rotation_failures_total %d\n", snap.RotationFailures)
}
