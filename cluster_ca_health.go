package main

// cluster_ca_health.go — cluster-CA usability health plane (CHAOS-50, register
// row CA-13).
//
// The cluster CA is the trust root for node enrollment: it signs the client
// certificates every Data Plane presents on the mTLS config-sync channel. Its
// failure modes were invisible from inside the appliance:
//
//   - auto-rotation failed → one log line and a field on the admin API's
//     Info() map. No counter, no alert, no health row. The next attempt is 24 h
//     later, so a CA that starts failing to rotate 30 days before expiry can
//     burn all 30 days silently and then expire;
//   - the CA expired → SignCSR kept issuing certificates (x509 does not check
//     the parent's window), so enrollment "succeeded" and the node then failed
//     every mTLS handshake. The only symptom was a wave of TLS errors on N data
//     planes, with the CP reporting nothing at all.
//
// `culvert_cluster_ca_rotations_total` counted only SUCCESSES, which is exactly
// the wrong shape: the series an operator needs is the one that moves when the
// appliance stops being able to renew its own trust root.
//
// This file mirrors ca_health.go's contract, because the failure shape is the
// same external-condition class:
//
//   - count every event, so magnitude is never lost to rate limiting;
//   - rate-limit the LOG and the ALERT on independent gates;
//   - never spawn a delivery goroutine when nothing subscribes to the event;
//   - report recovery on EVIDENCE (a rotation that actually succeeded), never
//     on elapsed time.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// clusterCAAlertInterval rate-limits the cluster_ca_degraded alert and its log
// line. A CP whose cluster CA has expired refuses EVERY enrollment and every
// renewal, so an ungated producer would emit one webhook per DP renewal attempt
// across the fleet. The counters carry the magnitude; one signal per interval
// carries the page.
const clusterCAAlertInterval = 5 * time.Minute

// Cluster-CA health counters. Label-free, consistent with the CA-2 metrics
// contract: no fingerprints, serials, subjects, SANs, node IDs, or key
// material appears in any series.
var (
	statClusterCARotationFailures atomic.Int64 // auto-rotation attempts that did not install a new CA
	statClusterCASignRefused      atomic.Int64 // CSRs refused because the CA is outside its own window
)

// clusterCAHealth is the process-wide record of cluster-CA faults.
type clusterCAHealth struct {
	mu sync.Mutex

	last       time.Time // most recent observed fault
	lastReason string    // sanitised, key-material-free detail
	lastOK     time.Time // most recent OBSERVED successful rotation

	// degraded is the CURRENT state, distinct from the cumulative counters.
	// A counter-keyed status row would stay latched until process restart even
	// after the operator fixed the volume and the next rotation succeeded —
	// the CHAOS-28 lesson, applied here from the start.
	degraded bool

	lastLog   time.Time
	lastAlert time.Time
}

var clusterCAFaults clusterCAHealth

// fireClusterCAAlert delivers the cluster_ca_degraded alert. Package-level seam
// so tests observe transitions synchronously rather than racing the
// process-global alerts sink (the -count/-shuffle determinism class).
var fireClusterCAAlert = func(detail string) {
	// Nobody subscribed → do nothing at all, and in particular do not spawn a
	// goroutine. This producer is reached from the enrollment RPC path, which
	// an unhealthy fleet drives at reconnect-storm rates.
	if !globalAlertStore.HasSubscriber("cluster_ca_degraded") {
		return
	}
	go fireAlert("cluster_ca_degraded", AlertPayload{
		Detail: detail,
		Source: "cluster-ca",
	})
}

// noteClusterCARotationFailure records an auto-rotation that did not install a
// new CA. reason is internal crypto/x509 or filesystem error text, never user
// input; it is sanitised anyway because it can embed a configured path.
func noteClusterCARotationFailure(reason string) {
	statClusterCARotationFailures.Add(1)
	noteClusterCAFault("cluster CA auto-rotation failed: " + reason)
}

// noteClusterCASignRefused records a node-certificate signing refused because
// the CA is outside its own validity window. This is the customer-visible half:
// each one is an enrollment or a renewal that did not happen.
func noteClusterCASignRefused(reason string) {
	statClusterCASignRefused.Add(1)
	noteClusterCAFault("cluster CA refused to sign a node certificate: " + reason)
}

// noteClusterCAFault is the shared sink: count (done by the callers), remember,
// then log and alert on independent rate gates.
func noteClusterCAFault(detail string) {
	detail = sanitizeLog(detail)
	now := time.Now()

	clusterCAFaults.mu.Lock()
	clusterCAFaults.last = now
	clusterCAFaults.lastReason = detail
	clusterCAFaults.degraded = true
	logNow := now.Sub(clusterCAFaults.lastLog) >= clusterCAAlertInterval || clusterCAFaults.lastLog.IsZero()
	if logNow {
		clusterCAFaults.lastLog = now
	}
	alertNow := now.Sub(clusterCAFaults.lastAlert) >= clusterCAAlertInterval || clusterCAFaults.lastAlert.IsZero()
	if alertNow {
		clusterCAFaults.lastAlert = now
	}
	clusterCAFaults.mu.Unlock()

	if logNow {
		logger.Printf("ClusterCA: DEGRADED — %q (rotation failures %d, sign refusals %d since boot)",
			detail, statClusterCARotationFailures.Load(), statClusterCASignRefused.Load())
	}
	if alertNow {
		fireClusterCAAlert(detail)
	}
}

// noteClusterCARotationSuccess clears the degraded state on EVIDENCE. Called
// from the ImportCA chokepoint, which is the only way a new CA is installed, so
// a manual operator import counts as recovery exactly like an auto-rotation.
func noteClusterCARotationSuccess() {
	clusterCAFaults.mu.Lock()
	was := clusterCAFaults.degraded
	clusterCAFaults.degraded = false
	clusterCAFaults.lastReason = ""
	clusterCAFaults.lastOK = time.Now()
	clusterCAFaults.mu.Unlock()

	if was {
		logger.Printf("ClusterCA: recovered — a new CA was installed and persisted")
	}
}

// clusterCADegraded reports the CURRENT state for the admin API.
func clusterCADegraded() (bool, string, time.Time) {
	clusterCAFaults.mu.Lock()
	defer clusterCAFaults.mu.Unlock()
	return clusterCAFaults.degraded, clusterCAFaults.lastReason, clusterCAFaults.last
}

// resetClusterCAHealthForTest isolates the process-global record between tests.
func resetClusterCAHealthForTest() {
	statClusterCARotationFailures.Store(0)
	statClusterCASignRefused.Store(0)
	// Reset FIELDS, never the struct: assigning a zero clusterCAHealth would
	// replace the mutex being held and unlock a different one.
	clusterCAFaults.mu.Lock()
	clusterCAFaults.last = time.Time{}
	clusterCAFaults.lastReason = ""
	clusterCAFaults.lastOK = time.Time{}
	clusterCAFaults.degraded = false
	clusterCAFaults.lastLog = time.Time{}
	clusterCAFaults.lastAlert = time.Time{}
	clusterCAFaults.mu.Unlock()
}

// clusterCAWritePrometheus appends the cluster-CA health series. Called from
// caWritePrometheus alongside the Root-CA usability writer.
//
// culvert_cluster_ca_expires_in_seconds is the one to alert on WELL before the
// cliff: auto-rotation triggers at 30 days, so this series falling below ~30
// days and staying there means rotation is not working, whatever the reason.
// The rest confirm the cliff was hit.
func clusterCAWritePrometheus(w *strings.Builder) {
	w.WriteString("\n# HELP culvert_cluster_ca_rotation_failures_total Cluster CA auto-rotation attempts that failed to install a new CA\n")
	w.WriteString("# TYPE culvert_cluster_ca_rotation_failures_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_ca_rotation_failures_total %d\n", statClusterCARotationFailures.Load())

	w.WriteString("\n# HELP culvert_cluster_ca_sign_refused_total Node CSRs refused because the cluster CA is outside its own validity window\n")
	w.WriteString("# TYPE culvert_cluster_ca_sign_refused_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_ca_sign_refused_total %d\n", statClusterCASignRefused.Load())

	// Both gauges are omitted entirely when no cluster CA is loaded — this is
	// a CP-only subsystem, and a DP-only node emitting cluster_ca_usable 0
	// would page an operator for a CA it is not supposed to have.
	if !globalClusterCA.Ready() {
		return
	}
	usable := 0
	if globalClusterCA.Usable() == nil {
		usable = 1
	}
	w.WriteString("\n# HELP culvert_cluster_ca_usable Whether the cluster CA can currently issue node certificates that verify (1) or not (0)\n")
	w.WriteString("# TYPE culvert_cluster_ca_usable gauge\n")
	fmt.Fprintf(w, "culvert_cluster_ca_usable %d\n", usable)

	if exp, ok := globalClusterCA.expiresAt(); ok {
		w.WriteString("\n# HELP culvert_cluster_ca_expires_in_seconds Seconds until the cluster CA certificate expires (negative once expired)\n")
		w.WriteString("# TYPE culvert_cluster_ca_expires_in_seconds gauge\n")
		fmt.Fprintf(w, "culvert_cluster_ca_expires_in_seconds %d\n", int64(time.Until(exp).Seconds()))
	}
}
