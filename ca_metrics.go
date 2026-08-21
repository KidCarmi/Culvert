package main

// ca_metrics.go — CA-2 observability for the CertManager leaf-cert cache.
//
// The MITM leaf cache (ca.go) signs a per-host leaf on a miss and serves it
// from an LRU cache on subsequent requests. Its effectiveness was previously
// invisible: handleMetrics surfaced no cert/CA metrics at all. This exposes the
// hit/miss counters and current size.
//
// Labels are deliberately absent. Per the CA-2 contract, no SNI host, SAN,
// subject, serial, fingerprint, or key material appears in any metric — the
// host drives the cache key but is never emitted. Only counts are rendered.

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// CA rotation counters (CA-2 PR3). Label-free; incremented only on real
// rotation success paths — never on startup/InitCA. No fingerprints, serials,
// subjects, SANs, key material, or node IDs are recorded.
var (
	statCARotations        atomic.Int64 // Root CA rotations (auto RotateIfNeeded + manual apiCARotate)
	statClusterCARotations atomic.Int64 // Cluster CA rotations/imports (ImportCA chokepoint)
)

// caWritePrometheus appends culvert_cert_cache_* and culvert_*_ca_rotations_*
// metric lines. Called from handleMetrics alongside the per-rule, latency,
// urlcat, and CDR writers. Reads live state at scrape time via
// certMgr.CacheStats(); no hot-path cost.
func caWritePrometheus(w *strings.Builder) {
	hits, misses, size := certMgr.CacheStats()

	w.WriteString("\n# HELP culvert_cert_cache_hits_total Leaf-cert cache hits (cached cert served without re-signing)\n")
	w.WriteString("# TYPE culvert_cert_cache_hits_total counter\n")
	fmt.Fprintf(w, "culvert_cert_cache_hits_total %d\n", hits)

	w.WriteString("\n# HELP culvert_cert_cache_misses_total Leaf-cert cache misses (request fell through to signing)\n")
	w.WriteString("# TYPE culvert_cert_cache_misses_total counter\n")
	fmt.Fprintf(w, "culvert_cert_cache_misses_total %d\n", misses)

	w.WriteString("\n# HELP culvert_cert_cache_size Current number of cached leaf certificates\n")
	w.WriteString("# TYPE culvert_cert_cache_size gauge\n")
	fmt.Fprintf(w, "culvert_cert_cache_size %d\n", size)

	w.WriteString("\n# HELP culvert_ca_rotations_total Root CA rotations (auto-renewal and manual admin rotation)\n")
	w.WriteString("# TYPE culvert_ca_rotations_total counter\n")
	fmt.Fprintf(w, "culvert_ca_rotations_total %d\n", statCARotations.Load())

	w.WriteString("\n# HELP culvert_cluster_ca_rotations_total Cluster CA rotations/imports (auto-renewal and manual import)\n")
	w.WriteString("# TYPE culvert_cluster_ca_rotations_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_ca_rotations_total %d\n", statClusterCARotations.Load())

	caWriteUsabilityPrometheus(w)
	clusterCAWritePrometheus(w)
}

// clusterCAWritePrometheus appends the CHAOS-50 cluster-CA usability series.
//
// The gap these close: before them, `culvert_cluster_ca_rotations_total` was the
// ONLY cluster-CA series, and it counts successes — so a control plane whose CA
// directory had gone read-only, and whose rotation had therefore failed every
// day for a month, was indistinguishable on /metrics from one that simply had
// not needed to rotate yet. Both read 0. There was no expiry series at all, so
// nothing an alerting rule could evaluate ahead of the cliff, and the cliff
// itself (a fleet-wide mTLS trust failure) moved no counter either.
//
// culvert_cluster_ca_expires_in_seconds is the one to alert on well before the
// cliff; culvert_cluster_ca_rotation_failures_total is the one that says the
// automatic remedy is not working, which is the actionable signal. The rest
// confirm the cliff was reached.
//
// Label-free, per the CA-2 metrics contract: no node ID, subject, serial,
// fingerprint, or key material — counts and one time delta only.
func clusterCAWritePrometheus(w *strings.Builder) {
	snap := clusterCAFailures()

	// BOTH gauges are omitted entirely when no cluster CA is loaded — the common
	// case on a single-node appliance or any data-plane node.
	//
	// The `usable` gauge needs this as much as the expiry one, and getting it
	// wrong is worse: Usable() returns the "no cluster CA loaded" error on such a
	// node, so an unconditional gauge reads `culvert_cluster_ca_usable 0` —
	// indistinguishable from an expired CA on a real control plane. The runbook's
	// recommended paging rule is literally `culvert_cluster_ca_usable == 0`, so
	// that would page for every node in the estate that legitimately has no
	// signing CA, exactly contradicting the runbook's promise that these rules do
	// not fire outside a cluster.
	//
	// An absent series is the honest encoding of "this node has no cluster CA":
	// the question does not apply, rather than having the answer "broken". Same
	// reasoning as `culvert_ca_expires_in_seconds` in CHAOS-28, where 0 would
	// have read as "expires now".
	//
	// The COUNTERS below stay unconditional on purpose: a counter resting at 0 is
	// the normal, non-alerting state and keeping the series present means rate()
	// and increase() work from the first scrape rather than starting on the first
	// fault.
	if exp := globalClusterCA.Expiry(); !exp.IsZero() {
		w.WriteString("\n# HELP culvert_cluster_ca_usable Whether the cluster CA can currently sign node certificates peers will accept (1 = yes)\n")
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

	w.WriteString("\n# HELP culvert_cluster_ca_sign_refused_total Node-certificate issuances refused because the cluster CA was outside its validity window\n")
	w.WriteString("# TYPE culvert_cluster_ca_sign_refused_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_ca_sign_refused_total %d\n", snap.SignRefusals)

	w.WriteString("\n# HELP culvert_cluster_ca_node_certs_clamped_total Node certificates whose validity was clamped to the cluster CA's own expiry\n")
	w.WriteString("# TYPE culvert_cluster_ca_node_certs_clamped_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_ca_node_certs_clamped_total %d\n", snap.ClampedIssuances)

	w.WriteString("\n# HELP culvert_cluster_ca_rotation_failures_total Cluster CA auto-rotation attempts that failed\n")
	w.WriteString("# TYPE culvert_cluster_ca_rotation_failures_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_ca_rotation_failures_total %d\n", snap.RotationFailures)
}

// caWriteUsabilityPrometheus appends the CHAOS-28 Root-CA usability series.
//
// The gap these close: before them, an expired inspection CA moved NOTHING an
// operator could scrape. `culvert_ca_rotations_total` only counts successes,
// the cache counters kept ticking (the engine happily signed unusable leaves),
// and there was no expiry series at all — CA expiry was visible only as
// `ca_expires_days` inside the proxy's /health JSON body, which no alerting rule
// evaluates. `culvert_ca_expires_in_seconds` is the one an operator should
// alert on WELL before the cliff; the rest are for confirming the cliff was hit.
//
// Label-free, per the CA-2 metrics contract: no SNI host, SAN, subject, serial,
// fingerprint, or key material — counts and one time delta only.
func caWriteUsabilityPrometheus(w *strings.Builder) {
	snap := caUsabilityFailures()

	w.WriteString("\n# HELP culvert_ca_usable Whether the Root CA can currently sign a leaf clients will accept (1 = yes)\n")
	w.WriteString("# TYPE culvert_ca_usable gauge\n")
	usable := 0
	if certMgr.Usable() == nil {
		usable = 1
	}
	fmt.Fprintf(w, "culvert_ca_usable %d\n", usable)

	// Omitted entirely when no CA is loaded — an absent series is honest,
	// whereas 0 would read as "expires now" and page on every CA-less node.
	if exp := certMgr.CAExpiry(); !exp.IsZero() {
		w.WriteString("\n# HELP culvert_ca_expires_in_seconds Seconds until the Root CA certificate expires (negative once expired)\n")
		w.WriteString("# TYPE culvert_ca_expires_in_seconds gauge\n")
		fmt.Fprintf(w, "culvert_ca_expires_in_seconds %d\n", int64(time.Until(exp).Seconds()))
	}

	w.WriteString("\n# HELP culvert_ca_sign_refused_total Leaf-sign attempts refused because the Root CA was outside its validity window\n")
	w.WriteString("# TYPE culvert_ca_sign_refused_total counter\n")
	fmt.Fprintf(w, "culvert_ca_sign_refused_total %d\n", certMgr.SignRefusals())

	w.WriteString("\n# HELP culvert_ca_inspect_blocked_total CONNECTs failed closed because the Root CA could not produce a usable leaf\n")
	w.WriteString("# TYPE culvert_ca_inspect_blocked_total counter\n")
	fmt.Fprintf(w, "culvert_ca_inspect_blocked_total %d\n", snap.Blocks)

	w.WriteString("\n# HELP culvert_ca_rotation_persist_failures_total Rotations that generated a new Root CA but could not write it to disk\n")
	w.WriteString("# TYPE culvert_ca_rotation_persist_failures_total counter\n")
	fmt.Fprintf(w, "culvert_ca_rotation_persist_failures_total %d\n", snap.PersistFailures)

	caWriteLoadFailurePrometheus(w)
}

// caWriteLoadFailurePrometheus appends the CHAOS-50 Root-CA load/recovery
// series — the FAIL-OPEN half of the CA fault surface.
//
// culvert_ca_usable already covers the fail-CLOSED direction (a CA that is
// loaded but outside its validity window). It cannot cover this one: when the
// bundle never loaded there is no CA to ask, so `culvert_ca_usable` reports 0
// and `culvert_ca_expires_in_seconds` is omitted — indistinguishable from a
// node that was never configured to inspect at all. The three series here say
// which it is, whether the appliance is still trying to recover, and how much
// traffic has left uninspected in the meantime.
//
// Label-free, per the CA-2 metrics contract.
func caWriteLoadFailurePrometheus(w *strings.Builder) {
	w.WriteString("\n# HELP culvert_ca_load_failed Whether a configured Root CA failed to load or persist and has not recovered (1 = failed)\n")
	w.WriteString("# TYPE culvert_ca_load_failed gauge\n")
	failed := 0
	if sslInspectionLoadFailure() != "" {
		failed = 1
	}
	fmt.Fprintf(w, "culvert_ca_load_failed %d\n", failed)

	rec := caLoadRecoveryStatus()
	w.WriteString("\n# HELP culvert_ca_load_recovery_attempts_total Bounded retry attempts made to recover a failed Root CA load\n")
	w.WriteString("# TYPE culvert_ca_load_recovery_attempts_total counter\n")
	fmt.Fprintf(w, "culvert_ca_load_recovery_attempts_total %d\n", rec.Attempts)

	w.WriteString("\n# HELP culvert_ca_inspect_bypassed_total CONNECTs policy selected for inspection that were forwarded UNINSPECTED because no Root CA was loaded\n")
	w.WriteString("# TYPE culvert_ca_inspect_bypassed_total counter\n")
	fmt.Fprintf(w, "culvert_ca_inspect_bypassed_total %d\n", caInspectBypassCount())
}
