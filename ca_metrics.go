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
	clusterCAWriteUsabilityPrometheus(w)
}

// clusterCAWriteUsabilityPrometheus appends the CHAOS-50 cluster-CA usability
// series — the CHAOS-28 shape, applied to the enrollment trust root.
//
// The gap these close: before them, an expired cluster CA moved nothing an
// operator could scrape. `culvert_cluster_ca_rotations_total` only counts
// successes, and the cluster CA had no expiry series at all — so the terminal
// state (every data-plane node unable to enroll or renew, then unable to
// connect) was visible only as N per-node mTLS errors on N different machines.
// `culvert_cluster_ca_expires_in_seconds` is the one to alert on well before the
// cliff; the rest confirm the cliff was hit.
//
// Label-free, per the CA-2 metrics contract: no node ID, subject, serial,
// fingerprint, or key material — counts and one time delta only.
func clusterCAWriteUsabilityPrometheus(w *strings.Builder) {
	snap := clusterCAUsabilityFailures()

	w.WriteString("\n# HELP culvert_cluster_ca_usable Whether the cluster CA can currently issue a node certificate peers will accept (1 = yes)\n")
	w.WriteString("# TYPE culvert_cluster_ca_usable gauge\n")
	usable := 0
	if globalClusterCA.Usable() == nil {
		usable = 1
	}
	fmt.Fprintf(w, "culvert_cluster_ca_usable %d\n", usable)

	// Omitted entirely when no cluster CA is loaded — an absent series is
	// honest, whereas 0 would read as "expires now" and page on every data-plane
	// node (which never has one).
	if exp := globalClusterCA.Expiry(); !exp.IsZero() {
		w.WriteString("\n# HELP culvert_cluster_ca_expires_in_seconds Seconds until the cluster CA certificate expires (negative once expired)\n")
		w.WriteString("# TYPE culvert_cluster_ca_expires_in_seconds gauge\n")
		fmt.Fprintf(w, "culvert_cluster_ca_expires_in_seconds %d\n", int64(time.Until(exp).Seconds()))
	}

	w.WriteString("\n# HELP culvert_cluster_ca_sign_refused_total Node-cert issuance attempts refused because the cluster CA was outside its validity window\n")
	w.WriteString("# TYPE culvert_cluster_ca_sign_refused_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_ca_sign_refused_total %d\n", snap.Refusals)

	w.WriteString("\n# HELP culvert_cluster_ca_node_cert_clamped_total Node certificates whose lifetime was shortened to the issuing cluster CA's expiry\n")
	w.WriteString("# TYPE culvert_cluster_ca_node_cert_clamped_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_ca_node_cert_clamped_total %d\n", snap.Clamped)
}

// caWriteUsabilityPrometheus appends the CHAOS-28 Root-CA usability series.
//
// The gap these close: before them, an expired inspection CA moved NOTHING an
// operator could scrape. `culvert_ca_rotations_total` only counts successes,
// the cache counters kept ticking (the engine happily signed unusable leaves),
// and there was no expiry series at all — CA expiry was visible only as
// `ca_expires_days` inside the /healthz JSON body, which no alerting rule
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
}
