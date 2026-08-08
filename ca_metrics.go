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

	// CHAOS-30. Root CA expiry was previously alertable only through
	// /health's ca_expires_days, which folds "no CA loaded" and "expired" into
	// the same -1. A signed gauge states both facts unambiguously and lets an
	// operator alert on the slope, not just the threshold. Omitted entirely
	// when no CA is loaded — an absent series is honest about "SSL inspection
	// is not configured"; a 0 or -1 would not be (same posture as
	// culvert_release_catalog_expires_in_seconds).
	if expiry := certMgr.CAExpiry(); !expiry.IsZero() {
		w.WriteString("\n# HELP culvert_ca_expires_in_seconds Seconds until the SSL-inspection Root CA expires (negative once expired)\n")
		w.WriteString("# TYPE culvert_ca_expires_in_seconds gauge\n")
		fmt.Fprintf(w, "culvert_ca_expires_in_seconds %d\n", int64(time.Until(expiry).Seconds()))
	}

	// Any non-zero value means an inspected TLS handshake could not be served
	// a leaf — the fail-closed refusals (expired / absent CA) plus genuine
	// signing errors. This is the server-side signal that used to exist only
	// as an opaque client-side chain error.
	w.WriteString("\n# HELP culvert_ca_sign_failures_total Leaf-certificate signs refused or failed (expired/absent Root CA, signing errors)\n")
	w.WriteString("# TYPE culvert_ca_sign_failures_total counter\n")
	fmt.Fprintf(w, "culvert_ca_sign_failures_total %d\n", certMgr.SignFailures())
}
