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
)

// caWritePrometheus appends culvert_cert_cache_* metric lines. Called from
// handleMetrics alongside the per-rule, latency, urlcat, and CDR writers.
// Reads live state at scrape time via certMgr.CacheStats(); no hot-path cost.
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
}
