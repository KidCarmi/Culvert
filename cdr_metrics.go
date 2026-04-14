package main

// Prometheus metrics for the Sluice CDR integration.
//
// Two layers:
//   1. Package-level atomic counters — incremented on the hot path from
//      cdr_proxy.go and cdr.go.  Zero allocation per increment.
//   2. WritePrometheus helpers called by the /metrics handler to convert
//      counters into text exposition.
//
// Labels are deliberately low-cardinality.  No policy_version, no user_id,
// no filename, no destination host — per the Culvert↔Sluice contract.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// ─── Raw counters ──────────────────────────────────────────────────────────
//
// Exported as package-level vars so tests can reset them between cases and
// cdr.go / cdr_proxy.go can increment cheaply without going through a mutex.

var (
	// Terminal decisions.
	statCDRClean       int64
	statCDRSanitized   int64
	statCDRBlocked     int64
	statCDRUnsupported int64

	// Operational.
	statCDROversizeSkipped int64 // Culvert-side oversize gate OR Sluice file_too_large
	statCDRErrors          int64 // network / Sluice ERROR / transport fault
	statCDRFailOpen        int64 // errors that fell open per cfg
	statCDRFailClosed      int64 // errors that blocked per cfg
	statCDRPanics          int64 // caught by the defer-recover in safeCDRSanitize

	// Cache.
	statCDRCacheHits   int64
	statCDRCacheMisses int64

	// Bytes (request body → Sluice; sanitized bytes received).
	statCDRBytesIn  int64
	statCDRBytesOut int64

	// Per-threat-type counters — low cardinality, stable vocabulary.
	threatCountersMu sync.Mutex
	threatCounters   = make(map[string]int64) // "macro" -> count
)

// recordThreatDetections increments the per-type counter for each threat
// in `ts`.  Capped at 64 distinct types to prevent cardinality blow-ups.
func recordThreatDetections(ts []CDRThreat) {
	if len(ts) == 0 {
		return
	}
	threatCountersMu.Lock()
	defer threatCountersMu.Unlock()
	for _, t := range ts {
		if len(threatCounters) >= 64 {
			if _, ok := threatCounters[t.Type]; !ok {
				continue // cap reached, don't add new keys
			}
		}
		threatCounters[t.Type]++
	}
}

// recordCDRTerminal increments the matching terminal-decision counter.
func recordCDRTerminal(status string) {
	switch status {
	case "CLEAN":
		atomic.AddInt64(&statCDRClean, 1)
	case "SANITIZED":
		atomic.AddInt64(&statCDRSanitized, 1)
	case "BLOCKED":
		atomic.AddInt64(&statCDRBlocked, 1)
	case "UNSUPPORTED":
		atomic.AddInt64(&statCDRUnsupported, 1)
	}
}

// ─── Prometheus exposition ─────────────────────────────────────────────────

// cdrWritePrometheus appends culvert_cdr_* metric lines to the builder.
// Called from handleMetrics in metrics.go alongside the per-rule and
// latency-histogram writers.
func cdrWritePrometheus(w *strings.Builder) {
	// Terminal decisions.
	w.WriteString("\n# HELP culvert_cdr_files_processed_total Files processed by the CDR engine, keyed on terminal status\n")
	w.WriteString("# TYPE culvert_cdr_files_processed_total counter\n")
	fmt.Fprintf(w, "culvert_cdr_files_processed_total{status=\"clean\"} %d\n", atomic.LoadInt64(&statCDRClean))
	fmt.Fprintf(w, "culvert_cdr_files_processed_total{status=\"sanitized\"} %d\n", atomic.LoadInt64(&statCDRSanitized))
	fmt.Fprintf(w, "culvert_cdr_files_processed_total{status=\"blocked\"} %d\n", atomic.LoadInt64(&statCDRBlocked))
	fmt.Fprintf(w, "culvert_cdr_files_processed_total{status=\"unsupported\"} %d\n", atomic.LoadInt64(&statCDRUnsupported))

	// Operational.
	w.WriteString("\n# HELP culvert_cdr_oversize_skipped_total Requests where CDR was skipped because the body exceeded the per-file cap\n")
	w.WriteString("# TYPE culvert_cdr_oversize_skipped_total counter\n")
	fmt.Fprintf(w, "culvert_cdr_oversize_skipped_total %d\n", atomic.LoadInt64(&statCDROversizeSkipped))

	w.WriteString("\n# HELP culvert_cdr_errors_total Transport or Sluice-reported errors\n")
	w.WriteString("# TYPE culvert_cdr_errors_total counter\n")
	fmt.Fprintf(w, "culvert_cdr_errors_total %d\n", atomic.LoadInt64(&statCDRErrors))

	w.WriteString("\n# HELP culvert_cdr_fail_open_total Errors that passed the original file through per fail_mode=open\n")
	w.WriteString("# TYPE culvert_cdr_fail_open_total counter\n")
	fmt.Fprintf(w, "culvert_cdr_fail_open_total %d\n", atomic.LoadInt64(&statCDRFailOpen))

	w.WriteString("\n# HELP culvert_cdr_fail_closed_total Errors that blocked the response per fail_mode=closed\n")
	w.WriteString("# TYPE culvert_cdr_fail_closed_total counter\n")
	fmt.Fprintf(w, "culvert_cdr_fail_closed_total %d\n", atomic.LoadInt64(&statCDRFailClosed))

	w.WriteString("\n# HELP culvert_cdr_panics_total Panics caught by the CDR defer-recover (always fail-closed regardless of fail_mode)\n")
	w.WriteString("# TYPE culvert_cdr_panics_total counter\n")
	fmt.Fprintf(w, "culvert_cdr_panics_total %d\n", atomic.LoadInt64(&statCDRPanics))

	// Cache.
	hits, misses, size := cdrCache.Stats()
	w.WriteString("\n# HELP culvert_cdr_cache_hits_total Hash cache hits (decision reused without calling Sluice)\n")
	w.WriteString("# TYPE culvert_cdr_cache_hits_total counter\n")
	fmt.Fprintf(w, "culvert_cdr_cache_hits_total %d\n", hits)

	w.WriteString("\n# HELP culvert_cdr_cache_misses_total Hash cache misses — required a Sluice call\n")
	w.WriteString("# TYPE culvert_cdr_cache_misses_total counter\n")
	fmt.Fprintf(w, "culvert_cdr_cache_misses_total %d\n", misses)

	w.WriteString("\n# HELP culvert_cdr_cache_size Current number of entries in the CDR hash cache\n")
	w.WriteString("# TYPE culvert_cdr_cache_size gauge\n")
	fmt.Fprintf(w, "culvert_cdr_cache_size %d\n", size)

	// Bytes.
	w.WriteString("\n# HELP culvert_cdr_bytes_in_total Bytes sent to Sluice for sanitisation (original file sizes)\n")
	w.WriteString("# TYPE culvert_cdr_bytes_in_total counter\n")
	fmt.Fprintf(w, "culvert_cdr_bytes_in_total %d\n", atomic.LoadInt64(&statCDRBytesIn))

	w.WriteString("\n# HELP culvert_cdr_bytes_out_total Sanitized bytes received from Sluice\n")
	w.WriteString("# TYPE culvert_cdr_bytes_out_total counter\n")
	fmt.Fprintf(w, "culvert_cdr_bytes_out_total %d\n", atomic.LoadInt64(&statCDRBytesOut))

	// Per-threat-type.
	threatCountersMu.Lock()
	if len(threatCounters) > 0 {
		w.WriteString("\n# HELP culvert_cdr_threats_detected_total Threats detected by type (capped at 64 distinct types)\n")
		w.WriteString("# TYPE culvert_cdr_threats_detected_total counter\n")
		for t, n := range threatCounters {
			safe := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(t)
			fmt.Fprintf(w, "culvert_cdr_threats_detected_total{type=%q} %d\n", safe, n)
		}
	}
	threatCountersMu.Unlock()
}
