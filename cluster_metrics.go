package main

// cluster_metrics.go — CL-9 cluster / HA / enrollment observability.
//
// PR1 surfaces enrollment token outcomes and node-count gauges. Operators
// previously relied on the audit ring and apiClusterStatus polling to tell
// whether enrollment was succeeding or how many nodes were connected.
//
// Labels are deliberately absent. Per the CL-9 contract, no node IDs, tokens,
// hashes, source IPs, hostnames, or other user-controlled strings appear in any
// metric — only aggregate counts.

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Enrollment token-outcome counters (CL-9 PR1). Incremented inside
// ClusterStore.ValidateAndConsumeToken via a deferred result check: every
// validation/persist error counts a failure, a successful consume counts one.
var (
	statEnrollTokensConsumed atomic.Int64
	statEnrollFailures       atomic.Int64
)

// clusterWritePrometheus appends culvert_enrollment_* metric lines. Called from
// handleMetrics alongside the per-rule, latency, urlcat, CA, and CDR writers.
// Node counts are read live at scrape time via ClusterStore.NodeCounts().
func clusterWritePrometheus(w *strings.Builder) {
	var total, connected int
	if globalClusterStore != nil {
		total, connected = globalClusterStore.NodeCounts()
	}

	w.WriteString("\n# HELP culvert_enrollment_tokens_consumed_total Enrollment tokens successfully consumed\n")
	w.WriteString("# TYPE culvert_enrollment_tokens_consumed_total counter\n")
	fmt.Fprintf(w, "culvert_enrollment_tokens_consumed_total %d\n", statEnrollTokensConsumed.Load())

	w.WriteString("\n# HELP culvert_enrollment_failures_total Enrollment token validation failures (invalid/used/expired/prefix/CIDR/persist)\n")
	w.WriteString("# TYPE culvert_enrollment_failures_total counter\n")
	fmt.Fprintf(w, "culvert_enrollment_failures_total %d\n", statEnrollFailures.Load())

	w.WriteString("\n# HELP culvert_enrollment_nodes Current number of enrolled nodes\n")
	w.WriteString("# TYPE culvert_enrollment_nodes gauge\n")
	fmt.Fprintf(w, "culvert_enrollment_nodes %d\n", total)

	w.WriteString("\n# HELP culvert_enrollment_nodes_connected Enrolled nodes currently connected\n")
	w.WriteString("# TYPE culvert_enrollment_nodes_connected gauge\n")
	fmt.Fprintf(w, "culvert_enrollment_nodes_connected %d\n", connected)
}
