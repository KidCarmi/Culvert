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

// Liveness + persistence counters (CL-9 PR2). statHeartbeatDisconnects counts
// connected→disconnected transitions in the heartbeat liveness check;
// statClusterStoreSaves counts successful ClusterStore persists, incremented in
// saveLocked() so every save path (Save() and all direct saveLocked() callers)
// is covered by one chokepoint.
var (
	statHeartbeatDisconnects atomic.Int64
	statClusterStoreSaves    atomic.Int64
)

// HA failover counter (CL-9 PR3). Incremented only on a successful standby→
// leader promotion (HAState.promote); the initial EnableAsLeader and failed
// promotions are not counted.
var statHAFailovers atomic.Int64

// dpPollHist records DP→CP config-poll latency (CL-9 PR4). Observed only on a
// successful primary methodGetConfig call in fetchAndApply (DP-node-only); a
// CP/standalone node simply renders zero observations. Reuses the generalized
// histogram from CA-2 PR2. Buckets span the intra-cluster fast path AND the
// slow-WAN large-snapshot tail (P1 #4): a 2 M-host config on a thin link can
// take tens of seconds, so buckets extend to 120s to keep those polls out of
// +Inf and make WAN-starved DPs visible before they trip the failover path.
var dpPollHist = newHistogram(
	"culvert_dp_poll_duration_seconds",
	"Data-plane → control-plane config poll latency",
	[]float64{0.005, 0.025, 0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120},
)

// haRoleCode maps the HA role string to a fixed numeric gauge value, so the
// state is exposed without a role= label: 0=disabled, 1=leader, 2=standby.
func haRoleCode() int {
	switch globalHA.Status().Role {
	case "leader":
		return 1
	case "standby":
		return 2
	default:
		return 0
	}
}

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

	w.WriteString("\n# HELP culvert_heartbeat_disconnects_total Node connected→disconnected transitions detected by the heartbeat monitor\n")
	w.WriteString("# TYPE culvert_heartbeat_disconnects_total counter\n")
	fmt.Fprintf(w, "culvert_heartbeat_disconnects_total %d\n", statHeartbeatDisconnects.Load())

	w.WriteString("\n# HELP culvert_cluster_store_saves_total Successful ClusterStore persistence operations\n")
	w.WriteString("# TYPE culvert_cluster_store_saves_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_store_saves_total %d\n", statClusterStoreSaves.Load())

	w.WriteString("\n# HELP culvert_ha_role HA role of this control plane (0=disabled, 1=leader, 2=standby)\n")
	w.WriteString("# TYPE culvert_ha_role gauge\n")
	fmt.Fprintf(w, "culvert_ha_role %d\n", haRoleCode())

	w.WriteString("\n# HELP culvert_ha_failovers_total Standby→leader promotions (excludes the initial designated leader)\n")
	w.WriteString("# TYPE culvert_ha_failovers_total counter\n")
	fmt.Fprintf(w, "culvert_ha_failovers_total %d\n", statHAFailovers.Load())

	// P1 #4: last full config-snapshot size received by this DP. Paired with the
	// poll-duration histogram it lets an operator spot a WAN-starved node (large
	// bytes + long duration) before a timeout trips spurious failover.
	w.WriteString("\n# HELP culvert_dp_config_last_snapshot_bytes Size of the most recent full config snapshot received by this data-plane node\n")
	w.WriteString("# TYPE culvert_dp_config_last_snapshot_bytes gauge\n")
	fmt.Fprintf(w, "culvert_dp_config_last_snapshot_bytes %d\n", dpLastFullSnapshotBytes.Load())

	writeConfigSnapshotSizeMetrics(w)
	dpPollHist.WritePrometheus(w)
}

// writeConfigSnapshotSizeMetrics emits size-vs-cap gauges for EVERY capped
// ConfigSnapshot slice plus the aggregate and url_category-hosts bounds, so an
// operator can alert before ANY sync cap overflows — not just blocked_hosts.
// Sourced from the sizes cached at publish (recordPublishedSnapshotSizes), so a
// /metrics scrape never rebuilds the full snapshot. Absent until the first
// publish (CP nodes); the always-available culvert_blocklist_size covers
// blocked_hosts on non-publishing nodes.
func writeConfigSnapshotSizeMetrics(w *strings.Builder) {
	ps, ok := lastPublishedSnapshotSizes.Load().(publishedSnapshotSizes)
	if !ok {
		return
	}
	w.WriteString("\n# HELP culvert_config_snapshot_slice_entries Current entry count of a capped ConfigSnapshot slice (last published)\n")
	w.WriteString("# TYPE culvert_config_snapshot_slice_entries gauge\n")
	for _, s := range ps.Slices {
		fmt.Fprintf(w, "culvert_config_snapshot_slice_entries{slice=%q} %d\n", s.Name, s.Size)
	}
	fmt.Fprintf(w, "culvert_config_snapshot_slice_entries{slice=\"url_category_hosts\"} %d\n", ps.URLCatHosts)
	fmt.Fprintf(w, "culvert_config_snapshot_slice_entries{slice=\"aggregate_host_scale\"} %d\n", ps.Aggregate)

	w.WriteString("\n# HELP culvert_config_snapshot_slice_cap Hard cap (CP↔DP sync) of a capped ConfigSnapshot slice\n")
	w.WriteString("# TYPE culvert_config_snapshot_slice_cap gauge\n")
	for _, s := range ps.Slices {
		fmt.Fprintf(w, "culvert_config_snapshot_slice_cap{slice=%q} %d\n", s.Name, s.Cap)
	}
	fmt.Fprintf(w, "culvert_config_snapshot_slice_cap{slice=\"url_category_hosts\"} %d\n", ps.URLCatHostsCap)
	fmt.Fprintf(w, "culvert_config_snapshot_slice_cap{slice=\"aggregate_host_scale\"} %d\n", ps.AggregateCap)
}
