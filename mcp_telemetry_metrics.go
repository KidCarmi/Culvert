package main

// QUAL-3 — low-cardinality MCP data-plane telemetry metrics. Following the repo's
// hand-rolled exposition convention (no Prometheus client library), this emits a
// bounded set of culvert_mcp_* series at scrape time, projected live from the shared
// telemetry holder (events.Manager health + spool stats + archive exporter stats +
// export cursors). Every label is a FIXED closed enum — capability ∈ {gateway},
// partition ∈ {crit,ord,den}, result ∈ {ok,fail}, track ∈ {critical,denial} — so no
// cardinality cap is needed and no tenant / principal / server / tool / event id /
// path / free-form error ever appears as a label.

import (
	"fmt"
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/events"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// writeMCPTelemetryMetrics appends the culvert_mcp_* telemetry series. It is called
// from the /metrics fan-out in metrics.go. A readiness gauge is ALWAYS emitted (so
// operators can alert on telemetry_ready==0); the rest are emitted only when the
// telemetry runtime is composed.
func writeMCPTelemetryMetrics(b *strings.Builder) {
	rt := sharedTelemetry()

	b.WriteString("# HELP culvert_mcp_telemetry_ready MCP durable telemetry readiness (1=ready).\n")
	b.WriteString("# TYPE culvert_mcp_telemetry_ready gauge\n")
	fmt.Fprintf(b, "culvert_mcp_telemetry_ready{capability=\"gateway\"} %d\n", boolMetric(rt != nil))
	if rt == nil {
		return
	}
	h := rt.mgr.Health()
	d, ok := h.Domains[evmodel.CapGateway]
	if !ok {
		return
	}
	writeMCPCommitMetrics(b, d)
	writeMCPSpoolMetrics(b, d)
	writeMCPExportMetrics(b, rt)
	writeMCPDegradedMetrics(b, d)
}

// writeMCPCommitMetrics emits per-capability commit/loss/aggregate counters.
func writeMCPCommitMetrics(b *strings.Builder, d mcpDomainHealth) {
	b.WriteString("# HELP culvert_mcp_event_commits_total MCP durable event commits by result.\n")
	b.WriteString("# TYPE culvert_mcp_event_commits_total counter\n")
	fmt.Fprintf(b, "culvert_mcp_event_commits_total{capability=\"gateway\",result=\"ok\"} %d\n", d.CommitOK)
	fmt.Fprintf(b, "culvert_mcp_event_commits_total{capability=\"gateway\",result=\"fail\"} %d\n", d.CommitFail)

	b.WriteString("# HELP culvert_mcp_ordinary_loss_total MCP ordinary (P-ORD) events lost under the accepted loss policy.\n")
	b.WriteString("# TYPE culvert_mcp_ordinary_loss_total counter\n")
	fmt.Fprintf(b, "culvert_mcp_ordinary_loss_total{capability=\"gateway\"} %d\n", d.OrdinaryLoss)

	b.WriteString("# HELP culvert_mcp_denial_loss_total MCP denial aggregates lost (denial-lane degraded).\n")
	b.WriteString("# TYPE culvert_mcp_denial_loss_total counter\n")
	fmt.Fprintf(b, "culvert_mcp_denial_loss_total{capability=\"gateway\"} %d\n", d.DenialLoss)

	b.WriteString("# HELP culvert_mcp_denial_aggregates_total MCP denial aggregates durably committed to P-DEN.\n")
	b.WriteString("# TYPE culvert_mcp_denial_aggregates_total counter\n")
	fmt.Fprintf(b, "culvert_mcp_denial_aggregates_total{capability=\"gateway\"} %d\n", d.DenialAggregates)
}

// writeMCPSpoolMetrics emits per-partition committed bytes/records/quota + reserve.
func writeMCPSpoolMetrics(b *strings.Builder, d mcpDomainHealth) {
	b.WriteString("# HELP culvert_mcp_spool_bytes MCP encrypted spool bytes committed per partition.\n")
	b.WriteString("# TYPE culvert_mcp_spool_bytes gauge\n")
	b.WriteString("# HELP culvert_mcp_spool_records MCP committed records per partition.\n")
	b.WriteString("# TYPE culvert_mcp_spool_records gauge\n")
	b.WriteString("# HELP culvert_mcp_spool_quota_bytes MCP per-partition byte quota.\n")
	b.WriteString("# TYPE culvert_mcp_spool_quota_bytes gauge\n")
	for _, part := range gatewayPartitions {
		ps := d.Spool.Partitions[part]
		p := telemPartitionName(part)
		fmt.Fprintf(b, "culvert_mcp_spool_bytes{capability=\"gateway\",partition=%q} %d\n", p, ps.Bytes)
		fmt.Fprintf(b, "culvert_mcp_spool_records{capability=\"gateway\",partition=%q} %d\n", p, ps.Records)
		fmt.Fprintf(b, "culvert_mcp_spool_quota_bytes{capability=\"gateway\",partition=%q} %d\n", p, ps.Quota)
	}
	b.WriteString("# HELP culvert_mcp_critical_reserve_free_bytes MCP P-CRIT reserve headroom in bytes.\n")
	b.WriteString("# TYPE culvert_mcp_critical_reserve_free_bytes gauge\n")
	fmt.Fprintf(b, "culvert_mcp_critical_reserve_free_bytes{capability=\"gateway\"} %d\n", d.Spool.CriticalFreeBytes)
}

// writeMCPExportMetrics emits archive exporter counters + per-partition lag.
func writeMCPExportMetrics(b *strings.Builder, rt *telemetryRuntime) {
	es := rt.exporter.stats()
	b.WriteString("# HELP culvert_mcp_export_batches_total MCP archive export batches by result.\n")
	b.WriteString("# TYPE culvert_mcp_export_batches_total counter\n")
	fmt.Fprintf(b, "culvert_mcp_export_batches_total{capability=\"gateway\",result=\"ok\"} %d\n", es.BatchesOK)
	fmt.Fprintf(b, "culvert_mcp_export_batches_total{capability=\"gateway\",result=\"fail\"} %d\n", es.Failures)

	b.WriteString("# HELP culvert_mcp_export_events_total MCP safe events durably archived.\n")
	b.WriteString("# TYPE culvert_mcp_export_events_total counter\n")
	fmt.Fprintf(b, "culvert_mcp_export_events_total{capability=\"gateway\"} %d\n", es.ExportedEvents)

	b.WriteString("# HELP culvert_mcp_export_saturated MCP archive at capacity (1=saturated).\n")
	b.WriteString("# TYPE culvert_mcp_export_saturated gauge\n")
	fmt.Fprintf(b, "culvert_mcp_export_saturated{capability=\"gateway\"} %d\n", boolMetric(es.Saturated))

	b.WriteString("# HELP culvert_mcp_last_export_timestamp_seconds MCP last successful archive export (unix seconds).\n")
	b.WriteString("# TYPE culvert_mcp_last_export_timestamp_seconds gauge\n")
	fmt.Fprintf(b, "culvert_mcp_last_export_timestamp_seconds{capability=\"gateway\"} %d\n", es.LastOKUnixNano/1e9)

	b.WriteString("# HELP culvert_mcp_export_lag MCP export lag in sequence space per partition.\n")
	b.WriteString("# TYPE culvert_mcp_export_lag gauge\n")
	for _, part := range gatewayPartitions {
		fmt.Fprintf(b, "culvert_mcp_export_lag{capability=\"gateway\",partition=%q} %d\n", telemPartitionName(part), rt.exportLag(part))
	}
}

// writeMCPDegradedMetrics emits the per-track degraded gauges (critical/denial).
func writeMCPDegradedMetrics(b *strings.Builder, d mcpDomainHealth) {
	b.WriteString("# HELP culvert_mcp_degraded MCP durability track degraded (1=degraded).\n")
	b.WriteString("# TYPE culvert_mcp_degraded gauge\n")
	fmt.Fprintf(b, "culvert_mcp_degraded{capability=\"gateway\",track=\"critical\"} %d\n", boolMetric(d.CriticalState != "normal"))
	fmt.Fprintf(b, "culvert_mcp_degraded{capability=\"gateway\",track=\"denial\"} %d\n", boolMetric(d.DenialState != "normal"))
}

// mcpDomainHealth aliases the events domain health for a shorter local signature.
type mcpDomainHealth = events.DomainHealth

func boolMetric(v bool) int {
	if v {
		return 1
	}
	return 0
}
