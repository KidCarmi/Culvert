package main

import (
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/shadowmetrics"
)

// mcpShadowMetrics is the Shadow evaluator's bounded telemetry sink, owned by
// internal/mcp/shadowmetrics (IM-011, ADR-0047). It implements execution.Metrics.
// Main owns the process-wide instance below and the nil gate on the read paths.
type mcpShadowMetrics = shadowmetrics.Sink

// shadowMetricsView is the bounded read-only snapshot for /metrics + status surfaces.
type shadowMetricsView = shadowmetrics.View

var (
	globalMCPShadowMetrics     *mcpShadowMetrics
	globalMCPShadowMetricsOnce sync.Once
)

// newMCPShadowMetrics returns the process-wide Shadow metrics singleton, so the sink the
// evaluator writes is the exact instance the /metrics + status surfaces read.
func newMCPShadowMetrics() *mcpShadowMetrics {
	globalMCPShadowMetricsOnce.Do(func() { globalMCPShadowMetrics = &mcpShadowMetrics{} })
	return globalMCPShadowMetrics
}

// mcpShadowMetricsSnapshotOrNil returns the current metrics singleton if it was ever
// constructed (i.e. Shadow readiness was requested this boot), else nil. Callers on the
// /metrics + status path use nil to mean "no shadow series to emit" so a node that never
// armed Shadow exposes nothing (an all-zero series would be indistinguishable from an
// idle armed node, and the paging rule for a security control is "> 0").
func mcpShadowMetricsSnapshotOrNil() *mcpShadowMetrics {
	return globalMCPShadowMetrics
}

// writeMCPShadowMetrics appends the bounded culvert_mcp_shadow_* series. It is called
// from the /metrics fan-out. Nothing is emitted on a node that never armed Shadow (a
// nil singleton) — an all-zero series would be indistinguishable from an idle armed node
// and a security-control paging rule is "> 0".
func writeMCPShadowMetrics(b *strings.Builder) {
	m := mcpShadowMetricsSnapshotOrNil()
	if m == nil {
		return
	}
	m.WritePrometheus(b)
}
