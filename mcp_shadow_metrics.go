package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// mcpShadowMetrics is the bounded, low-cardinality telemetry sink for the non-executing
// Shadow evaluator (SHADOW-ACTIVATION.md §12). Every label is a FIXED enum — the eight
// Model-1 shadow outcomes — never a tenant, subject, server, tool, or argument, so the
// series cardinality is constant regardless of traffic. It implements execution.Metrics.
//
// It is the SAME instance the evaluator writes and the /metrics + health surfaces read
// (a process-wide singleton), so an operator watching a controlled activation sees the
// live evaluation counts without any cross-wiring.
type mcpShadowMetrics struct {
	evaluations              atomic.Int64 // total non-executing shadow evaluations
	wouldExecute             atomic.Int64
	wouldBlock               atomic.Int64
	wouldRequireApproval     atomic.Int64
	wouldRequireConfirmation atomic.Int64
	wouldFailCredential      atomic.Int64
	wouldFailInspection      atomic.Int64
	wouldFailStale           atomic.Int64
	wouldFailHardControl     atomic.Int64
	wouldOther               atomic.Int64 // fail-safe bucket for an unrecognised outcome
	// evaluationErrors counts a shadow evaluation that FAILED CLOSED (durable-evidence
	// commit failed, emergency kill, or an invalid mode reached the evaluator) — i.e. the
	// evaluator emitted a block rather than a verdict. It is NOT a would_block outcome.
	evaluationErrors atomic.Int64
}

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

// ── execution.Metrics ──────────────────────────────────────────────────────────

// ObserveShadowOutcome records one non-executing evaluation and its Model-1 verdict.
func (m *mcpShadowMetrics) ObserveShadowOutcome(_ string, outcome string) {
	m.evaluations.Add(1)
	switch outcome {
	case "would_execute":
		m.wouldExecute.Add(1)
	case "would_block":
		m.wouldBlock.Add(1)
	case "would_require_approval":
		m.wouldRequireApproval.Add(1)
	case "would_require_confirmation":
		m.wouldRequireConfirmation.Add(1)
	case "would_fail_credential_readiness":
		m.wouldFailCredential.Add(1)
	case "would_fail_inspection":
		m.wouldFailInspection.Add(1)
	case "would_fail_stale_decision":
		m.wouldFailStale.Add(1)
	case "would_fail_hard_control":
		m.wouldFailHardControl.Add(1)
	default:
		m.wouldOther.Add(1)
	}
}

// ObserveBlock counts a shadow evaluation that failed CLOSED (durability/kill/invalid
// mode) — the evaluator emitted a terminal block rather than a Model-1 verdict.
func (m *mcpShadowMetrics) ObserveBlock(string, mcperr.Reason) { m.evaluationErrors.Add(1) }

// ObserveResolution is a no-op for the shadow sink: the evaluation is counted
// authoritatively (with its verdict) by ObserveShadowOutcome, so counting the
// resolution too would double-count.
func (m *mcpShadowMetrics) ObserveResolution(string, rollout.Resolution) {}

// The remaining execution.Metrics methods describe LIVE-execution events the Shadow
// evaluator can never produce (it performs no upstream call, no DLP, no outcome event).
// They are no-ops; a non-zero value on any of them would itself be a bug.
func (m *mcpShadowMetrics) ObserveExecution(string, bool)     {}
func (m *mcpShadowMetrics) ObserveUpstream(string, string)    {}
func (m *mcpShadowMetrics) ObserveDLPBlock(string, bool)      {}
func (m *mcpShadowMetrics) ObserveOutcomeEvidenceLoss(string) {}

// shadowMetricsView is the bounded read-only snapshot for /metrics + status surfaces.
type shadowMetricsView struct {
	Evaluations              int64 `json:"evaluations"`
	WouldExecute             int64 `json:"would_execute"`
	WouldBlock               int64 `json:"would_block"`
	WouldRequireApproval     int64 `json:"would_require_approval"`
	WouldRequireConfirmation int64 `json:"would_require_confirmation"`
	WouldFailCredential      int64 `json:"would_fail_credential_readiness"`
	WouldFailInspection      int64 `json:"would_fail_inspection"`
	WouldFailStale           int64 `json:"would_fail_stale_decision"`
	WouldFailHardControl     int64 `json:"would_fail_hard_control"`
	WouldOther               int64 `json:"would_other"`
	EvaluationErrors         int64 `json:"evaluation_errors"`
}

// writeMCPShadowMetrics appends the bounded culvert_mcp_shadow_* series. It is called
// from the /metrics fan-out. Nothing is emitted on a node that never armed Shadow (a
// nil singleton) — an all-zero series would be indistinguishable from an idle armed node
// and a security-control paging rule is "> 0"; the outcome label is the only dimension,
// a fixed closed enum, so cardinality is constant.
func writeMCPShadowMetrics(b *strings.Builder) {
	m := mcpShadowMetricsSnapshotOrNil()
	if m == nil {
		return
	}
	v := m.snapshot()
	b.WriteString("# HELP culvert_mcp_shadow_evaluations_total MCP non-executing Shadow evaluations by Model-1 outcome.\n")
	b.WriteString("# TYPE culvert_mcp_shadow_evaluations_total counter\n")
	row := func(outcome string, n int64) {
		fmt.Fprintf(b, "culvert_mcp_shadow_evaluations_total{capability=\"gateway\",outcome=%q} %d\n", outcome, n)
	}
	row("would_execute", v.WouldExecute)
	row("would_block", v.WouldBlock)
	row("would_require_approval", v.WouldRequireApproval)
	row("would_require_confirmation", v.WouldRequireConfirmation)
	row("would_fail_credential_readiness", v.WouldFailCredential)
	row("would_fail_inspection", v.WouldFailInspection)
	row("would_fail_stale_decision", v.WouldFailStale)
	row("would_fail_hard_control", v.WouldFailHardControl)
	row("other", v.WouldOther)
	b.WriteString("# HELP culvert_mcp_shadow_evaluation_errors_total MCP Shadow evaluations that failed closed (durability/kill/invalid mode).\n")
	b.WriteString("# TYPE culvert_mcp_shadow_evaluation_errors_total counter\n")
	fmt.Fprintf(b, "culvert_mcp_shadow_evaluation_errors_total{capability=\"gateway\"} %d\n", v.EvaluationErrors)
}

// snapshot reads all counters (each an independent atomic load; the view can land
// between two consistent states under concurrent traffic, which is fine for telemetry).
func (m *mcpShadowMetrics) snapshot() shadowMetricsView {
	return shadowMetricsView{
		Evaluations:              m.evaluations.Load(),
		WouldExecute:             m.wouldExecute.Load(),
		WouldBlock:               m.wouldBlock.Load(),
		WouldRequireApproval:     m.wouldRequireApproval.Load(),
		WouldRequireConfirmation: m.wouldRequireConfirmation.Load(),
		WouldFailCredential:      m.wouldFailCredential.Load(),
		WouldFailInspection:      m.wouldFailInspection.Load(),
		WouldFailStale:           m.wouldFailStale.Load(),
		WouldFailHardControl:     m.wouldFailHardControl.Load(),
		WouldOther:               m.wouldOther.Load(),
		EvaluationErrors:         m.evaluationErrors.Load(),
	}
}
