package shadowmetrics

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Sink is the Shadow evaluator's metrics sink. The zero value is ready to use.
// It is the SAME instance the evaluator writes and the /metrics + status
// surfaces read, so an operator watching a controlled activation sees the live
// evaluation counts without any cross-wiring.
type Sink struct {
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

// ── execution.Metrics ──────────────────────────────────────────────────────────

// ObserveShadowOutcome records one non-executing evaluation and its Model-1 verdict.
func (m *Sink) ObserveShadowOutcome(_ string, outcome string) {
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
func (m *Sink) ObserveBlock(string, mcperr.Reason) { m.evaluationErrors.Add(1) }

// ObserveResolution is a no-op for the shadow sink: the evaluation is counted
// authoritatively (with its verdict) by ObserveShadowOutcome, so counting the
// resolution too would double-count.
func (m *Sink) ObserveResolution(string, rollout.Resolution) {}

// The remaining execution.Metrics methods describe LIVE-execution events the Shadow
// evaluator can never produce (it performs no upstream call, no DLP, no outcome event).
// They are no-ops; a non-zero value on any of them would itself be a bug.

// ObserveExecution is a no-op: Shadow never executes.
func (m *Sink) ObserveExecution(string, bool) {}

// ObserveUpstream is a no-op: Shadow makes no upstream call.
func (m *Sink) ObserveUpstream(string, string) {}

// ObserveDLPBlock is a no-op: Shadow inspects no response.
func (m *Sink) ObserveDLPBlock(string, bool) {}

// ObserveOutcomeEvidenceLoss is a no-op: Shadow emits no outcome event.
func (m *Sink) ObserveOutcomeEvidenceLoss(string) {}

// View is the bounded read-only snapshot for /metrics + status surfaces. Its JSON
// field names are the status wire contract.
type View struct {
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

// WritePrometheus appends the bounded culvert_mcp_shadow_* series. The outcome
// label is the only dimension, a fixed closed enum, so cardinality is constant.
// The caller decides whether to emit at all (main emits nothing on a node that
// never armed Shadow).
func (m *Sink) WritePrometheus(b *strings.Builder) {
	v := m.Snapshot()
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

// Snapshot reads all counters (each an independent atomic load; the view can land
// between two consistent states under concurrent traffic, which is fine for telemetry).
func (m *Sink) Snapshot() View {
	return View{
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
