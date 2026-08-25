package execution

import (
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Metrics is the optional bounded, low-cardinality rollout telemetry sink. All
// labels are bounded enums (capability, disposition, reason code, hard class) —
// never a tenant, subject, tool argument, URL, or token.
type Metrics interface {
	ObserveResolution(capability string, res rollout.Resolution)
	ObserveBlock(capability string, reason mcperr.Reason)
	ObserveExecution(capability string, ok bool)
	ObserveUpstream(capability string, outcome string)
	ObserveDLPBlock(capability string, response bool)
	// ObserveOutcomeEvidenceLoss records that a post-execution outcome event could
	// not be committed. The side effect already happened, so this is the archive
	// losing its record of it — best-effort must mean "does not block the response",
	// never "fails invisibly".
	ObserveOutcomeEvidenceLoss(capability string)
	// ObserveShadowOutcome records ONE non-executing Shadow evaluation and its formal
	// Model-1 verdict. outcome is a ShadowOutcome value (a bounded, low-cardinality enum:
	// would_execute / would_block / would_require_* / would_fail_*) — never a tenant,
	// subject, tool, or argument. It is emitted only by the ShadowEvaluator; the live
	// executor never calls it.
	ObserveShadowOutcome(capability string, outcome string)
}

// noopMetrics is the default no-op sink.
type noopMetrics struct{}

// ObserveResolution discards the resolution observation.
func (noopMetrics) ObserveResolution(string, rollout.Resolution) {}

// ObserveBlock discards the block observation.
func (noopMetrics) ObserveBlock(string, mcperr.Reason) {}

// ObserveExecution discards the execution observation.
func (noopMetrics) ObserveExecution(string, bool) {}

// ObserveUpstream discards the upstream-outcome observation.
func (noopMetrics) ObserveUpstream(string, string) {}

// ObserveDLPBlock discards the response-DLP observation.
func (noopMetrics) ObserveDLPBlock(string, bool) {}

// ObserveOutcomeEvidenceLoss discards the outcome-evidence-loss observation.
func (noopMetrics) ObserveOutcomeEvidenceLoss(string) {}

// ObserveShadowOutcome discards the shadow-outcome observation.
func (noopMetrics) ObserveShadowOutcome(string, string) {}
