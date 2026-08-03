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
}

// noopMetrics is the default no-op sink.
type noopMetrics struct{}

func (noopMetrics) ObserveResolution(string, rollout.Resolution) {}
func (noopMetrics) ObserveBlock(string, mcperr.Reason)           {}
func (noopMetrics) ObserveExecution(string, bool)                {}
func (noopMetrics) ObserveUpstream(string, string)               {}
func (noopMetrics) ObserveDLPBlock(string, bool)                 {}
