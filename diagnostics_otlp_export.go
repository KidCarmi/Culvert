package main

// diagnostics_otlp_export.go — operator-contract rows for an OTLP export that
// is not delivering: one for a half that is FAILING, and one for a plane that
// is only HALF ENABLED (CHAOS-130).
//
// The push-loop health (failure count, last error, last delivery) is shown only
// under Settings → OpenTelemetry (OTLP). The one-page diagnostics report — where
// an operator checks "is this node healthy" — said nothing while the collector
// rejected or never received this node's metrics and traces, so the external
// dashboards and alerts built on them went quiet with no signal on the appliance.
//
// Report-only: reads the exporters' in-memory health and enablement, no I/O,
// and no change to push, retry or buffering. Contributes nothing when OTLP
// export is off on both halves, has not attempted a push yet, or its latest
// attempt was delivered.
// Health is per-process, so the row clears on restart until the next failure.
// Names the failing signal only: never the endpoint (it may embed a token), the
// auth header or the raw error text (viewer-readable).

import (
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/otlp"
)

// checkOTLPExport returns the rows for an OTLP export plane that is not
// delivering: one for an enabled half whose most recent push attempt failed,
// and one for a plane that is only HALF enabled (CHAOS-130).
func checkOTLPExport() []OperatorContractCheck {
	// The pair mutex: both halves are read from the same instant, so a
	// configure or disable caught in progress cannot be reported as a
	// divergence. Read-only and uncontended — the writers are the admin
	// handler, the CP snapshot apply and startup.
	otlpPairMu.Lock()
	metricsOn, metricsEP := globalOTLP.Enabled(), globalOTLP.Endpoint()
	tracesOn, tracesEP := globalOTLPTraces.Enabled(), globalOTLPTraces.Endpoint()
	otlpPairMu.Unlock()

	var rows []OperatorContractCheck
	if partial := otlpIncoherentExportRow(metricsOn, tracesOn, metricsEP, tracesEP); partial != nil {
		rows = append(rows, *partial)
	}

	var failing []string
	if metricsOn && otlpLatestPushFailed(globalOTLP.Health()) {
		failing = append(failing, "metrics")
	}
	if tracesOn && otlpLatestPushFailed(globalOTLPTraces.Health()) {
		failing = append(failing, "traces")
	}
	return append(rows, otlpExportRows(failing)...)
}

// otlpIncoherentExportRow reports an export plane whose two halves do not
// agree: exactly one of them running, or both running against DIFFERENT
// collectors.
//
// CHAOS-130: the two exporters are configured and stopped together by every
// caller, so one half running alone is not a configuration an operator can
// ask for — it is the residue of two transitions that interleaved. It used to
// be both PERMANENT and invisible: no later CP snapshot restored a traces
// exporter stopped on its own (the apply decided both halves from the metrics
// exporter's state), the row below did not exist, and the only other surface —
// the failure row — reports an export that is FAILING and has nothing to say
// about one that is simply OFF. Spans stopped being exported with no counter,
// no row and no log line.
//
// The transitions are atomic now and this state should be unreachable; the row
// exists because "unreachable" is a claim about the callers known today, and
// the failure mode it guards against is silence.
func otlpIncoherentExportRow(metricsOn, tracesOn bool, metricsEP, tracesEP string) *OperatorContractCheck {
	const action = "Settings → OpenTelemetry (OTLP): re-enter the collector endpoint and select Enable to apply " +
		"the same setting to both halves, or clear it to turn export off entirely. " +
		"Proxy traffic and policy enforcement are not affected."

	if metricsOn != tracesOn {
		off, on := "traces", "metrics"
		if !metricsOn {
			off, on = "metrics", "traces"
		}
		return &OperatorContractCheck{
			Code:   "otlp_export_partial",
			Status: diagWarn,
			Message: "OpenTelemetry (OTLP) export is only half enabled — " + on + " is exporting and " +
				off + " is not, so the dashboards and alerts built on this node's " + off +
				" are not being updated and will not recover on their own",
			OperatorAction: action,
		}
	}
	// Both halves running, but not to the same place. No caller can ask for
	// this — every one of them configures the pair from a single endpoint — so
	// like the half-enabled case it is the residue of two transitions that
	// interleaved, and it splits a node's telemetry across two collectors with
	// neither one complete. The endpoints are NOT named: one may embed a token
	// (see this file's header).
	if metricsOn && metricsEP != tracesEP {
		return &OperatorContractCheck{
			Code:   "otlp_export_split",
			Status: diagWarn,
			Message: "OpenTelemetry (OTLP) export is split across two different collectors — metrics and traces " +
				"are being sent to different endpoints, so neither collector has a complete view of this node " +
				"and it will not correct itself",
			OperatorAction: action,
		}
	}
	return nil
}

// otlpLatestPushFailed reports whether the latest recorded push attempt failed:
// a failure is recorded and no delivery is recorded after it. The timestamps are
// whole seconds; a failure and a delivery in the same second read as delivered,
// so the row never outlives a recovery.
func otlpLatestPushFailed(h otlp.PushHealth) bool {
	if h.LastErrorAt == "" {
		return false
	}
	if h.LastSuccessAt == "" {
		return true
	}
	failedAt, err := time.Parse(time.RFC3339, h.LastErrorAt)
	if err != nil {
		return false
	}
	deliveredAt, err := time.Parse(time.RFC3339, h.LastSuccessAt)
	if err != nil {
		return true
	}
	return failedAt.After(deliveredAt)
}

func otlpExportRows(failing []string) []OperatorContractCheck {
	if len(failing) == 0 {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   "otlp_export",
		Status: diagWarn,
		Message: "OpenTelemetry (OTLP) export is failing for " + strings.Join(failing, " and ") +
			" — the most recent push to the collector was not delivered, so external dashboards and alerts built on this node's telemetry are not being updated",
		OperatorAction: "Settings → OpenTelemetry (OTLP) shows the failure count, the last error and the last successful delivery. " +
			"Correct the endpoint or auth header there and select Enable to apply; this warning clears after the next delivered push or a restart. " +
			"Proxy traffic and policy enforcement are not affected.",
	}}
}
