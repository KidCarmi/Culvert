package main

// diagnostics_otlp_export.go — operator-contract row for a failing OTLP export.
//
// The push-loop health (failure count, last error, last delivery) is shown only
// under Settings → OpenTelemetry (OTLP). The one-page diagnostics report — where
// an operator checks "is this node healthy" — said nothing while the collector
// rejected or never received this node's metrics and traces, so the external
// dashboards and alerts built on them went quiet with no signal on the appliance.
//
// Report-only: reads the exporters' in-memory health snapshot, no I/O, and no
// change to push, retry or buffering. Contributes nothing when OTLP export is
// off, has not attempted a push yet, or its latest attempt was delivered.
// Health is per-process, so the row clears on restart until the next failure.
// Names the failing signal only: never the endpoint (it may embed a token), the
// auth header or the raw error text (viewer-readable).

import (
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/otlp"
)

// checkOTLPExport returns zero or one row for an enabled OTLP export whose most
// recent push attempt failed.
func checkOTLPExport() []OperatorContractCheck {
	var failing []string
	if globalOTLP.Enabled() && otlpLatestPushFailed(globalOTLP.Health()) {
		failing = append(failing, "metrics")
	}
	if globalOTLPTraces.Enabled() && otlpLatestPushFailed(globalOTLPTraces.Health()) {
		failing = append(failing, "traces")
	}
	return otlpExportRows(failing)
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
