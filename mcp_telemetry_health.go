package main

// QUAL-3 — truthful, safe telemetry health projection. It maps the composed
// telemetry runtime (events.Manager health + spool stats + archive exporter stats +
// durable export cursors) into (a) the existing per-capability adminapi
// DurabilityHealth surface and (b) an additive TelemetryStatus block on the admin
// overview. It exposes ONLY bounded counts/bytes/state names — never a
// data-directory or archive path, provider/KEK identity, raw backend error, raw
// event content, or a tenant id.

import (
	"github.com/KidCarmi/Culvert/internal/mcp/adminapi"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// TelemetryStatus is the safe, read-only telemetry readiness surfaced on the admin
// overview. It distinguishes telemetry_not_configured / ready / invalid, reports
// bounded durability + exporter counters, and truthfully labels decision telemetry
// as pending-policy (Policy is not composed in QUAL-3). It never claims Observe-,
// qualification-, or production-ready.
type TelemetryStatus struct {
	State               string                 `json:"state"` // telemetry_not_configured | ready | invalid
	Reason              string                 `json:"reason,omitempty"`
	NodeID              string                 `json:"node_id,omitempty"`
	EncryptionAvailable bool                   `json:"encryption_available"`
	DecisionTelemetry   string                 `json:"decision_telemetry"` // always "pending_policy" in QUAL-3
	ExecutionEnabled    bool                   `json:"execution_enabled"`  // always false
	Gateway             *TelemetryDomainStatus `json:"gateway,omitempty"`
}

// TelemetryDomainStatus is one capability domain's safe durability snapshot.
type TelemetryDomainStatus struct {
	CriticalState     string                              `json:"critical_state"`
	DenialState       string                              `json:"denial_state"`
	Severity          string                              `json:"severity"`
	RecoveryState     string                              `json:"recovery_state"`
	CommitOK          uint64                              `json:"commit_ok"`
	CommitFail        uint64                              `json:"commit_fail"`
	OrdinaryLoss      uint64                              `json:"ordinary_loss"`
	DenialLoss        uint64                              `json:"denial_loss"`
	DenialAggregates  uint64                              `json:"denial_aggregates"`
	RecoveryAttempts  uint64                              `json:"recovery_attempts"`
	RecoverySuccesses uint64                              `json:"recovery_successes"`
	CriticalReserve   int64                               `json:"critical_reserve_free"`
	Partitions        map[string]TelemetryPartitionStatus `json:"partitions"`
	Exporter          TelemetryExporterStatus             `json:"exporter"`
}

// TelemetryPartitionStatus is one partition's safe committed + export state.
type TelemetryPartitionStatus struct {
	Bytes     int64  `json:"bytes"`
	Quota     int64  `json:"quota"`
	Records   int    `json:"records"`
	Cursor    uint64 `json:"export_cursor"`
	ExportLag uint64 `json:"export_lag"`
}

// TelemetryExporterStatus is the archive exporter's safe state (no paths).
type TelemetryExporterStatus struct {
	Configured     bool   `json:"configured"`
	Ready          bool   `json:"ready"`
	Type           string `json:"type"`
	ExportedEvents uint64 `json:"exported_events"`
	BatchesOK      uint64 `json:"batches_ok"`
	Failures       uint64 `json:"failures"`
	Saturated      bool   `json:"saturated"`
	BytesUsed      int64  `json:"bytes_used"`
	MaxBytes       int64  `json:"max_bytes"`
	LastReason     string `json:"last_reason,omitempty"`
	LastExportUnix int64  `json:"last_export_unix_nano,omitempty"`
}

// telemetryStatus builds the safe overview status from the published holder.
func mcpTelemetryStatus() TelemetryStatus {
	mcpTelem.mu.RLock()
	state, reason, rt := mcpTelem.state, mcpTelem.reason, mcpTelem.rt
	mcpTelem.mu.RUnlock()

	st := TelemetryStatus{
		State:             string(state),
		Reason:            reason,
		DecisionTelemetry: "pending_policy", // Policy is not composed in QUAL-3
		ExecutionEnabled:  false,
	}
	if rt == nil {
		return st
	}
	st.NodeID = rt.nodeID
	st.EncryptionAvailable = true // a ready manager proves the KEK/DEK opened
	st.Gateway = rt.domainStatus()
	return st
}

// domainStatus projects the Gateway domain's manager health + spool stats + exporter
// stats + cursors into the safe status.
func (t *telemetryRuntime) domainStatus() *TelemetryDomainStatus {
	h := t.mgr.Health()
	d, ok := h.Domains[evmodel.CapGateway]
	if !ok {
		return nil
	}
	out := &TelemetryDomainStatus{
		CriticalState: d.CriticalState, DenialState: d.DenialState, Severity: d.Severity,
		RecoveryState:     recoveryStateLabel(d),
		CommitOK:          d.CommitOK,
		CommitFail:        d.CommitFail,
		OrdinaryLoss:      d.OrdinaryLoss,
		DenialLoss:        d.DenialLoss,
		DenialAggregates:  d.DenialAggregates,
		RecoveryAttempts:  d.RecoveryAttempts,
		RecoverySuccesses: d.RecoverySuccesses,
		CriticalReserve:   d.Spool.CriticalFreeBytes,
		Partitions:        map[string]TelemetryPartitionStatus{},
	}
	for _, part := range gatewayPartitions {
		ps := d.Spool.Partitions[part]
		out.Partitions[telemPartitionName(part)] = TelemetryPartitionStatus{
			Bytes:     ps.Bytes,
			Quota:     int64(ps.Quota),
			Records:   ps.Records,
			Cursor:    t.cursors.get(part),
			ExportLag: t.exportLag(part),
		}
	}
	es := t.exporter.stats()
	out.Exporter = TelemetryExporterStatus{
		Configured: true, Ready: true, Type: telemExportTypeArchive,
		ExportedEvents: es.ExportedEvents, BatchesOK: es.BatchesOK, Failures: es.Failures,
		Saturated: es.Saturated, BytesUsed: es.BytesUsed, MaxBytes: es.MaxBytes,
		LastReason: es.LastReason, LastExportUnix: es.LastOKUnixNano,
	}
	return out
}

// recoveryStateLabel derives a bounded recovery label from the domain counters.
func recoveryStateLabel(d events.DomainHealth) string {
	switch {
	case d.RecoveryAttempts == 0:
		return "clean"
	case d.RecoverySuccesses >= d.RecoveryAttempts:
		return "recovered"
	default:
		return "recovering"
	}
}

// mcpTelemetryDurability is the adminapi Durability source (per-capability). It
// replaces the QUAL-1/2 hardcoded stub with the real, safe durability snapshot when
// telemetry is composed; otherwise it reports the truthful not-configured baseline.
func mcpTelemetryDurability(capability string) adminapi.DurabilityHealth {
	base := adminapi.DurabilityHealth{
		CriticalState: "normal", DenialState: "normal", Severity: "none", RecoveryState: "n/a",
	}
	rt := sharedTelemetry()
	if rt == nil || capability != "gateway" {
		return base
	}
	h := rt.mgr.Health()
	d, ok := h.Domains[evmodel.CapGateway]
	if !ok {
		return base
	}
	crit := d.Spool.Partitions[evmodel.PartCrit]
	ord := d.Spool.Partitions[evmodel.PartOrd]
	den := d.Spool.Partitions[evmodel.PartDen]
	return adminapi.DurabilityHealth{
		CriticalState:        d.CriticalState,
		DenialState:          d.DenialState,
		Severity:             d.Severity,
		CritBytes:            crit.Bytes,
		CritQuota:            int64(crit.Quota),
		OrdBytes:             ord.Bytes,
		OrdQuota:             int64(ord.Quota),
		DenBytes:             den.Bytes,
		DenQuota:             int64(den.Quota),
		CriticalReserveFree:  d.Spool.CriticalFreeBytes,
		CommitFailures:       d.CommitFail,
		DenialLoss:           d.DenialLoss,
		CriticalDegradations: d.CriticalLoss,
		RecoveryState:        recoveryStateLabel(d),
		ExporterLag:          rt.maxExportLag(),
	}
}

// maxExportLag returns the largest per-partition export lag (a single bounded health
// scalar for the DurabilityHealth surface).
func (t *telemetryRuntime) maxExportLag() uint64 {
	var m uint64
	for _, part := range gatewayPartitions {
		if l := t.exportLag(part); l > m {
			m = l
		}
	}
	return m
}

// ── Admin API committed-event read seam ─────────────────────────────────────────

// mcpEventReader adapts the shared telemetry manager's Gateway spool to the adminapi
// EventReader (the DecisionService source). It exposes ONLY committed P-CRIT/P-ORD
// decision events for the Gateway capability — the same durable spool the runtime
// commits to (single source of truth). With Policy absent no decision event is ever
// committed on a live request, so the DecisionService is truthfully empty; a decision
// committed via the manager (test seam / future Policy) is read back through THIS
// real path — never a fabricated row.
type mcpEventReader struct{ mgr *events.Manager }

func (r mcpEventReader) CommittedEvents(capability, partition string, afterSeq uint64, limit int) ([]evmodel.Event, []uint64, uint64, error) {
	if capability != "gateway" {
		return nil, nil, afterSeq, nil // Management is not composed here
	}
	sp := r.mgr.Spool(evmodel.CapGateway)
	if sp == nil {
		return nil, nil, afterSeq, nil
	}
	part, ok := parseTelemPartition(partition)
	if !ok {
		return nil, nil, afterSeq, nil
	}
	return sp.CommittedForExport(part, afterSeq, limit)
}

// parseTelemPartition maps the adminapi partition label to the model partition.
func parseTelemPartition(s string) (evmodel.Partition, bool) {
	switch s {
	case "P-CRIT":
		return evmodel.PartCrit, true
	case "P-ORD":
		return evmodel.PartOrd, true
	case "P-DEN":
		return evmodel.PartDen, true
	default:
		return evmodel.PartNone, false
	}
}

// mcpAdminEventReader returns the adminapi EventReader over the shared telemetry
// manager, or a nil interface when telemetry is not composed (so the DecisionService
// stays disabled — QUAL-2 behavior).
func mcpAdminEventReader() adminapi.EventReader {
	rt := sharedTelemetry()
	if rt == nil {
		return nil
	}
	return mcpEventReader{mgr: rt.mgr}
}
