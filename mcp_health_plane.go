package main

// RISK-027 — fleet-visible MCP capability health.
//
// Every other Culvert subsystem with a failure mode reports through the same three
// surfaces: a `/healthz` field, a `/readyz` row, and `culvert_*` metrics
// (storage_health.go, ca_health.go, socks5_health.go, cluster_ca_health.go,
// auth_backend_health.go). MCP had NONE of them — its health existed only under
// admin-authenticated `/api/mcp/*`, so a degraded or dead MCP listener was
// invisible to the monitoring that watches everything else in the binary, and
// there was no series to alert on.
//
// Three postures are kept strictly distinct, and the distinction is the whole
// point of this file:
//
//   - PROCESS health — is the binary alive? MCP never affects it.
//   - SWG READINESS — should this node receive proxy traffic? MCP is REPORT-ONLY
//     here, always. An MCP fault must never pull a healthy Secure Web Gateway out
//     of rotation: MCP is disabled by default, optional when enabled, and shares
//     no state with the SWG data path. Making it gating would turn an optional
//     capability into an availability SPOF for the primary product.
//   - MCP CAPABILITY health — is the MCP gateway itself serving? This is what the
//     new row and series actually report, and what an operator alerts on.
//
// Disclosure discipline. `/readyz` and `/metrics` are reachable on the proxy port
// without admin authentication, so nothing here may emit a token, tenant, raw
// server id, path, policy content, credential, identity, bind address or raw
// error. Row details are FIXED strings chosen from a closed set; every number is a
// plain total. This mirrors the `ca` / `socks5` rows, whose details are fixed for
// exactly this reason.

import (
	"context"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// mcpCapabilityState is the bounded, low-cardinality classification of the MCP
// capability's health. It is a CLOSED set: every value is safe to publish on an
// unauthenticated surface and safe to use as a metric label.
type mcpCapabilityState string

const (
	// mcpCapDisabled — MCP was never requested. The default posture.
	mcpCapDisabled mcpCapabilityState = "disabled"
	// mcpCapInvalid — enablement was requested but a security prerequisite failed;
	// nothing bound. This is the state an operator must see: the node looks
	// configured but is serving no MCP.
	mcpCapInvalid mcpCapabilityState = "invalid"
	// mcpCapStarting — composed, not yet accepting.
	mcpCapStarting mcpCapabilityState = "starting"
	// mcpCapReady — the listener is accepting requests.
	mcpCapReady mcpCapabilityState = "ready"
	// mcpCapDegraded — running but shedding load, or the serve loop failed.
	mcpCapDegraded mcpCapabilityState = "degraded"
	// mcpCapDraining — graceful shutdown in progress.
	mcpCapDraining mcpCapabilityState = "draining"
	// mcpCapStopped — fully stopped while still configured. Distinct from disabled:
	// a configured capability that has stopped is a fault, not a posture.
	mcpCapStopped mcpCapabilityState = "stopped"
)

// mcpHealthSnapshot is the safe, typed MCP capability snapshot shared by
// `/healthz`, `/readyz` and `/metrics`, so all three report the SAME truth from
// ONE read rather than three independently-computed sources.
type mcpHealthSnapshot struct {
	// Configured is true once enablement has been requested, whether or not it
	// succeeded. A node that never asked for MCP emits no rows and no series at
	// all: `up 0` on a node that never had MCP is indistinguishable from a dead
	// listener, and the documented paging rule is `== 0` (the socks5_health.go
	// rule, applied here).
	Configured bool
	State      mcpCapabilityState
	// Reason is the bounded, secret-free activation classification (already a
	// closed vocabulary produced by the startup loader). Surfaced ONLY on the
	// admin plane and in logs — never on `/readyz`, which is unauthenticated.
	Reason string

	ListenerReady      bool
	ActiveSessions     int64
	AcceptedConns      int64
	RequestsTotal      int64
	RequestsRejected   int64
	AuthFailures       int64
	HostOriginFailures int64
	AdmissionRejected  int64
	Timeouts           int64
	ObserveDrops       int64
	InFlight           int64
	Queued             int64

	// Plane readiness — each is a truthful "is this dependency composed and
	// usable", never a claim that the dependency exists.
	PolicyState          string // not_configured | loaded | invalid
	InventoryReady       bool
	TelemetryReady       bool
	DistributionComposed bool
	RolloutMode          string
}

// mcpHealthState is the single read every MCP health surface uses.
func mcpHealthState() mcpHealthSnapshot {
	act := getMCPObserveStatus()
	snap := mcpHealthSnapshot{Configured: act.EnableRequested}

	switch act.State {
	case mcpObserveDisabled:
		snap.State = mcpCapDisabled
		// A node that never requested MCP is not "configured": emit nothing.
		snap.Configured = false
		return snap
	case mcpObserveInvalid:
		snap.State, snap.Reason, snap.Configured = mcpCapInvalid, act.Reason, true
		return snap
	}

	// Configured: reflect the LIVE listener phase, never the stored config.
	snap.Configured = true
	snap.State = mcpCapStarting
	if live, ok := gatewayHealthSnapshot(); ok {
		snap.State = mcpPhaseCapabilityState(live.Phase)
		snap.ListenerReady = live.Phase == mcpruntime.PhaseReady
		snap.ActiveSessions = live.ActiveSessions
		snap.AcceptedConns = live.AcceptedConns
		snap.RequestsTotal = live.RequestsTotal
		snap.RequestsRejected = live.RequestsRejected
		snap.AuthFailures = live.AuthFailures
		snap.HostOriginFailures = live.HostOriginFailures
		snap.AdmissionRejected = live.AdmissionRejected
		snap.Timeouts = live.Timeouts
		snap.ObserveDrops = live.ObserveDrops
		snap.InFlight = live.InFlight
		snap.Queued = live.Queued
	}
	snap.PolicyState = mcpPolicyStatus().State
	if reg, cat := mcpInventory.sharedInventory(); reg != nil || cat != nil {
		snap.InventoryReady = true
	}
	snap.TelemetryReady = sharedTelemetry() != nil
	if st, ok := mcpDistributionStatus()["dp_composed"].(bool); ok {
		snap.DistributionComposed = st
	}
	snap.RolloutMode = getMCPRollout().stateFor(rollout.CapabilityGateway).CurrentConfig().Mode.String()
	return snap
}

// mcpPhaseCapabilityState maps a listener phase to the capability state.
func mcpPhaseCapabilityState(p mcpruntime.Phase) mcpCapabilityState {
	switch p {
	case mcpruntime.PhaseStarting:
		return mcpCapStarting
	case mcpruntime.PhaseReady:
		return mcpCapReady
	case mcpruntime.PhaseDegraded:
		return mcpCapDegraded
	case mcpruntime.PhaseDraining:
		return mcpCapDraining
	case mcpruntime.PhaseStopped:
		return mcpCapStopped
	default:
		return mcpCapDisabled
	}
}

// mcpCapabilityFaulted reports whether the MCP capability is in a state an
// operator must act on: enablement was requested but the capability is not
// serving. Draining is deliberately NOT a fault (it is an orderly shutdown), and
// neither is `disabled` (nobody asked for MCP).
func (s mcpHealthSnapshot) Faulted() bool {
	if !s.Configured {
		return false
	}
	switch s.State {
	case mcpCapInvalid, mcpCapDegraded, mcpCapStopped:
		return true
	default:
		return false
	}
}

// appendMCPReadinessCheck adds the REPORT-ONLY MCP row.
//
// It is absent entirely when MCP was never requested — an always-present row
// would make every node look like it has an MCP capability, and a `fail` row on a
// node that never wanted MCP would be pure noise.
//
// It NEVER gates the default readiness verdict. The caller must not set allOK
// from it. An operator who genuinely wants dependency-degraded nodes ejected opts
// in through /ready?strict=1, which is the existing repository-wide mechanism for
// exactly this choice (CHAOS-09) — MCP does not invent a second one.
//
// The detail is a FIXED string from a closed set: /readyz is unauthenticated on
// the proxy port, and the activation reason can name a configuration fault
// (a missing certificate path, an invalid policy file) that fingerprints the
// node's setup. The precise reason is on the admin plane.
func appendMCPReadinessCheck(checks map[string]*readinessCheck) {
	snap := mcpHealthState()
	if !snap.Configured {
		return
	}
	switch snap.State {
	case mcpCapInvalid:
		checks["mcp_gateway"] = &readinessCheck{
			Status: "fail",
			Detail: "MCP gateway was enabled but did not start — see MCP status in the admin UI",
		}
	case mcpCapDegraded, mcpCapStopped:
		checks["mcp_gateway"] = &readinessCheck{
			Status: "fail",
			Detail: "MCP gateway is not accepting requests — see MCP status in the admin UI",
		}
	case mcpCapDraining, mcpCapStarting:
		checks["mcp_gateway"] = &readinessCheck{Status: "ok", Detail: string(snap.State)}
	default:
		checks["mcp_gateway"] = &readinessCheck{Status: "ok"}
	}
}

// mcpHealthFieldValue is the `/healthz` field value: the bounded capability state,
// or "" on a node that never requested MCP (the field is omitempty).
func mcpHealthFieldValue() string {
	snap := mcpHealthState()
	// /healthz is the monitoring read, so it is the natural evaluation point: the
	// alert transitions on the same snapshot the probe reports, and never on a
	// separate, independently-computed view.
	evaluateMCPHealthAlert(snap)
	if !snap.Configured {
		return ""
	}
	return string(snap.State)
}

// boolGauge renders a boolean as a Prometheus 0/1 gauge value.
func boolGauge(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ── alerting ─────────────────────────────────────────────────────────────────

// mcpAlertState latches the last reported fault so the alert fires ONCE per
// episode rather than once per evaluation. Recovery clears the latch on OBSERVED
// evidence — the capability actually serving again — never on elapsed time, the
// discipline storage_health.go and ca_health.go establish.
var mcpAlertState struct {
	mu      sync.Mutex
	alerted bool
}

// fireMCPGatewayAlert delivers the `mcp_gateway_down` alert.
//
// Package-level seam so tests observe transitions SYNCHRONOUSLY instead of racing
// the process-global alerts sink (the -count/-shuffle determinism class the CI
// gate catches). HasSubscriber-gated for the reason documented on
// fireStorageWriteAlert: with no webhook configured — the default posture, and the
// state of every test binary — this must not spawn a goroutine at all.
var fireMCPGatewayAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("mcp_gateway_down") {
		return
	}
	go fireAlert("mcp_gateway_down", AlertPayload{
		Detail: detail,
		Source: "mcp",
	})
}

// evaluateMCPHealthAlert fires once when the capability enters a fault state and
// clears the latch once it is observed serving again.
//
// The Detail is a BOUNDED state label, never the activation reason: Dispatch
// dedups on `event + ":" + Detail`, so an unbounded detail would give the dedup
// key one distinct value per evaluation — the WK-12/RS-5 defect — and the
// activation reason can name a configuration path. The precise reason stays on the
// admin plane and in the log.
func evaluateMCPHealthAlert(snap mcpHealthSnapshot) {
	mcpAlertState.mu.Lock()
	defer mcpAlertState.mu.Unlock()
	if !snap.Faulted() {
		// Recovery on OBSERVED evidence: the capability is serving (or was never
		// requested), so a later fault may alert again.
		mcpAlertState.alerted = false
		return
	}
	if mcpAlertState.alerted {
		return
	}
	mcpAlertState.alerted = true
	fireMCPGatewayAlert("MCP gateway is not serving (state=" + string(snap.State) + ")")
}

// resetMCPHealthAlertForTest clears the process-global latch (TEST-ONLY).
func resetMCPHealthAlertForTest() {
	mcpAlertState.mu.Lock()
	mcpAlertState.alerted = false
	mcpAlertState.mu.Unlock()
}

// ── periodic evaluation ──────────────────────────────────────────────────────

// mcpHealthAlertInterval is how often the capability's health is re-evaluated for
// alerting. It is deliberately coarse: the latch means a standing fault alerts
// once, so the interval governs DETECTION LATENCY for a new fault, not alert
// volume.
const mcpHealthAlertInterval = 30 * time.Second

// startMCPHealthAlertPoller evaluates the MCP capability's health on a timer.
//
// Without it the alert is POLL-DRIVEN: evaluateMCPHealthAlert runs from
// mcpHealthFieldValue, i.e. only when something reads /healthz. That inverts the
// relationship an alert is supposed to have with monitoring — the alert exists to
// tell an operator to look, so making it depend on someone already looking means a
// node whose MCP listener dies, on a deployment that scrapes /metrics but not
// /healthz, or during an outage of the scraper itself, would never say so.
//
// Evaluation stays idempotent and latched, so the timer cannot produce duplicate
// alerts and the probe path keeps working exactly as before — this only removes
// the dependency on being scraped.
//
// Started only when MCP was actually requested: a node that never asked for MCP
// gets no goroutine, matching the rest of the disabled-by-default posture. The
// round is panic-guarded for the CHAOS-24 reason — a panic here must not take down
// the gateway, and must not silently stop the poller, which would freeze detection
// at "healthy" for the life of the process.
// It reports whether the poller was started, so the disabled-by-default posture is
// directly assertable rather than inferred from a goroutine count (a count-based
// test tolerates slack for unrelated goroutines and so cannot distinguish "did not
// start" from "started one").
func startMCPHealthAlertPoller(ctx context.Context) bool {
	if !mcpHealthState().Configured {
		return false
	}
	go func() {
		t := time.NewTicker(mcpHealthAlertInterval)
		defer t.Stop()
		runGuarded("mcp_health_alert", func() { evaluateMCPHealthAlert(mcpHealthState()) })
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				runGuarded("mcp_health_alert", func() { evaluateMCPHealthAlert(mcpHealthState()) })
			}
		}
	}()
	return true
}
