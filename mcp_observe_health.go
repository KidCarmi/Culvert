package main

// QUAL-1 — truthful runtime status bridge for the admin MCP health surface. It maps
// (a) the node-local activation outcome recorded at startup and (b) the LIVE
// listener phase reported by the bound runtime into the existing adminapi
// RuntimeStateHealth DTO. Nothing here fabricates readiness: a stored admin config
// never implies an active listener — active state comes only from the runtime.

import (
	"github.com/KidCarmi/Culvert/internal/mcp/adminapi"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// mcpObserveRuntimeHealth reports the truthful per-capability runtime state for the
// admin health API. Management is never activated in QUAL-1, so it is always
// disabled. Gateway reflects the activation outcome and, when configured, the live
// listener phase.
func mcpObserveRuntimeHealth(capability string) adminapi.RuntimeStateHealth {
	if capability != "gateway" {
		// Management MCP has no startup-activation path in this slice: always disabled.
		return adminapi.RuntimeStateHealth{State: "disabled"}
	}
	st := getMCPObserveStatus()
	h := adminapi.RuntimeStateHealth{EnableRequested: st.EnableRequested}
	switch st.State {
	case mcpObserveDisabled:
		h.State = "disabled"
		return h
	case mcpObserveInvalid:
		// Enable was requested but a security prerequisite failed: nothing bound.
		h.State = "invalid"
		h.Reason = st.Reason
		return h
	}
	// Configured: the listener was validly built. Reflect the live phase; QUAL-1 is
	// Observe-only with no upstream execution composed.
	h.Posture = "observe"
	h.ExecutionEnabled = false
	snap, ok := gatewayHealthSnapshot()
	if !ok {
		// Built but the runtime has not (yet) reported a bound listener.
		h.State = "configured_not_started"
		return h
	}
	h.State = mcpPhaseState(snap.Phase)
	h.ListenerReady = snap.Phase == mcpruntime.PhaseReady
	h.Draining = snap.Phase == mcpruntime.PhaseDraining
	h.ActiveSessions = nonNegInt(snap.ActiveSessions)
	h.AcceptedConns = nonNegU64(snap.AcceptedConns)
	h.RejectedConns = nonNegU64(snap.RejectedConns)
	h.InFlight = nonNegInt(snap.InFlight)
	return h
}

// gatewayHealthSnapshot returns the live Gateway listener health snapshot when the
// runtime is bound. Gateway is the first enabled listener (Management is never
// enabled here), so it is the first element when present.
func gatewayHealthSnapshot() (mcpruntime.HealthSnapshot, bool) {
	if mcpRuntime == nil {
		return mcpruntime.HealthSnapshot{}, false
	}
	// Index-based range: HealthSnapshot is a wide (168-byte) struct, so avoid the
	// per-iteration value copy (gocritic rangeValCopy).
	snaps := mcpRuntime.Health()
	for i := range snaps {
		if snaps[i].Capability == "gateway" {
			return snaps[i], true
		}
	}
	return mcpruntime.HealthSnapshot{}, false
}

// gatewayServingReady reports whether the Gateway observe listener is not merely
// CONFIGURED at startup but LIVE and SERVING: the observe state is mcpObserveConfigured
// AND the runtime's Gateway health snapshot is present and in PhaseReady. It is pure (no
// global reads) so the phase mapping is unit-testable without a live runtime.
//
// The distinction is load-bearing for the Shadow activation preflight: serve() sets
// PhaseReady synchronously at Start, but a listener that started and later exited its serve
// loop with an unexpected error becomes PhaseDegraded while getMCPObserveStatus().State
// stays mcpObserveConfigured. Relying on the startup result alone would let the preflight
// declare a node ready and open a Shadow evidence window on a listener that can no longer
// receive traffic (Codex P1, PR #1234).
func gatewayServingReady(state mcpObserveState, snap mcpruntime.HealthSnapshot, haveSnap bool) bool {
	return state == mcpObserveConfigured && haveSnap && snap.Phase == mcpruntime.PhaseReady
}

// liveGatewayListenerReady is the production Shadow-preflight listener probe: it reads the
// current observe state and the live Gateway health snapshot and requires PhaseReady.
func liveGatewayListenerReady() bool {
	snap, ok := gatewayHealthSnapshot()
	return gatewayServingReady(getMCPObserveStatus().State, snap, ok)
}

// mcpPhaseState maps a listener Phase to the admin health state label.
func mcpPhaseState(p mcpruntime.Phase) string {
	switch p {
	case mcpruntime.PhaseStarting:
		return "starting"
	case mcpruntime.PhaseReady:
		return "ready"
	case mcpruntime.PhaseDegraded:
		return "degraded"
	case mcpruntime.PhaseDraining:
		return "draining"
	case mcpruntime.PhaseStopped:
		return "stopped"
	default:
		return "disabled"
	}
}

// nonNegU64 clamps a monotonic (non-negative) counter to uint64 without a
// sign-conversion overflow.
func nonNegU64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v) // #nosec G115 -- guarded non-negative above
}

// nonNegInt clamps a monotonic (non-negative) counter to a platform int, bounding
// the (theoretical, 32-bit) overflow gosec flags on an int64->int conversion.
func nonNegInt(v int64) int {
	if v < 0 {
		return 0
	}
	if v > int64(^uint(0)>>1) {
		return int(^uint(0) >> 1)
	}
	return int(v)
}
