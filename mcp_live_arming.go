package main

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// MCP live-execution tier ARMING + QUIESCE authoritative paths (§5/§6).
//
// armLiveTier is the ONE explicit authoritative arming path — the sole production caller of the
// live arming hook (setLiveExecDepsArmed(true) → markGatewayExecDepsReady), pinned by the evolved
// execution-posture wall. It arms ONLY when the tier is composed AND the node satisfies the
// LIVE-tier node readiness gate. It is NOT a startup convenience path and NOTHING arms implicitly
// because dependencies happen to exist: arming is always this deliberate, gated act.
//
// NODE readiness vs ACTIVATION readiness (§5). This gate checks the NODE-level prerequisites the
// live tier needs to EXIST safely — executor composed, upstream/credential path present (implied by
// composition), durable events / response inspection / registry / catalog / policy healthy, the
// final kill + tool-freshness boundary guards present (implied by the composed live executor),
// emergency kill clear, Shadow-Exit attestation valid, rollback MECHANICS evidence valid, and the
// AUTHORITATIVE coordinator rollback rehearsal valid. It deliberately does NOT check the
// ACTIVATION-level facts (scope / per-tool live approval / budget) — those belong to the separate
// Shadow→Canary transition preflight, not to arming the tier.
//
// The live-armed quiesce-then-demote rehearsal (CANARY-ROLLBACK-LIVE-QUIESCE-REHEARSAL, §15) is
// deliberately NOT an arming prerequisite: that rehearsal STARTS by arming the tier, so gating arming
// on it is a bootstrap paradox (you would need the evidence to arm, yet must arm to produce it). It is
// a POST-arming qualification — produced by the controlled drill on an armed synthetic tier and
// required by the deferred real-arming DEPLOYMENT (which also provides the operator producer), the same
// deferred-prerequisite class as the production composition deps. Its durable, build-bound evidence is
// surfaced read-only on the tier status (liveQuiesceRehearsed) so an operator can see whether this
// build has qualified, without arming depending on it.

// liveArmReadiness is the bounded result of the arming node-readiness gate.
type liveArmReadiness struct {
	Ready  bool
	Reason string // bounded classification of the FIRST unmet prerequisite ("" when Ready)
}

// evaluateLiveArmReadiness gathers the LIVE-tier node readiness for a capability from live node
// state. It is fail-closed: the first unmet prerequisite names itself and Ready is false. It reads
// only holders (no mutation, no upstream, no credential).
func evaluateLiveArmReadiness(capb rollout.Capability) liveArmReadiness {
	r := getMCPRollout()
	// The composed live executor is the source of the executor/upstream/credential/boundary-guard
	// facts: it is composed as ONE unit (executor + UpstreamCaller + materialize broker + the
	// final kill-generation and tool-freshness guards), so composition presence asserts them all.
	if !mcpLiveTierFor(capb).composed() {
		return liveArmReadiness{Reason: "live_executor_absent"}
	}
	reg, cat := mcpInventory.sharedInventory()
	// Ordered so the FIRST unmet prerequisite is reported (fail-closed, deterministic).
	switch {
	case !durableEventsHealthy(capb):
		return liveArmReadiness{Reason: "durable_events_degraded"}
	case !globalMCPShadow.inspectionComposed.Load():
		return liveArmReadiness{Reason: "response_inspection_not_ready"}
	case reg == nil:
		return liveArmReadiness{Reason: "registry_unhealthy"}
	case cat == nil:
		return liveArmReadiness{Reason: "catalog_unhealthy"}
	case !mcpPolicy.composed():
		return liveArmReadiness{Reason: "policy_unhealthy"}
	case r.stateFor(capb).Killed():
		return liveArmReadiness{Reason: "emergency_kill_active"}
	case !shadowExitReviewAttested():
		return liveArmReadiness{Reason: "shadow_exit_review_not_passed"}
	case !rollbackPathHealthy(capb):
		return liveArmReadiness{Reason: "rollback_path_unhealthy"}
	case !coordinatorRollbackRehearsedFn(r, capb, false):
		return liveArmReadiness{Reason: "rollback_coordinator_rehearsal_pending"}
	default:
		return liveArmReadiness{Ready: true}
	}
}

// armLiveTier is the authoritative arming entry. It evaluates node readiness and, only if ready,
// arms the tier (composed→armed) via the lifecycle object — the single toggle of the live armed
// bit. Arming activates NO Canary: the rollout mode is untouched, no generation is begun, no
// upstream is reached (§16). Returns the readiness result (so a caller/test sees the exact reason
// on refusal) and the arm error (nil on success).
func armLiveTier(capb rollout.Capability) (liveArmReadiness, error) {
	rd := evaluateLiveArmReadiness(capb)
	err := mcpLiveTierFor(capb).arm(rd.Ready, "armed:"+rd.Reason)
	if err == nil {
		mcpLiveTierFor(capb).setComposeReason("armed")
		logger.Printf("MCP gateway LIVE execution tier ARMED (node ready). Canary is NOT active; a separate Shadow→Canary transition is still required.")
	}
	return rd, err
}

// quiesceLiveTier is the authoritative quiesce (disarm) entry (§6). It un-arms the tier, closes
// new-execution admission, and bounds the drain of in-flight executions to a deadline. It returns
// the number of executions still in flight when the bound elapsed (0 on a clean drain). It
// preserves evidence and trust records, never widens scope, and never silently re-arms. Emergency
// kill remains authoritative regardless. A not-armed tier is a no-op (idempotent).
func quiesceLiveTier(capb rollout.Capability, drainBudget time.Duration) int {
	lt := mcpLiveTierFor(capb)
	deadline := time.Now().Add(drainBudget)
	remaining := lt.quiesce(drainWaitFn(lt, deadline))
	if remaining > 0 {
		logger.Printf("MCP gateway LIVE execution tier quiesced with %d execution(s) still in flight at the drain bound (they complete under emergency-kill authority; no new work admitted)", remaining)
	} else {
		logger.Printf("MCP gateway LIVE execution tier quiesced cleanly (drained; unarmed; evidence and trust preserved).")
	}
	return remaining
}

// drainWaitFn returns a bounded drain wait for quiesce: it blocks until the in-flight count reaches
// zero (signaled by each execution's release via drainCond) or the deadline elapses, and returns
// the residual in-flight count. A deadline that is already past returns the current count
// immediately (no wait). It re-reads the count under the lock, so the release path's broadcast
// races cleanly with the wait.
func drainWaitFn(lt *mcpLiveTier, deadline time.Time) func(inFlight func() int) int {
	return func(_ func() int) int {
		lt.mu.Lock()
		defer lt.mu.Unlock()
		for lt.inFlight > 0 {
			now := time.Now()
			if !now.Before(deadline) {
				return lt.inFlight // bound elapsed — residual in flight
			}
			// Timed wait: a timer broadcasts at the deadline so a stalled in-flight execution can
			// never wedge the drain past its bound. The release path also broadcasts on reaching zero.
			timer := time.AfterFunc(deadline.Sub(now), func() {
				lt.mu.Lock()
				lt.drainCond.Broadcast()
				lt.mu.Unlock()
			})
			lt.drainCond.Wait()
			timer.Stop()
		}
		return 0
	}
}

// mcpLiveTierStatus is the read-only, viewer-safe status for the Gateway live-execution tier. It
// composes the lifecycle state (composed/armed/quiescing), the in-flight/quiesce accounting, the
// bounded gate-denial counters, and the NODE readiness gate result (so an operator can see WHY the
// tier is not armable without any ability to arm). It carries no secret/tenant/subject.
func mcpLiveTierStatus() map[string]any {
	capb := rollout.CapabilityGateway
	m := mcpLiveTierFor(capb).status()
	m["gate_denials"] = mcpLiveGateDenialSnapshot()
	rd := evaluateLiveArmReadiness(capb)
	m["arm_ready"] = rd.Ready
	m["arm_unmet_reason"] = rd.Reason
	// The §15 live-quiesce rehearsal is a POST-arming qualification (not an arming gate — see
	// evaluateLiveArmReadiness); surface its durable, build-bound status read-only so an operator can
	// see whether THIS build has qualified for a real Canary activation.
	m["live_quiesce_rehearsed"] = liveQuiesceRehearsed(capb)
	// The REAL production dependency composition status (§13/§18/§22): whether this node opted into
	// the production live-dependency graph, whether it composed, and the machine-readable per-
	// dependency readiness reason tokens. This is the "real dep status" behind readiness rows
	// 6/7/14/15 (UpstreamCaller / credential path / boundary guards): in a production build the
	// lifecycle-composed bit those rows derive from can ONLY have been set by this real composition
	// (the execution-posture wall pins composeGatewayLiveTierInto's sole production caller as
	// composeProductionGatewayLiveTier). It carries no secret — only bounded tokens.
	m["production_dependencies"] = mcpLiveProdStatusView()
	return m
}
