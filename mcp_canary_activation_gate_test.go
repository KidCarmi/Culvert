package main

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// writeValidShadowExitAttestation writes a durable, current-build PASSED Shadow Exit attestation
// so a test node satisfies the ShadowExitReviewPassed prerequisite. It relies on the caller having
// pointed dataDir at a temp dir.
func writeValidShadowExitAttestation(t *testing.T) {
	t.Helper()
	a := &canary.ShadowExitAttestation{
		SchemaVersion:      canary.ShadowExitAttestationSchemaVersion,
		Status:             canary.ShadowExitStatusPassed,
		ReviewID:           "SXR-test",
		EvidenceDigest:     "digest",
		Identity:           currentRuntimeIdentity(),
		AttestedBy:         "admin",
		AttestedAtUnixNano: 1,
	}
	if err := saveShadowExitAttestation(a); err != nil {
		t.Fatalf("write shadow exit attestation: %v", err)
	}
}

// writeValidRollbackRehearsal writes durable, current-build rollback-rehearsal evidence for a
// capability so a test node satisfies the RollbackPathHealthy prerequisite without running the
// full drill. It relies on the caller having pointed dataDir at a temp dir.
func writeValidRollbackRehearsal(t *testing.T, capb rollout.Capability) {
	t.Helper()
	rec := &canary.RollbackRehearsalRecord{
		SchemaVersion:       canary.RollbackRehearsalSchemaVersion,
		Capability:          capb.String(),
		Identity:            currentRuntimeIdentity(),
		Executed:            true,
		Steps:               canary.RequiredRollbackPath(),
		RehearsedAtUnixNano: 1,
	}
	if err := saveRollbackRehearsal(capb, rec); err != nil {
		t.Fatalf("write rollback rehearsal: %v", err)
	}
}

// withCanaryReadyNode composes the FULL Canary node readiness fixture: the shadow-ready node
// (durable events, inspection, registry/catalog, policy, serving listener), the live tier armed,
// a Shadow Exit attestation, and rollback-rehearsal evidence — everything canary.EvaluateNode
// checks. It is used by tests that must reach a Canary-committable state; a test WITHOUT it proves
// the gate refuses. NOTE: this arms the live tier permanently, so a test using it must NOT also
// commit a Shadow config (the Shadow preflight forbids a live-armed node) — use the surgical
// helpers above for a test that toggles the live tier around a single Canary commit.
func withCanaryReadyNode(t *testing.T) {
	t.Helper()
	withReadyShadowNode(t) // durable events, inspection, inventory, policy, listener + shadow tier
	prevLive := globalExecDeps.gateway.Load()
	globalExecDeps.gateway.Store(true)
	t.Cleanup(func() { globalExecDeps.gateway.Store(prevLive) })
	writeValidShadowExitAttestation(t)
	writeValidRollbackRehearsal(t, rollout.CapabilityGateway)
}

// TestCanaryCommitGate_RefusesWhenNodeNotReady is the §2 authoritative-gate proof: the shared
// commit path refuses a Canary transition unless the Canary activation preflight is Ready — even
// when the coarse exec-deps tier is armed (so modeExecReady passes). Removing the gate lets a
// live-armed-but-not-canary-ready node commit Canary and fails this test.
func TestCanaryCommitGate_RefusesWhenNodeNotReady(t *testing.T) {
	withTempDataDir(t)
	withReadyShadowNode(t)
	// Arm ONLY the live tier: modeExecReady(Canary) now passes, but the node is NOT canary-ready
	// (no Shadow Exit attestation, no rollback rehearsal). The Canary preflight must still refuse.
	prevLive := globalExecDeps.gateway.Load()
	globalExecDeps.gateway.Store(true)
	t.Cleanup(func() { globalExecDeps.gateway.Store(prevLive) })

	// Sanity: the coarse tier IS satisfied, so this is not merely a modeExecReady rejection.
	if !modeExecReady(rollout.ModeCanary, false) {
		t.Fatal("precondition: the live tier must be armed so modeExecReady(Canary) passes")
	}
	r := newTestRollout()
	err := r.commitRolloutTransition(gwCanaryCfg(1), "admin", time.Unix(1000, 0))
	if err != errCanaryActivationPreflightFailed {
		t.Fatalf("a Canary transition on a not-canary-ready node must be refused by the activation preflight, got %v", err)
	}
	if r.gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("mode must stay Disabled after a refused Canary transition, got %s", r.gateway.CurrentMode())
	}
	if r.gateway.Evidence().CanaryStartUnix != 0 {
		t.Fatal("no Canary window may be stamped on a refused transition")
	}
}

// armCanaryActivationInputs points the authoritative-inputs seam at the given valid activation
// inputs for the duration of a test, restoring it on cleanup. Production returns fail-closed
// empties; a test that must reach a committed Canary supplies valid inputs this way.
func armCanaryActivationInputs(t *testing.T, in CanaryActivationInput) {
	t.Helper()
	prev := canaryActivationInputsProbe
	canaryActivationInputsProbe = func(_ rollout.Capability, _ rollout.ScopeSpec, _ uint64) canaryActivationInputs {
		return canaryActivationInputs{
			ToolApprovals:      in.ToolApprovals,
			Budget:             in.Budget,
			ServerUsable:       in.ServerUsable,
			FingerprintCurrent: in.FingerprintCurrent,
		}
	}
	t.Cleanup(func() { canaryActivationInputsProbe = prev })
}

// canaryCfgForScope builds a Canary SignedConfig over a scope (used to drive a committed Canary in
// tests where the FULL activation preflight must pass).
func canaryCfgForScope(scope rollout.ScopeSpec, rev uint64) *rollout.SignedConfig {
	return &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeCanary,
		Scope: scope, ScopeRevision: rev, ConnectorMode: rollout.ConnectorLocalClient,
	}
}

// TestCanaryCommitGate_AllowsWhenFullyReady proves the gate is not a blanket refusal: when the FULL
// canary verdict holds — node canary-ready AND a valid bounded read-first scope AND authoritative
// per-tool live approvals AND a valid budget AND usable/current targets — the same commit path
// admits the Canary transition. This is the positive control that keeps the refusal tests honest (a
// gate that refused everything would pass those while being wrong), and it proves the gate enforces
// the ACTIVATION-level facts (scope/approval/budget), not merely node readiness.
func TestCanaryCommitGate_AllowsWhenFullyReady(t *testing.T) {
	withTempDataDir(t)
	withCanaryReadyNode(t) // node facts + live tier + attestation + rehearsal
	now := time.Unix(1000, 0)
	vin := validCanaryActivationInput(now) // valid scope + per-tool approvals + budget + server + fingerprint
	armCanaryActivationInputs(t, vin)
	// Precondition: the FULL activation preflight is Ready for this scope + inputs.
	if rd := evaluateCanaryActivationPreflight(vin); !rd.Ready {
		t.Fatalf("fixture must make the FULL preflight ready, unmet=%v", rd.Unmet)
	}
	r := newTestRollout()
	if err := r.commitRolloutTransitionAt(canaryCfgForScope(vin.Scope, vin.ScopeRev), "admin", now, rollout.OriginSynthetic); err != nil {
		t.Fatalf("a fully-ready Canary transition must be admitted, got %v", err)
	}
	if r.gateway.CurrentMode() != rollout.ModeCanary {
		t.Fatalf("mode must be Canary after an admitted transition, got %s", r.gateway.CurrentMode())
	}
}

// TestCanaryCommitGate_RefusesWhenActivationInputsMissing proves the ACTIVATION-level half: a node
// that is fully canary-READY but whose authoritative activation inputs are absent (the shipped
// production posture — no approval/budget store) still refuses the Canary transition. This is the
// Codex P1 fix: node readiness alone can never admit Canary.
func TestCanaryCommitGate_RefusesWhenActivationInputsMissing(t *testing.T) {
	withTempDataDir(t)
	withCanaryReadyNode(t) // node canary-ready, but the activation-inputs probe stays production (empties)
	now := time.Unix(1000, 0)
	if rd := evaluateCanaryNodeReadiness(rollout.CapabilityGateway); !rd.Ready {
		t.Fatalf("node must be canary-ready for this test, unmet=%v", rd.Unmet)
	}
	// A valid signed Canary scope, but NO authoritative approvals/budget (the default probe).
	vin := validCanaryActivationInput(now)
	r := newTestRollout()
	if err := r.commitRolloutTransitionAt(canaryCfgForScope(vin.Scope, vin.ScopeRev), "admin", now, rollout.OriginSynthetic); err != errCanaryActivationPreflightFailed {
		t.Fatalf("SECURITY: a canary-ready node with no authoritative approvals/budget must still refuse Canary, got %v", err)
	}
	if r.gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("mode must stay Disabled, got %s", r.gateway.CurrentMode())
	}
}

// TestCanaryCommitGate_MissingAttestationRefuses proves the gate is driven by REAL prerequisites:
// removing just the Shadow Exit attestation from an otherwise canary-ready node re-blocks the
// Canary transition (shadow_exit_review_not_passed).
func TestCanaryCommitGate_MissingAttestationRefuses(t *testing.T) {
	withTempDataDir(t)
	withReadyShadowNode(t)
	prevLive := globalExecDeps.gateway.Load()
	globalExecDeps.gateway.Store(true)
	t.Cleanup(func() { globalExecDeps.gateway.Store(prevLive) })
	// Rollback rehearsal present, but NO attestation.
	writeValidRollbackRehearsal(t, rollout.CapabilityGateway)

	rd := evaluateCanaryNodeReadiness(rollout.CapabilityGateway)
	if rd.Ready || !canaryUnmetHas(rd, canary.ReasonShadowExitNotPassed) {
		t.Fatalf("missing attestation must block with shadow_exit_review_not_passed, got %v", rd.Unmet)
	}
	r := newTestRollout()
	if err := r.commitRolloutTransition(gwCanaryCfg(1), "admin", time.Unix(1000, 0)); err != errCanaryActivationPreflightFailed {
		t.Fatalf("Canary transition without attestation must be refused, got %v", err)
	}
}

// TestCanaryCommitGate_MissingRehearsalRefuses proves the rollback-rehearsal half: removing just
// the executable rehearsal evidence re-blocks the Canary transition (rollback_path_unhealthy).
func TestCanaryCommitGate_MissingRehearsalRefuses(t *testing.T) {
	withTempDataDir(t)
	withReadyShadowNode(t)
	prevLive := globalExecDeps.gateway.Load()
	globalExecDeps.gateway.Store(true)
	t.Cleanup(func() { globalExecDeps.gateway.Store(prevLive) })
	// Attestation present, but NO rollback rehearsal.
	writeValidShadowExitAttestation(t)

	rd := evaluateCanaryNodeReadiness(rollout.CapabilityGateway)
	if rd.Ready || !canaryUnmetHas(rd, canary.ReasonRollbackPathUnhealthy) {
		t.Fatalf("missing rehearsal must block with rollback_path_unhealthy, got %v", rd.Unmet)
	}
	r := newTestRollout()
	if err := r.commitRolloutTransition(gwCanaryCfg(1), "admin", time.Unix(1000, 0)); err != errCanaryActivationPreflightFailed {
		t.Fatalf("Canary transition without rehearsal must be refused, got %v", err)
	}
}

// TestCanaryCommitGate_ProductionAlsoGated proves the gate covers Production too (RequiresLiveExecution
// is Canary OR Production). A Production config on a canary-ready node still fails closed at the
// exec-deps tier first when live is absent; here we prove the preflight refuses a Production
// transition on a not-canary-ready node with the live tier armed.
func TestCanaryCommitGate_ProductionAlsoGated(t *testing.T) {
	withTempDataDir(t)
	withReadyShadowNode(t)
	prevLive := globalExecDeps.gateway.Load()
	globalExecDeps.gateway.Store(true)
	t.Cleanup(func() { globalExecDeps.gateway.Store(prevLive) })

	prodCfg := &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeProduction,
		ScopeRevision: 1,
		Scope:         rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Servers: []string{"s1"}},
		ConnectorMode: rollout.ConnectorLocalClient,
	}
	r := newTestRollout()
	if err := r.commitRolloutTransition(prodCfg, "admin", time.Unix(1000, 0)); err != errCanaryActivationPreflightFailed {
		t.Fatalf("Production transition on a not-canary-ready node must be refused by the preflight, got %v", err)
	}
	if r.gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("mode must stay Disabled after refused Production transition, got %s", r.gateway.CurrentMode())
	}
}
