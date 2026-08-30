package main

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// withCoordinatorRehearsalEnv arms a node on which the authoritative rollback rehearsal can run: the
// FULL shadow tier composed (so the Gateway Shadow preflight the Canary→Shadow rung hits is satisfied),
// the live tier NOT armed (the Shadow preflight forbids a live-armed node — the rehearsal is run while
// in Shadow, before Canary), a concrete build stamp (evidence must be build-bound), a fresh temp
// dataDir, and a fresh rollout singleton so the coordinator core reads deterministic node state.
func withCoordinatorRehearsalEnv(t *testing.T) *mcpRollout {
	t.Helper()
	withTempDataDir(t)
	pinTestBuildVersion(t)
	withReadyShadowNode(t) // durable events, policy, inventory, inspection, listener + usable-tool probes; live tier OFF
	_ = getMCPRollout()
	prevR := globalMCPRollout
	globalMCPRollout = &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	t.Cleanup(func() { globalMCPRollout = prevR })
	return globalMCPRollout
}

// TestCoordinatorRehearsal_EndToEndPassThroughRealCoordinator is the load-bearing PASS proof: on a
// genuinely rollback-capable node the authoritative rehearsal drives Canary→Shadow→Observe THROUGH the
// real coordinator core (commitRolloutTransitionCore — the same body production uses), recovers the
// scratch state to Observe, records durable build-bound evidence, and closes row 20. It also proves the
// rehearsal never touched live state and left no scratch file.
func TestCoordinatorRehearsal_EndToEndPassThroughRealCoordinator(t *testing.T) {
	r := withCoordinatorRehearsalEnv(t)
	capb := rollout.CapabilityGateway

	// Precondition: row 20 is UNMET before any rehearsal.
	if productionCoordinatorRollbackRehearsed(r, capb, false) {
		t.Fatal("precondition: row 20 must be unmet before a rehearsal")
	}
	// Snapshot live state so we can prove the rehearsal never mutated it.
	liveModeBefore := r.stateFor(capb).CurrentMode()

	if err := r.recordCoordinatorRehearsal(capb); err != nil {
		t.Fatalf("authoritative rehearsal on a ready node must succeed, got %v", err)
	}

	// Row 20 is now CLOSED (both accessors agree).
	if !productionCoordinatorRollbackRehearsed(r, capb, false) {
		t.Fatal("row 20 must be closed after a successful coordinator-routed rehearsal (locking)")
	}
	if !r.coordinatorRollbackRehearsalAttested(capb) {
		t.Fatal("coordinatorRollbackRehearsalAttested must be true after a successful rehearsal")
	}
	// The durable record validates and is coordinator-routed with the full ladder + Observe recovery.
	rec, err := loadCoordinatorRehearsal(capb)
	if err != nil || rec == nil {
		t.Fatalf("a valid record must be loadable, got rec=%v err=%v", rec, err)
	}
	if reason := canary.ValidateCoordinatorRehearsal(rec, capb.String(), currentRuntimeIdentity()); reason != canary.CoordinatorRehearsalOK {
		t.Fatalf("the recorded evidence must validate, got %q", reason)
	}
	if !rec.Routed || rec.RecoveredMode != canary.CoordinatorRecoveredMode() {
		t.Fatalf("evidence must be coordinator-routed and recovered to observe, got routed=%v recovered=%q", rec.Routed, rec.RecoveredMode)
	}

	// SECURITY: the rehearsal must not have mutated live state, the live rollout file, or the mgmt cap.
	if r.stateFor(capb).CurrentMode() != liveModeBefore {
		t.Fatalf("SECURITY: the rehearsal mutated live rollout mode (%s → %s)", liveModeBefore, r.stateFor(capb).CurrentMode())
	}
	if _, serr := os.Stat(rolloutStateFileName(capb)); !os.IsNotExist(serr) {
		t.Fatal("SECURITY: the rehearsal must not write the live rollout state file")
	}
	if _, serr := os.Stat(coordinatorRehearsalScratchPath(capb)); !os.IsNotExist(serr) {
		t.Fatal("the drill scratch file must be removed after the drill")
	}
	if r.coordinatorRollbackRehearsalAttested(rollout.CapabilityManagement) {
		t.Fatal("a gateway rehearsal must not certify the management capability (capability isolation)")
	}
}

// TestCoordinatorRehearsal_RejectionCases is the core-invariant proof: the rehearsal FAILS (records no
// evidence, leaves row 20 unmet) for every security reason a REAL Canary→Shadow rollback through the
// coordinator would fail — because it runs through that same coordinator. Each case breaks exactly one
// node-authoritative gate.
func TestCoordinatorRehearsal_RejectionCases(t *testing.T) {
	capb := rollout.CapabilityGateway
	cases := []struct {
		name   string
		break_ func(t *testing.T, r *mcpRollout)
	}{
		{"shadow_preflight_fails", func(t *testing.T, _ *mcpRollout) {
			// Remove the inventory so the Gateway Shadow preflight the Canary→Shadow rung hits fails.
			publishMCPInventory(mcpInvNotConfigured, "", nil, nil)
		}},
		{"emergency_kill_active", func(t *testing.T, r *mcpRollout) {
			// Engage the emergency kill: the Shadow preflight includes shadowPFKillActive.
			r.stateFor(capb).EngageKillSwitch("test", 1)
		}},
		{"durability_unhealthy", func(t *testing.T, _ *mcpRollout) {
			// Force the persist gate to fail: a rollback that cannot be durably persisted must not pass.
			prev := rolloutStateAtomicWrite
			rolloutStateAtomicWrite = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
			t.Cleanup(func() { rolloutStateAtomicWrite = prev })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := withCoordinatorRehearsalEnv(t)
			tc.break_(t, r)
			if err := r.recordCoordinatorRehearsal(capb); err == nil {
				t.Fatalf("SECURITY: the rehearsal must FAIL when %s, but it passed", tc.name)
			}
			if r.coordinatorRollbackRehearsalAttested(capb) {
				t.Fatalf("SECURITY: a failed rehearsal (%s) must leave row 20 UNMET", tc.name)
			}
			if _, serr := os.Stat(coordinatorRehearsalPath(capb)); !os.IsNotExist(serr) {
				t.Fatalf("a failed rehearsal (%s) must write no durable record", tc.name)
			}
		})
	}
}

// TestCoordinatorRehearsal_InvalidConfigRejected proves the config/scope-validity gate (cfg.Validate
// via SetConfig, inside the coordinator core) fails the rehearsal: a Shadow rung whose scope is not
// enumerable (Shadow/Canary require an enumerable scope) is rejected exactly as a real transition would
// be, so a rollback whose target config the coordinator would reject records no evidence.
func TestCoordinatorRehearsal_InvalidConfigRejected(t *testing.T) {
	r := withCoordinatorRehearsalEnv(t)
	capb := rollout.CapabilityGateway
	// Corrupt the drill's Shadow config to carry a NON-enumerable scope, which cfg.Validate rejects for
	// an executing mode.
	prev := rehearsalDrillConfigsFn
	rehearsalDrillConfigsFn = func(c rollout.Capability) (canaryCfg, shadowCfg, observeCfg rollout.SignedConfig) {
		canaryCfg, shadowCfg, observeCfg = rehearsalDrillConfigs(c)
		shadowCfg.Scope = rollout.ScopeSpec{Capability: c} // no tenants/principals/operations ⇒ not enumerable
		return
	}
	t.Cleanup(func() { rehearsalDrillConfigsFn = prev })
	if err := r.recordCoordinatorRehearsal(capb); err == nil {
		t.Fatal("SECURITY: an invalid Shadow config (non-enumerable scope) must fail the rehearsal")
	}
	if r.coordinatorRollbackRehearsalAttested(capb) {
		t.Fatal("SECURITY: an invalid-config rehearsal must leave row 20 unmet")
	}
}

// TestCoordinatorRehearsal_FailedAttemptInvalidatesPriorPass proves the Codex P2 fail-closed rule: once
// a build has a valid coordinator-rehearsal PASS (row 20 closed), a LATER rehearsal that fails — for any
// reason a real rollback would fail — must durably invalidate that prior PASS so row 20 REOPENS. The
// operator was just told the authoritative rehearsal failed; productionCoordinatorRollbackRehearsed must
// not keep returning true on stale evidence and let Canary activate on it. Both failure exits of
// recordCoordinatorRehearsal are covered: a drill failure (before the evidence write) and an
// evidence-write failure (after a successful drill).
func TestCoordinatorRehearsal_FailedAttemptInvalidatesPriorPass(t *testing.T) {
	capb := rollout.CapabilityGateway
	cases := []struct {
		name   string
		break_ func(t *testing.T)
	}{
		{"drill_failure_after_prior_pass", func(t *testing.T) {
			// Break the scratch durability gate inside the coordinator core so the second drill FAILS
			// (exercises the drill-failure exit). Real os ops used by the invalidation are unaffected.
			prev := rolloutStateAtomicWrite
			rolloutStateAtomicWrite = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
			t.Cleanup(func() { rolloutStateAtomicWrite = prev })
		}},
		{"evidence_write_failure_after_prior_pass", func(t *testing.T) {
			// Let the second drill SUCCEED but fail the evidence write (exercises the save-failure exit).
			prev := coordinatorRehearsalAtomicWrite
			coordinatorRehearsalAtomicWrite = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
			t.Cleanup(func() { coordinatorRehearsalAtomicWrite = prev })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := withCoordinatorRehearsalEnv(t)
			// (1) A first rehearsal succeeds and closes row 20 for this build.
			if err := r.recordCoordinatorRehearsal(capb); err != nil {
				t.Fatalf("the first rehearsal on a ready node must succeed, got %v", err)
			}
			if !productionCoordinatorRollbackRehearsed(r, capb, false) {
				t.Fatal("precondition: row 20 must be closed after the first successful rehearsal")
			}
			// (2) A second rehearsal now fails.
			tc.break_(t)
			if err := r.recordCoordinatorRehearsal(capb); err == nil {
				t.Fatalf("SECURITY: the second rehearsal must FAIL for %s", tc.name)
			}
			// (3) The prior PASS is durably invalidated — row 20 reopens (fail-closed on fresh failure).
			if productionCoordinatorRollbackRehearsed(r, capb, false) {
				t.Fatalf("SECURITY: a failed rehearsal (%s) must invalidate the prior PASS, but row 20 stayed closed", tc.name)
			}
			if r.coordinatorRollbackRehearsalAttested(capb) {
				t.Fatalf("SECURITY: coordinatorRollbackRehearsalAttested must be false after the failed re-run (%s)", tc.name)
			}
			if rec, _ := loadCoordinatorRehearsal(capb); rec != nil {
				t.Fatalf("a failed re-run (%s) must leave no valid durable record, got %+v", tc.name, rec)
			}
		})
	}
}

// TestCoordinatorRehearsal_InvalidationFailurePoisonsRow20 proves the fail-closed backstop for the
// worst case (Codex P2, 2nd round): a re-run in which the SAME filesystem fault fails BOTH the drill and
// the durable invalidation of the prior record (a read-only volume), so the earlier build-bound PASS
// stays READABLE on disk. Discarding the invalidation error would leave row 20 closed on that stale
// record; instead an in-memory poison latch makes productionCoordinatorRollbackRehearsed fail closed
// regardless of the surviving record, and a successful re-run on a recovered volume clears it.
func TestCoordinatorRehearsal_InvalidationFailurePoisonsRow20(t *testing.T) {
	r := withCoordinatorRehearsalEnv(t)
	capb := rollout.CapabilityGateway

	// (1) A first rehearsal succeeds → valid record, row 20 closed.
	if err := r.recordCoordinatorRehearsal(capb); err != nil {
		t.Fatalf("the first rehearsal on a ready node must succeed, got %v", err)
	}
	if !productionCoordinatorRollbackRehearsed(r, capb, false) {
		t.Fatal("precondition: row 20 must be closed after the first successful rehearsal")
	}

	// (2) A re-run where BOTH the drill (scratch persist) AND the durable invalidation of the prior record
	// fail — modeling a read-only volume. The prior record is left untouched and still readable.
	prevW := rolloutStateAtomicWrite
	prevInv := coordinatorRehearsalInvalidateContent
	t.Cleanup(func() { rolloutStateAtomicWrite = prevW; coordinatorRehearsalInvalidateContent = prevInv })
	rolloutStateAtomicWrite = func(string, []byte, os.FileMode) error { return errors.New("read-only fs") }
	coordinatorRehearsalInvalidateContent = func(string) error { return errors.New("read-only fs") }
	if err := r.recordCoordinatorRehearsal(capb); err == nil {
		t.Fatal("SECURITY: the re-run must FAIL when the volume is read-only")
	}

	// (3) Test premise: the prior record is STILL on disk and would validate on its own...
	if rec, _ := loadCoordinatorRehearsal(capb); rec == nil {
		t.Fatal("test premise: the prior record must still be present (invalidation was blocked)")
	}
	// ...but row 20 fails CLOSED via the in-memory poison latch (both accessors agree).
	if productionCoordinatorRollbackRehearsed(r, capb, false) {
		t.Fatal("SECURITY: a failed re-run whose invalidation also failed must poison row 20 despite the readable record")
	}
	if r.coordinatorRollbackRehearsalAttested(capb) {
		t.Fatal("SECURITY: coordinatorRollbackRehearsalAttested must be false under the poison latch")
	}

	// (4) Recovery: once the volume is writable again, a successful re-run clears the poison and re-closes
	// row 20 (a fresh valid record supersedes the poisoned prior one).
	rolloutStateAtomicWrite = prevW
	coordinatorRehearsalInvalidateContent = prevInv
	if err := r.recordCoordinatorRehearsal(capb); err != nil {
		t.Fatalf("the recovery rehearsal on a writable volume must succeed, got %v", err)
	}
	if !productionCoordinatorRollbackRehearsed(r, capb, false) {
		t.Fatal("a successful re-run on a recovered volume must clear the poison and re-close row 20")
	}
}

// TestCoordinatorRehearsal_LiveArmedRejectsBothPathsIdentically pins the security-decision PARITY
// against the live-tier posture (Codex P1). The shared Shadow preflight (gate 1b in
// commitRolloutTransitionCore) forbids a Shadow target while the live-execution tier is armed
// (shadowPFLiveRequirement), and it is the SAME gate for the production coordinator's real Canary→Shadow
// demotion AND the rehearsal drill — so BOTH are rejected identically, and the rehearsal can never record
// a row-20 PASS in a posture where the real demotion would be refused. (This is why the rehearsal legitimately
// runs with the live tier OFF: a real rollback also cannot demote to Shadow while live is armed — it must
// quiesce the live tier first, and the drill models that post-quiesce demotion. In the shipped build the
// live tier is NEVER armed, so this posture is unreachable in production and no real Canary→Shadow rollback
// occurs; faithfully rehearsing the live-armed quiesce-then-demote sequence requires the live tier itself
// and is deferred to the live-tier phase — see the posture report's residual.)
func TestCoordinatorRehearsal_LiveArmedRejectsBothPathsIdentically(t *testing.T) {
	r := withCoordinatorRehearsalEnv(t)
	capb := rollout.CapabilityGateway

	// Simulate the live tier being armed WITHOUT composing any live executor: this flips only the readiness
	// flag liveExecDepsConfigured reads — no LiveExecutor/upstream/broker is composed and
	// markGatewayExecDepsReady is never called. It is a fail-closed simulation (we assert REJECTION), and it
	// is restored on cleanup.
	globalExecDeps.gateway.Store(true)
	t.Cleanup(func() { globalExecDeps.gateway.Store(false) })

	// (A) The production coordinator's real Shadow demotion is rejected by the shared preflight. It fails at
	// gate 1b, BEFORE any state mutation, so live rollout state is untouched.
	_, shadowCfg, _ := rehearsalDrillConfigs(capb)
	if err := r.commitRolloutTransitionAt(&shadowCfg, "test", time.Now(), rollout.OriginSynthetic); !errors.Is(err, errShadowPreflightFailed) {
		t.Fatalf("the real coordinator Shadow demotion with the live tier armed must be rejected by the Shadow preflight, got %v", err)
	}
	// (B) The authoritative rehearsal drill is rejected IDENTICALLY (its Shadow rung hits the same preflight)
	// and records NO row-20 PASS.
	if err := r.recordCoordinatorRehearsal(capb); err == nil {
		t.Fatal("SECURITY: the rehearsal must FAIL when the live tier is armed (same shared Shadow preflight as the real demotion)")
	}
	if r.coordinatorRollbackRehearsalAttested(capb) {
		t.Fatal("SECURITY: no row-20 PASS may be recorded while the live tier is armed")
	}
}

// TestCoordinatorRehearsal_ShadowScopeAdmitsWriteClassTool proves the rehearsal's Shadow config is
// genuinely Shadow-ELIGIBLE (Codex P1): the real usable-tool gate (shadowScopeHasUsableTool ->
// Scope.AdmitsToolForEvaluation) requires the scope to admit the WRITE risk class, so a read-only
// rehearsal scope would fail the real probe with no_usable_shadow_tools even after the tool-approval
// slice makes catalog tools Usable — permanently blocking row 20. This asserts the compiled Shadow scope
// admits a write-class tool for evaluation, so once tools become Usable the coordinator-routed drill can
// actually close row 20. It fails against the previous read-only (RiskRead-only) scope.
func TestCoordinatorRehearsal_ShadowScopeAdmitsWriteClassTool(t *testing.T) {
	_, shadowCfg, _ := rehearsalDrillConfigs(rollout.CapabilityGateway)
	sc, err := rollout.Compile(shadowCfg.Scope, shadowCfg.ScopeRevision, rollout.DefaultLimits())
	if err != nil {
		t.Fatalf("the rehearsal Shadow scope must compile, got %v", err)
	}
	if !sc.AdmitsToolForEvaluation("any-server", "any-tool", "any-fingerprint") {
		t.Fatal("the rehearsal Shadow scope must admit a write-class tool for evaluation, else the real usable-tool probe always yields no_usable_shadow_tools and row 20 can never close")
	}
	// The Canary rung is deliberately read-first (read-only): a real Canary requires it, and the scratch
	// Canary is established by direct SetConfig (never through the Canary activation preflight), so it is
	// not subject to — and must not conflict with — the Shadow rung's write-admitting scope.
	canaryCfg, _, _ := rehearsalDrillConfigs(rollout.CapabilityGateway)
	csc, err := rollout.Compile(canaryCfg.Scope, canaryCfg.ScopeRevision, rollout.DefaultLimits())
	if err != nil {
		t.Fatalf("the rehearsal Canary scope must compile, got %v", err)
	}
	if csc.AdmitsToolForEvaluation("any-server", "any-tool", "any-fingerprint") {
		t.Fatal("the rehearsal Canary scope is read-first and must NOT admit a write-class tool")
	}
}

// TestCoordinatorRehearse_HTTPHandler pins the admin surface: non-admins are forbidden, an unversioned
// build is refused 409, and on a ready node an admin POST runs the coordinator-routed drill and closes
// row 20 (authoritative_rollback_rehearsed:true).
func TestCoordinatorRehearse_HTTPHandler(t *testing.T) {
	const path = "/api/mcp/rollout/rehearse-rollback-authoritative"
	t.Run("rbac_non_admin_forbidden", func(t *testing.T) {
		withCoordinatorRehearsalEnv(t)
		for _, role := range []UIRole{RoleViewer, RoleOperator} {
			if got := mcpReq("POST", path, role, `{"capability":"gateway"}`).Code; got != 403 {
				t.Fatalf("role %v must be forbidden, got %d", role, got)
			}
		}
	})
	t.Run("unversioned_build_refused", func(t *testing.T) {
		withTempDataDir(t)
		prevVer, prevCommit := version, buildCommit
		version, buildCommit = "dev", ""
		t.Cleanup(func() { version, buildCommit = prevVer, prevCommit })
		if got := mcpReq("POST", path, RoleAdmin, `{"capability":"gateway"}`).Code; got != 409 {
			t.Fatalf("unversioned build must be 409, got %d", got)
		}
	})
	t.Run("admin_on_ready_node_closes_row20", func(t *testing.T) {
		r := withCoordinatorRehearsalEnv(t)
		rec := mcpReq("POST", path, RoleAdmin, `{"capability":"gateway"}`)
		if rec.Code != 200 {
			t.Fatalf("admin rehearse on a ready node = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		if !r.coordinatorRollbackRehearsalAttested(rollout.CapabilityGateway) {
			t.Fatal("row 20 must be closed after the HTTP authoritative rehearse")
		}
	})
}
