package main

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// errShadowExecDepsNotConfigured is returned when a transition to an executing mode
// (Shadow/Canary/Production) is attempted but the guarded-execution plane is not
// composed (the shipped Observe-only posture). Fail-closed: no partial Shadow state.
//
// It carries an mcperr.Reason so that when it is used as a DP rejection cause the
// resulting acknowledgement reaches the Control Plane with a truthful, alertable
// code. A bare errors.New resolves to ReasonNone under mcperr.ReasonOf, which
// renders a security-relevant nack indistinguishable from an unclassified one.
var errShadowExecDepsNotConfigured = mcperr.New(mcperr.ReasonRolloutTransitionInvalid,
	"rollout.transition", "shadow_execution_dependencies_not_configured")

// errRolloutCapabilityMismatch marks a signed envelope whose embedded rollout config
// names a different capability than the envelope itself — the capability-confusion
// shape the Gateway/Management isolation boundary exists to reject.
var errRolloutCapabilityMismatch = mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch,
	"rollout.transition", "rollout capability does not match the envelope capability")

// errShadowPreflightFailed marks a Shadow transition rejected because the node is not
// genuinely ready to EVALUATE Shadow (the §14 preflight failed). It carries the same
// transition-invalid reason class as the exec-deps gate so a DP nack reaches the CP with
// a truthful, alertable code; the specific bounded reasons are logged, never embedded.
var errShadowPreflightFailed = mcperr.New(mcperr.ReasonRolloutTransitionInvalid,
	"rollout.transition", "shadow_activation_preflight_failed")

// errCanaryActivationPreflightFailed marks a transition into a mode that performs a REAL
// upstream side effect (Canary/Production) rejected because the Canary activation preflight is
// not Ready (§2, Canary Activation Gate). It carries the same transition-invalid reason class as
// the exec-deps and Shadow gates so a DP nack reaches the CP with a truthful, alertable code; the
// specific unmet prerequisites are logged, never embedded. In this build the live tier is never
// armed, so this ALWAYS fires for a Canary/Production transition — the Canary preflight, not a
// syntactically-valid signed config, is the sole authority for a live-execution mode.
var errCanaryActivationPreflightFailed = mcperr.New(mcperr.ReasonRolloutTransitionInvalid,
	"rollout.transition", "canary_activation_preflight_failed")

// errRolloutPersistFailed wraps a durable-persistence failure so callers can reject a
// transition rather than acknowledge a RAM-only mode change.
var errRolloutPersistFailed = errors.New("rollout_persist_failed")

// mcpRollout is the process-wide, DISABLED-BY-DEFAULT PR-11 rollout composition.
// It owns the two capability-local rollout states (Gateway + Management) and the
// bounded low-cardinality rollout metrics. Gateway and Management are physically
// and logically isolated: separate states, scopes, kill switches, transition
// history, and metrics — nothing is shared between them.
//
// Disabled-by-default posture: with no MCP configuration the states are Disabled
// with empty scopes, no listener binds, no upstream pool starts, no executor runs,
// no credential is materialized, and the existing SWG request path is unaffected.
// An active PR-10 snapshot does NOT silently enable Shadow/Canary — the mode comes
// only from an explicitly-published rollout config.
type mcpRollout struct {
	gateway    *rollout.State
	management *rollout.State
	metrics    mcpRolloutMetrics

	// durableMu serializes the whole read-modify-write-persist sequence of every
	// durable rollout mutation (config commit, kill-switch engage/clear, rehearsal
	// record) so two concurrent mutators can never interleave and persist a stale or
	// half-applied snapshot. State.swapMu only serializes the atomic in-memory swap;
	// this guards the surrounding evidence-window + persistence steps too.
	durableMu sync.Mutex

	// persistState records, per capability, the outcome of the last durable-state
	// restore/persist so the admin surface can distinguish recovered vs fresh-default
	// vs degraded persistence. Guarded by persistMu. Values: "fresh" (no durable file
	// yet), "recovered" (restored from disk), "degraded" (corrupt/invalid — kept
	// Disabled, fail-closed), "write_failed" (a persist write failed).
	persistMu       sync.Mutex
	persistGateway  string
	persistManageme string

	// coordRehearsalStalePoison latches, per capability, that a FAILED authoritative rollback rehearsal
	// could not durably invalidate an earlier build-bound PASS record (e.g. the same read-only volume that
	// failed the drill/evidence write also failed the truncation of the prior record). While set, row 20
	// fails CLOSED regardless of the still-readable on-disk record, so a stale PASS cannot qualify after a
	// failed re-run (Codex P2). Set/cleared/read only under durableMu. Process-scoped: like the mechanics
	// path's in-memory write_failed blocker it is lost on restart — a restart on a still-broken volume can
	// re-expose the stale record, which the durability-health prerequisites still gate (documented residual).
	coordRehearsalStalePoison map[rollout.Capability]bool
}

// setPersistStatus records the durable-state health for a capability (admin surface).
func (r *mcpRollout) setPersistStatus(capb rollout.Capability, status string) {
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	if capb == rollout.CapabilityManagement {
		r.persistManageme = status
	} else {
		r.persistGateway = status
	}
}

// persistStatus returns the recorded durable-state health for a capability.
func (r *mcpRollout) persistStatus(capb rollout.Capability) string {
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	s := r.persistGateway
	if capb == rollout.CapabilityManagement {
		s = r.persistManageme
	}
	if s == "" {
		return "fresh"
	}
	return s
}

// rollbackPathReady reports whether the capability's rollback path is durable AND rehearsed —
// read as ONE consistent snapshot. It takes durableMu, which recordRehearsal and every other
// durable read-modify-write-persist holds for its whole sequence, so no rehearsal write can be
// in flight while this reads: the durable rehearsal EVIDENCE and the persistStatus it observes are
// both post-write (never the pre-persist window). Fail-closed: false unless persistence is not
// degraded/write_failed AND a build-bound executable rollback-rehearsal record validates. Lock
// order is durableMu → persistMu (persistStatus takes persistMu), the SAME order recordRehearsal
// uses, so there is no deadlock (Codex P1, PR #1249).
//
// §5 (Canary Activation Gate): readiness is now driven by EXECUTABLE evidence, not a self-attested
// marker. rollbackRehearsalAttested loads the durable canary.RollbackRehearsalRecord that a REAL
// Canary→Shadow→Observe demotion drill produced (through the actual persist/restore path) and
// requires it to validate against the CURRENT build identity. A missing/corrupt/incomplete record,
// or one produced under a different build, fails closed — so an ancient drill against a materially
// changed runtime cannot satisfy the current build's readiness. The pre-existing self-attested
// EvidenceSummary.RollbackRehearsed marker is still stamped by recordRehearsal for the read model,
// but it is NO LONGER what this gate consults.
func (r *mcpRollout) rollbackPathReady(capb rollout.Capability) bool {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	return r.rollbackPathReadyLocked(capb)
}

// rollbackPathReadyLocked is rollbackPathReady for a caller that ALREADY holds r.durableMu — the
// commit path re-validates the full Canary activation verdict INSIDE its serialized section (so a
// concurrent emergencyDisable or attestation revocation cannot make a pre-lock verdict stale before
// install — Codex P1), and durableMu is non-reentrant, so it must consult this locked variant rather
// than the locking wrapper above. It reads persistStatus (its own persistMu) and stateFor (a field),
// neither of which takes durableMu, and the durable rehearsal evidence — consistent against an
// in-flight rehearsal because that writer holds durableMu too.
func (r *mcpRollout) rollbackPathReadyLocked(capb rollout.Capability) bool {
	switch r.persistStatus(capb) {
	case "degraded", "write_failed":
		return false
	}
	st := r.stateFor(capb)
	if st == nil {
		return false
	}
	return rollbackRehearsalAttested(capb)
}

// mcpRolloutMetrics are bounded, low-cardinality counters. No tenant/subject/
// session/URL/argument/tool-name label is ever used.
type mcpRolloutMetrics struct {
	inScope        atomic.Int64
	outOfScope     atomic.Int64
	shadowOverride atomic.Int64
	hardBlocks     atomic.Int64
	executed       atomic.Int64
	upstreamOK     atomic.Int64
	upstreamErr    atomic.Int64
	dlpBlocks      atomic.Int64
	commitFail     atomic.Int64
	emergencies    atomic.Int64
	transitions    atomic.Int64
}

var (
	globalMCPRollout     *mcpRollout
	globalMCPRolloutOnce sync.Once
)

// getMCPRollout returns the process-wide rollout composition, constructing the two
// isolated capability states on first use (both Disabled).
func getMCPRollout() *mcpRollout {
	globalMCPRolloutOnce.Do(func() {
		lim := rollout.DefaultLimits()
		globalMCPRollout = &mcpRollout{
			gateway:    rollout.NewState(rollout.CapabilityGateway, lim),
			management: rollout.NewState(rollout.CapabilityManagement, lim),
		}
	})
	return globalMCPRollout
}

// initMCPRollout is the startup shim (disabled-by-default): it constructs the
// isolated capability states and recovers node-local rollout state from durable
// storage (mode/kill-switch/evidence window), fail-closed to Disabled on corrupt or
// invalid state. It binds no socket and starts no worker.
//
// It also restores the Canary activation runtime (generation + durable budget/abort
// state, §3/§4/§7). In the shipped build no Canary ever activated, so no durable canary
// runtime file exists and this is a no-op that leaves the runtime dormant (generation 0,
// nothing armed) — it composes no executor and reaches no upstream.
func initMCPRollout(_ *startupState) {
	getMCPRollout().restore()
	globalCanaryRuntime.restore()
	// Reconcile the two independently-restored durable domains: disarm any Canary runtime whose
	// rollout mode was clamped (or is otherwise not a live-execution mode) so a restart never resumes
	// an execution-eligible runtime under a mode a fresh commit would reject (Codex P1).
	reconcileCanaryRuntimeAfterRestore()
}

// stateFor returns the capability-local rollout state (never shared).
func (r *mcpRollout) stateFor(capb rollout.Capability) *rollout.State {
	switch capb {
	case rollout.CapabilityManagement:
		return r.management
	default:
		return r.gateway
	}
}

// commitRolloutTransition applies a validated signed rollout config with the full
// durable-transition contract (B-MECH-1/2/3):
//
//  1. Execution-dependency precondition — an executing target mode (Shadow/Canary/
//     Production) is REJECTED fail-closed unless the guarded-execution plane is
//     composed (never today; see mcp_rollout_execdeps.go). No partial Shadow state.
//  2. Atomic in-memory install via State.SetConfig (mode/scope authoritative).
//  3. Evidence-window coupling — BeginWindow is called at the accepted-transition
//     point (idempotent per mode: a continuous Shadow/Canary window is preserved
//     across idempotent re-applies of the same mode; a demotion resets it).
//  4. Restart-durable persistence BEFORE acknowledgement — if the state cannot be
//     durably persisted the transition is ROLLED BACK in memory and rejected, so no
//     externally-acknowledged transition ever exists only in RAM.
//
// It never calls BeginWindow with a synthetic origin; production transitions record
// OriginProduction. Tests inject a clock/origin via commitRolloutTransitionAt.
func (r *mcpRollout) commitRolloutTransition(cfg *rollout.SignedConfig, actor string, now time.Time) error {
	return r.commitRolloutTransitionAt(cfg, actor, now, rollout.OriginProduction)
}

// commitTransitionTarget is the INJECTABLE side-effect destination of the coordinator core. The core's
// SECURITY DECISIONS (exec-deps tier, Gateway Shadow preflight, Canary/Production activation gate) are
// identical regardless of this target — they read node-authoritative facts from r/globals, NEVER from
// the target — so a rehearsal that swaps in a scratch destination exercises the EXACT SAME gates a real
// transition would, while touching no live state. Production supplies the live State + canonical
// persistence + live status/metric sinks (liveCommitTarget); the authoritative rollback rehearsal
// (mcp_canary_coordinator_rehearsal.go) supplies a scratch State + scratch-file persist + no-op sinks.
type commitTransitionTarget struct {
	st              *rollout.State             // the State the transition mutates (live capability state, or a scratch)
	persist         func(*rollout.State) error // how the mutated state is persisted (canonical path, or a scratch path)
	setStatus       func(status string)        // record a persist status ("recovered"/"write_failed") — live sink or no-op
	countTransition func()                     // record a successful transition — live metric or no-op
}

// liveCommitTarget is the PRODUCTION side-effect destination: the live capability State, the canonical
// per-capability persistence, and the live persist-status + transition-metric sinks. Production commits
// route through this so their behavior is byte-identical to the pre-extraction coordinator.
func (r *mcpRollout) liveCommitTarget(capb rollout.Capability) commitTransitionTarget {
	return commitTransitionTarget{
		st:              r.stateFor(capb),
		persist:         persistRolloutState,
		setStatus:       func(status string) { r.setPersistStatus(capb, status) },
		countTransition: func() { r.metrics.transitions.Add(1) },
	}
}

// commitRolloutTransitionAt is commitRolloutTransition with an explicit evidence
// origin so deterministic tests can assert that synthetic elapsed time is labeled
// OriginSynthetic and can never masquerade as OriginProduction evidence. It is a THIN wrapper: it
// acquires durableMu once and delegates to the single authoritative coordinator core, which every
// rollout transition (production AND the authoritative rollback rehearsal) shares.
func (r *mcpRollout) commitRolloutTransitionAt(cfg *rollout.SignedConfig, actor string, now time.Time, origin rollout.EvidenceOrigin) error {
	if cfg == nil {
		return nil
	}
	// Serialize the whole read-modify-write-persist sequence against other durable
	// mutations (kill switch, rehearsal, another commit).
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	return r.commitRolloutTransitionCore(r.liveCommitTarget(cfg.Capability), cfg, actor, now, origin)
}

// commitRolloutTransitionCore is THE single authoritative rollout coordinator. EVERY rollout transition
// — production (commitRolloutTransitionAt) and the authoritative rollback rehearsal
// (executeCoordinatorRollbackRehearsalLocked) — runs through this one body, so a security gate added
// here is enforced for BOTH by construction: parity is architectural, not a duplicated checklist, and is
// pinned by the coordinator-rehearsal parity tests. The caller MUST already hold r.durableMu
// (non-reentrant): both entry points acquire it exactly once, so the core never re-locks (this is what
// lets the rehearsal, which holds durableMu, route through the coordinator without self-deadlock — the
// re-entrancy hazard the previous investigation flagged). The gates read node-authoritative state from
// r/globals; only the transition side effects (in-memory install, evidence window, persist, status,
// metric) touch the injected target, so a scratch target isolates every side effect while the gates stay
// real. The Canary/Production activation gate (1c) reads r's LIVE state, but it is reachable only for a
// live-execution target, which the rehearsal never drives through the core (it drives demotions only).
func (r *mcpRollout) commitRolloutTransitionCore(tgt commitTransitionTarget, cfg *rollout.SignedConfig, actor string, now time.Time, origin rollout.EvidenceOrigin) error {
	st := tgt.st
	// (1) Execution-dependency precondition: fail closed unless the readiness TIER the
	// target mode requires is composed. Shadow requires only the non-executing shadow
	// plane; Canary/Production require the live-execution plane (never composed in this
	// build). modeExecReady owns the shadow-vs-live split.
	if !modeExecReady(cfg.Mode, cfg.Capability == rollout.CapabilityManagement) {
		return errShadowExecDepsNotConfigured
	}
	// (1b) Gateway Shadow activation preflight, enforced in the SHARED commit path so
	// EVERY caller is covered — the CP→DP apply (applyMCPCapabilityEnvelope), the startup
	// reconcile (reconcileRolloutWithAppliers), and any future caller. The coarse
	// modeExecReady tier only proves the shadow evaluator is composed; it does NOT prove
	// the node can actually EVALUATE (policy/inventory/inspection/listener). Without this,
	// startup reconciliation could re-install a recovered active Gateway Shadow envelope
	// right after restore() clamped it, re-advertising Shadow on a node that fails every
	// request closed and restarting the evidence window (Codex P1, PR #1234). Management
	// Shadow is a distinct, read-only concept (no upstream evaluation) and is intentionally
	// NOT gated by this Gateway preflight — its shadow tier gate above suffices.
	if cfg.Mode == rollout.ModeShadow && cfg.Capability == rollout.CapabilityGateway {
		if pf := evaluateShadowActivationPreflight(cfg.Capability, cfg.Scope, cfg.ScopeRevision); !pf.Ready {
			logger.Printf("MCP rollout: Gateway Shadow transition rejected by activation preflight %v (fail-closed)", pf.Reasons)
			return errShadowPreflightFailed
		}
	}
	// (1c) Canary/Production activation gate (§2, Canary Activation Gate). A transition into a
	// mode that performs a REAL upstream side effect is authorized ONLY by the FULL Canary
	// activation preflight, enforced HERE in the shared commit path so EVERY caller is covered —
	// the CP→DP apply (applyMCPCapabilityEnvelope), the startup reconcile
	// (reconcileRolloutWithAppliers), and any future caller. This makes the preflight — not a
	// syntactically-valid signed config — the SOLE authority for a live-execution mode: a Canary
	// config can be perfectly valid and signed yet MUST NOT become active unless the WHOLE
	// canary.Evaluate verdict (node readiness AND the activation-level scope/read-first/per-tool
	// live-approval/budget/server/fingerprint facts) is Ready. The scope comes from the SIGNED
	// config (authoritative); the other activation inputs are resolved from AUTHORITATIVE node
	// state via canaryActivationInputsProbe — NEVER a request-supplied claim — so a signed Canary
	// envelope cannot smuggle an approval or budget past the gate (Codex P1). In this build the
	// authoritative approval/budget store does not exist (the probe returns empties) and the live
	// tier is never armed, so a Canary/Production transition ALWAYS fails here.
	if cfg.Mode.RequiresLiveExecution() {
		// Evaluate the FULL activation verdict INSIDE the serialized section, against THIS rollout's
		// state, so a mutable fail-closed fact that changed after the caller's checks — an
		// emergencyDisable kill engaged, an attestation revoked, the rehearsal evidence removed — cannot
		// leave a stale verdict that installs Canary anyway (Codex P1). It consults the LOCKED readiness
		// path (evaluateCanaryActivationPreflightLocked → rollbackPathReadyLocked): durableMu is
		// non-reentrant and we already hold it, so the locking wrapper would self-deadlock — which in
		// production is the same singleton the commit holds. Activation inputs come from authoritative
		// state via the probe (never the signed config), keeping a valid signed Canary from smuggling an
		// approval/budget past the gate.
		ai := canaryActivationInputsProbe(cfg.Capability, cfg.Scope, cfg.ScopeRevision)
		rd := evaluateCanaryActivationPreflightLocked(r, CanaryActivationInput{
			Capability:         cfg.Capability,
			Scope:              cfg.Scope,
			ScopeRev:           cfg.ScopeRevision,
			ToolApprovals:      ai.ToolApprovals,
			Budget:             ai.Budget,
			ServerUsable:       ai.ServerUsable,
			FingerprintCurrent: ai.FingerprintCurrent,
			Now:                now,
		})
		if !rd.Ready {
			logger.Printf("MCP rollout: %s transition to %s refused by Canary activation preflight %v (fail-closed)",
				cfg.Capability.String(), cfg.Mode.String(), rd.Unmet)
			return errCanaryActivationPreflightFailed
		}
	}
	// Snapshot the prior state for a fail-closed rollback if persistence fails, and
	// for the scope-change continuity check below.
	prevCfg := st.CurrentConfig()
	prevMode := st.CurrentMode()
	prevScopeHash := st.ScopeHash()
	prevEvidence := st.Evidence()
	// (2) Atomic in-memory install.
	if err := st.SetConfig(*cfg, actor, now.UnixNano()); err != nil {
		return err
	}
	// (3) Couple the evidence window to the accepted transition.
	//
	// An IDEMPOTENT re-apply (same mode AND same scope) must touch NO window/soak
	// timer — the DP applier accepts same-revision same-content envelopes idempotently,
	// so ordinary repeated ConfigSnapshot delivery would otherwise reset the soak (and
	// on a genuine change, must restart the window). A real transition (a mode change
	// or a material scope change) resets the ENTERED executing mode's continuous window
	// first — so re-entering Shadow from Canary, or entering under a materially changed
	// scope, starts a fresh window and cannot inherit prior time — then BeginWindow
	// stamps the fresh window + soak.
	sameModeSameScope := prevMode == cfg.Mode && prevScopeHash == st.ScopeHash()
	if !sameModeSameScope {
		st.UpdateEvidence(func(e *rollout.EvidenceSummary) {
			if cfg.Mode.RequiresExecutionPlane() {
				switch cfg.Mode {
				case rollout.ModeShadow:
					e.ShadowStartUnix = 0
				case rollout.ModeCanary, rollout.ModeProduction:
					e.CanaryStartUnix = 0
				}
			}
			e.BeginWindow(cfg.Mode, now.Unix(), origin)
		})
	}
	// (4) Persist before acknowledging; roll back in memory on failure. The persistence DESTINATION is
	// injected (tgt.persist): production writes the canonical per-capability file, the rehearsal a
	// scratch file — the durability GATE is identical, only the target differs.
	if err := tgt.persist(st); err != nil {
		// Revert the in-memory install to the prior config. prevCfg was previously
		// valid, so this should never fail — but if it ever did, we must NOT leave the
		// advanced (new) mode active while telling the caller the transition was
		// rejected: force Disabled, fail-closed and loud.
		if rerr := st.SetConfig(prevCfg, actor, now.UnixNano()); rerr != nil {
			_ = st.SetConfig(rollout.DisabledConfig(cfg.Capability), actor, now.UnixNano())
			logger.Printf("MCP rollout: rollback of %s failed after persist error; forced Disabled (fail-closed): %q", cfg.Capability.String(), sanitizeLog(rerr.Error()))
		}
		st.UpdateEvidence(func(e *rollout.EvidenceSummary) { *e = prevEvidence })
		tgt.setStatus("write_failed")
		return fmt.Errorf("%w: %v", errRolloutPersistFailed, err)
	}
	tgt.setStatus("recovered")
	tgt.countTransition()
	return nil
}

// restore re-establishes both capabilities' node-local rollout state from durable
// storage at startup. A missing file is a fresh state (kept Disabled). A corrupt or
// invalid file fails closed to Disabled and is logged (never a silent promotion).
func (r *mcpRollout) restore() {
	for _, st := range []*rollout.State{r.gateway, r.management} {
		if ok, err := restoreRolloutState(st); err != nil {
			r.setPersistStatus(st.Capability(), "degraded")
			logger.Printf("MCP rollout restore for %s: %q", st.Capability().String(), sanitizeLog(err.Error()))
		} else if ok {
			// Defense-in-depth: a restored EXECUTING mode (Shadow/Canary/Production)
			// must not stand while the guarded-execution plane is not composed. In the
			// shipped build the exec-deps gate blocks such a state from ever being
			// persisted, so this only fires against a hand-crafted state file — clamp it
			// to Disabled (fail-closed) rather than surface a misleading executing label.
			if !modeExecReady(st.CurrentMode(), st.Capability() == rollout.CapabilityManagement) {
				_ = st.SetConfig(rollout.DisabledConfig(st.Capability()), "restore-clamp", time.Now().UnixNano())
				r.setPersistStatus(st.Capability(), "degraded")
				logger.Printf("MCP rollout restore for %s: refused executing mode without required execution deps; clamped to Disabled", st.Capability().String())
				continue
			}
			// A restored Shadow mode must also pass the full activation preflight — not just
			// the coarse exec-deps tier (Codex P1, PR #1234). On a restart where the shadow
			// flag is armed (composition) but the node cannot actually EVALUATE — policy or
			// inventory removed, listener not serving, inspection absent — the node would
			// otherwise advertise an active Shadow rollout while its status preflight says
			// not-ready and the evidence window accrues invalid time. The KILL reason is
			// EXCLUDED: the kill switch is restored independently and is reversible via
			// clearEmergency, so a killed-but-otherwise-ready Shadow node keeps its mode
			// (clamping it to Disabled would make the kill irreversible for the mode).
			if st.CurrentMode() == rollout.ModeShadow {
				restored := st.CurrentConfig()
				if pf := evaluateShadowActivationPreflight(st.Capability(), restored.Scope, restored.ScopeRevision); shadowPreflightUnreadyIgnoringKill(pf) {
					_ = st.SetConfig(rollout.DisabledConfig(st.Capability()), "restore-clamp", time.Now().UnixNano())
					r.setPersistStatus(st.Capability(), "degraded")
					logger.Printf("MCP rollout restore for %s: restored Shadow failed activation preflight %v; clamped to Disabled (fail-closed)", st.Capability().String(), pf.Reasons)
					continue
				}
			}
			// A restored LIVE-EXECUTION mode (Canary/Production) must ALSO pass the FULL activation
			// preflight, not just the coarse exec-deps tier: a prerequisite (attestation, rehearsal,
			// per-tool approval, target, budget) may have been removed while the process was down, and a
			// restart must never resume a live mode a fresh commit would now reject (Codex P1). The scope
			// comes from the restored config; the other activation inputs are resolved from AUTHORITATIVE
			// state via the probe (never trusted from the restored record). In this build the exec-deps
			// check above already clamps every live mode (the live tier is unarmed), so this is the
			// future-arming safety net; the paired runtime disarm is reconcileCanaryRuntimeAfterRestore.
			if st.CurrentMode().RequiresLiveExecution() {
				restored := st.CurrentConfig()
				ai := canaryActivationInputsProbe(st.Capability(), restored.Scope, restored.ScopeRevision)
				rd := evaluateCanaryActivationPreflight(CanaryActivationInput{
					Capability: st.Capability(), Scope: restored.Scope, ScopeRev: restored.ScopeRevision,
					ToolApprovals: ai.ToolApprovals, Budget: ai.Budget,
					ServerUsable: ai.ServerUsable, FingerprintCurrent: ai.FingerprintCurrent, Now: time.Now(),
				})
				if !rd.Ready {
					_ = st.SetConfig(rollout.DisabledConfig(st.Capability()), "restore-clamp", time.Now().UnixNano())
					r.setPersistStatus(st.Capability(), "degraded")
					logger.Printf("MCP rollout restore for %s: restored live mode failed activation preflight %v; clamped to Disabled (fail-closed)", st.Capability().String(), rd.Unmet)
					continue
				}
			}
			r.setPersistStatus(st.Capability(), "recovered")
			logger.Printf("MCP rollout restore for %s: mode=%s (recovered)", st.Capability().String(), st.CurrentMode().String())
		} else {
			r.setPersistStatus(st.Capability(), "fresh")
		}
	}
}

// emergencyDisable engages the capability-local kill switch immediately (admission
// stop) without a CP round trip. It never widens access. The kill-switch state is
// restart-durable: it is persisted after engaging. The in-memory disable is ALWAYS in
// effect (narrowing, safe) even if persistence fails — but a persist failure is
// RETURNED so the caller does not report a durable success the operator would trust
// while a restart could silently re-admit traffic. The disable is never un-done.
func (r *mcpRollout) emergencyDisable(capb rollout.Capability, actor string) error {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	st := r.stateFor(capb)
	st.EngageKillSwitch(actor, time.Now().UnixNano())
	r.metrics.emergencies.Add(1)
	if err := persistRolloutState(st); err != nil {
		r.setPersistStatus(capb, "write_failed")
		logger.Printf("MCP rollout emergency-disable persist for %s failed (disable in effect in memory, NOT restart-durable): %q", capb.String(), sanitizeLog(err.Error()))
		return fmt.Errorf("%w: %v", errRolloutPersistFailed, err)
	}
	r.setPersistStatus(capb, "recovered") // a successful durable write clears any stale write_failed
	return nil
}

// clearEmergency clears the capability-local kill switch (does not change mode) and
// persists the cleared state so the restart-recovered state matches the operator's
// last action.
func (r *mcpRollout) clearEmergency(capb rollout.Capability) error {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	st := r.stateFor(capb)
	st.ClearKillSwitch()
	if err := persistRolloutState(st); err != nil {
		r.setPersistStatus(capb, "write_failed")
		logger.Printf("MCP rollout emergency-clear persist for %s failed: %q", capb.String(), sanitizeLog(err.Error()))
		return fmt.Errorf("%w: %v", errRolloutPersistFailed, err)
	}
	r.setPersistStatus(capb, "recovered") // a successful durable write clears any stale write_failed
	return nil
}

// recordRehearsal EXECUTES a real rollback-rehearsal drill and records durable, build-bound
// evidence (§5, Canary Activation Gate), serialized against other durable mutations. It replaces
// the old self-attested marker: rehearseRollback drives a scratch state Canary→Shadow→Observe
// through the actual persist/restore path and writes evidence ONLY on full success, so a broken
// rollback path records nothing and the caller learns the drill failed. On success it also stamps
// the read-model EvidenceSummary.RollbackRehearsed marker (now backed by a real drill) and
// persists the rollout state. A persist/drill failure is returned so the caller does not report
// durable success.
func (r *mcpRollout) recordRehearsal(capb rollout.Capability) error {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	// (1) Execute the drill and write build-bound executable evidence. A drill or evidence-write
	// failure is fatal to the rehearsal — no marker is stamped and no false success is reported.
	if _, err := rehearseRollback(capb); err != nil {
		logger.Printf("MCP rollout rollback rehearsal drill for %s failed (no evidence recorded): %q", capb.String(), sanitizeLog(err.Error()))
		return fmt.Errorf("%w: %v", errRolloutPersistFailed, err)
	}
	// (2) Stamp the read-model marker (now backed by the real drill above) and persist the
	// rollout state so the status surface stays truthful across a restart.
	st := r.stateFor(capb)
	st.UpdateEvidence(func(e *rollout.EvidenceSummary) { e.RollbackRehearsed = true })
	if err := persistRolloutState(st); err != nil {
		r.setPersistStatus(capb, "write_failed")
		// The build-bound rehearsal record from (1) is ALREADY durable on disk, but persistStatus is
		// in-memory only. A restart that restores the pre-rehearsal rollout snapshot (whose persist just
		// failed) clears the write_failed blocker while the valid record survives — rollbackPathReadyLocked
		// would then accept a rehearsal the operator was told failed (Codex P1). Durably remove the record
		// and revert the in-memory marker so the gate fails CLOSED to "not rehearsed" until a
		// fully-successful drill+persist runs.
		st.UpdateEvidence(func(e *rollout.EvidenceSummary) { e.RollbackRehearsed = false })
		// removeRollbackRehearsalDurable invalidates the record content durably FIRST, so it returns an
		// error ONLY when even that content-invalidation failed (a total filesystem failure). In that
		// residual case the record may survive a crash and the sole remaining guarantee is the in-memory
		// write_failed blocker (lost on restart) — logged loudly so the operator re-runs the rehearsal.
		if rerr := removeRollbackRehearsalDurable(capb); rerr != nil {
			logger.Printf("MCP rollout rehearsal record for %s could not be durably invalidated after a persist error (a crash could expose a record reported as failed; re-run the rehearsal): %q", capb.String(), sanitizeLog(rerr.Error()))
		}
		logger.Printf("MCP rollout rehearsal persist for %s failed: %q", capb.String(), sanitizeLog(err.Error()))
		return fmt.Errorf("%w: %v", errRolloutPersistFailed, err)
	}
	// A successful durable write clears any stale write_failed, so a rehearsal that succeeds
	// after an earlier failure is not stuck reporting the rollback path unhealthy forever
	// (Codex P2, PR #1249). Mirrors commitRolloutTransition's success path.
	r.setPersistStatus(capb, "recovered")
	return nil
}

// mcpRolloutStatus returns a bounded, safe status view for the admin surface. It
// never includes a tenant/subject/token/secret.
func (r *mcpRollout) status() map[string]any {
	capView := func(st *rollout.State) map[string]any {
		ev := st.Evidence()
		return map[string]any{
			"mode":               st.CurrentMode().String(),
			"desired":            st.Desired().String(),
			"scope_hash":         st.ScopeHash(),
			"scope_revision":     st.CurrentConfig().ScopeRevision,
			"killed":             st.Killed(),
			"connector":          st.CurrentConfig().ConnectorMode,
			"history_len":        len(st.History()),
			"evidence_origin":    ev.Origin.String(),
			"shadow_start_unix":  ev.ShadowStartUnix,
			"canary_start_unix":  ev.CanaryStartUnix,
			"soak_start_unix":    ev.SoakStartUnix,
			"rollback_rehearsed": ev.RollbackRehearsed,
			"persistence":        r.persistStatus(st.Capability()),
		}
	}
	return map[string]any{
		"gateway":    capView(r.gateway),
		"management": capView(r.management),
		"metrics": map[string]int64{
			"in_scope":        r.metrics.inScope.Load(),
			"out_of_scope":    r.metrics.outOfScope.Load(),
			"shadow_override": r.metrics.shadowOverride.Load(),
			"hard_blocks":     r.metrics.hardBlocks.Load(),
			"executed":        r.metrics.executed.Load(),
			"upstream_ok":     r.metrics.upstreamOK.Load(),
			"upstream_err":    r.metrics.upstreamErr.Load(),
			"dlp_blocks":      r.metrics.dlpBlocks.Load(),
			"commit_fail":     r.metrics.commitFail.Load(),
			"emergencies":     r.metrics.emergencies.Load(),
			"transitions":     r.metrics.transitions.Load(),
		},
		// Production is unreachable without an externally-verified qualification
		// receipt; this build ships no issuer.
		"production_locked": true,
	}
}

// rolloutFromEnvelope extracts the signed rollout config from a cpdp envelope's
// payload, selecting the block by the envelope's SIGNED capability rather than by
// which block happens to be populated. Block presence is the wrong selector: it is
// attacker/publisher-influenced data, whereas Manifest.Capability is covered by the
// signature and is the same value the applier validated against. Selecting by
// presence would let a stray foreign block decide which rollout config is read.
//
// It returns nil when the envelope carries no rollout change for its own capability.
func rolloutFromEnvelope(env *cpdp.Envelope) *rollout.SignedConfig {
	if env == nil {
		return nil
	}
	switch env.Manifest.Capability {
	case cpdp.CapabilityGateway:
		if g := env.Payload.Gateway; g != nil {
			return g.Rollout
		}
	case cpdp.CapabilityManagement:
		if m := env.Payload.Management; m != nil {
			return m.Rollout
		}
	}
	return nil
}

// rolloutCapabilityMatches reports whether a rollout config's self-declared
// capability agrees with the envelope capability it arrived under.
//
// This is load-bearing rather than redundant: commitRolloutTransition routes by
// cfg.Capability (rollout.State is capability-local), so a disagreeing config would
// commit onto the OTHER capability's state. cpdp now rejects such an envelope at
// validation, but every path that COMMITS a rollout re-checks it locally so the
// guarantee does not depend on validation having run at a different time, on a
// different node, or in a different binary version — notably the startup reconcile
// path, which commits from RECOVERED state whose re-verification deliberately skips
// full payload validation.
func rolloutCapabilityMatches(cfg *rollout.SignedConfig, capb cpdp.Capability) bool {
	if cfg == nil {
		return true
	}
	return (cfg.Capability == rollout.CapabilityManagement) == (capb == cpdp.CapabilityManagement)
}
