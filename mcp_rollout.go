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
func initMCPRollout(_ *startupState) {
	getMCPRollout().restore()
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

// commitRolloutTransitionAt is commitRolloutTransition with an explicit evidence
// origin so deterministic tests can assert that synthetic elapsed time is labeled
// OriginSynthetic and can never masquerade as OriginProduction evidence.
func (r *mcpRollout) commitRolloutTransitionAt(cfg *rollout.SignedConfig, actor string, now time.Time, origin rollout.EvidenceOrigin) error {
	if cfg == nil {
		return nil
	}
	// Serialize the whole read-modify-write-persist sequence against other durable
	// mutations (kill switch, rehearsal, another commit).
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	st := r.stateFor(cfg.Capability)
	// (1) Execution-dependency precondition: fail closed unless the readiness TIER the
	// target mode requires is composed. Shadow requires only the non-executing shadow
	// plane; Canary/Production require the live-execution plane (never composed in this
	// build). modeExecReady owns the shadow-vs-live split.
	if !modeExecReady(cfg.Mode, cfg.Capability == rollout.CapabilityManagement) {
		return errShadowExecDepsNotConfigured
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
	// (4) Persist before acknowledging; roll back in memory on failure.
	if err := persistRolloutState(st); err != nil {
		// Revert the in-memory install to the prior config. prevCfg was previously
		// valid, so this should never fail — but if it ever did, we must NOT leave the
		// advanced (new) mode active while telling the caller the transition was
		// rejected: force Disabled, fail-closed and loud.
		if rerr := st.SetConfig(prevCfg, actor, now.UnixNano()); rerr != nil {
			_ = st.SetConfig(rollout.DisabledConfig(cfg.Capability), actor, now.UnixNano())
			logger.Printf("MCP rollout: rollback of %s failed after persist error; forced Disabled (fail-closed): %q", cfg.Capability.String(), sanitizeLog(rerr.Error()))
		}
		st.UpdateEvidence(func(e *rollout.EvidenceSummary) { *e = prevEvidence })
		r.setPersistStatus(cfg.Capability, "write_failed")
		return fmt.Errorf("%w: %v", errRolloutPersistFailed, err)
	}
	r.setPersistStatus(cfg.Capability, "recovered")
	r.metrics.transitions.Add(1)
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
	return nil
}

// recordRehearsal records a rollback rehearsal (durable evidence) and persists it,
// serialized against other durable mutations. A persist failure is returned so the
// caller does not report durable success while a restart could lose the evidence.
func (r *mcpRollout) recordRehearsal(capb rollout.Capability) error {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	st := r.stateFor(capb)
	st.UpdateEvidence(func(e *rollout.EvidenceSummary) { e.RollbackRehearsed = true })
	if err := persistRolloutState(st); err != nil {
		r.setPersistStatus(capb, "write_failed")
		logger.Printf("MCP rollout rehearsal persist for %s failed: %q", capb.String(), sanitizeLog(err.Error()))
		return fmt.Errorf("%w: %v", errRolloutPersistFailed, err)
	}
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
