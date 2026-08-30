package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Authoritative rollback rehearsal — durable root wiring (CANARY-ROLLBACK-COORDINATOR-REHEARSAL).
//
// This closes the last open Canary-activation prerequisite that PR #1252 recorded. The mechanics
// rehearsal (mcp_canary_rollback_rehearsal.go) drives the demotion ladder DIRECTLY through
// persist/restore and proves rollback MECHANICS (readiness fact RollbackPathHealthy, row 19). This
// file drives the SAME Canary→Shadow→Observe ladder through the REAL authoritative coordinator
// (commitRolloutTransitionCore — the single body every production transition runs), so the rehearsal
// fails for every security reason a real rollback would fail: the Gateway Shadow preflight (policy,
// inventory, inspection, listener, usable-tools, live-requirement, durable events), the emergency kill
// switch, config/scope/revision validity (cfg.Validate via SetConfig), and durability (the persist
// gate). On full success it records DISTINCT durable, build-bound evidence that drives the SEPARATE
// readiness fact RollbackCoordinatorRehearsed (reason rollback_coordinator_rehearsal_pending, row 20).
//
// Hard rules (never relax):
//   - the demotion runs ONLY through commitRolloutTransitionCore (never a bypass/second impl);
//   - it NEVER touches live rollout state — it drives a SCRATCH State and persists to a SCRATCH file;
//   - it never routes a live-execution target (Canary/Production) through the core (demotions only);
//   - evidence is written ONLY after every rung committed AND the scratch state recovered to Observe;
//   - a failed rehearsal writes/keeps NO valid PASS record for the current build (fail closed);
//   - the record is bound to the current build identity; corrupt/unknown-schema is quarantined.

// coordinatorRehearsalPath is the per-capability durable coordinator-rehearsal evidence path. It is a
// SIBLING of, and DISTINCT from, rollbackRehearsalPath so the mechanics and authoritative facts never
// share a record.
func coordinatorRehearsalPath(capb rollout.Capability) string {
	name := "mcp_coordinator_rollback_rehearsal_gateway.json"
	if capb == rollout.CapabilityManagement {
		name = "mcp_coordinator_rollback_rehearsal_management.json"
	}
	return filepath.Join(dataDir, name)
}

// coordinatorRehearsalScratchPath is the drill-scoped scratch file the coordinator persists each rung
// to and the drill recovers from. It is DISTINCT from both rolloutStateFileName and the mechanics
// drill's scratch path so no drill can ever clobber live state or another drill.
func coordinatorRehearsalScratchPath(capb rollout.Capability) string {
	name := "mcp_coordinator_rollback_rehearsal_scratch_gateway.json"
	if capb == rollout.CapabilityManagement {
		name = "mcp_coordinator_rollback_rehearsal_scratch_management.json"
	}
	return filepath.Join(dataDir, name)
}

// errCoordinatorRehearsalLiveTarget guards the invariant that the rehearsal never routes a
// live-execution mode through the coordinator core (a demotion is never one; this is defense-in-depth).
var errCoordinatorRehearsalLiveTarget = errors.New("coordinator rollback rehearsal: refusing to route a live-execution target through the coordinator")

// rehearsalDrillConfigsFn is the seam that supplies the drill's Canary/Shadow/Observe configs.
// Production is rehearsalDrillConfigs (shared with the mechanics drill — the SINGLE source of truth for
// the demotion ladder); a test injects an invalid config to exercise the coordinator's cfg.Validate gate.
var rehearsalDrillConfigsFn = rehearsalDrillConfigs

// executeCoordinatorRollbackRehearsalLocked drives the Canary→Shadow→Observe demotion ladder through
// the authoritative coordinator core on a SCRATCH state + SCRATCH file, then recovers from that file
// and returns the committed steps and the recovered mode. The caller MUST hold r.durableMu — the core
// requires it and re-locking would self-deadlock; holding it once is why the rehearsal can route
// through the same coordinator the production commit uses. It NEVER touches live rollout state.
//
// It fails closed: the first rung whose coordinator commit is REJECTED by any gate (Shadow preflight,
// kill, config/revision validity, durability) returns the error and the partial step list, so a
// rollback path a real transition would reject records no evidence.
func (r *mcpRollout) executeCoordinatorRollbackRehearsalLocked(capb rollout.Capability, now time.Time) (steps []string, recoveredMode string, err error) {
	lim := rollout.DefaultLimits()
	canaryCfg, shadowCfg, observeCfg := rehearsalDrillConfigsFn(capb)
	scratch := coordinatorRehearsalScratchPath(capb)
	// The scratch file is transient by construction; remove it however the drill returns.
	defer func() { _ = os.Remove(scratch) }()

	// Establish the scratch Canary START state DIRECTLY (not through the coordinator): committing INTO
	// Canary hits the live-execution activation gate (always fail in this build), and the ROLLBACK — the
	// thing under test — is the demotion, not the setup. From here every transition goes through the core.
	scratchSt := rollout.NewState(capb, lim)
	if serr := scratchSt.SetConfig(canaryCfg, "coordinator-rollback-rehearsal", now.UnixNano()); serr != nil {
		return nil, "", fmt.Errorf("coordinator rehearsal setup canary: %w", serr)
	}
	steps = append(steps, "canary")

	// The INJECTED scratch destination: a scratch State + scratch-file persist + no-op live sinks. The
	// coordinator's SECURITY GATES read node-authoritative state from r/globals regardless of this
	// target, so they are the exact gates a real transition runs; only the side effects land on scratch.
	tgt := commitTransitionTarget{
		st:              scratchSt,
		persist:         func(st *rollout.State) error { return persistRolloutStateTo(st, scratch) },
		setStatus:       func(string) {}, // scratch: never mutate the live persist status
		countTransition: func() {},       // scratch: never bump the live transition metric
	}

	// Index-based range: rollout.SignedConfig is large (832 bytes), so a value range would copy it
	// per iteration (gocritic rangeValCopy).
	rungs := []struct {
		step string
		cfg  rollout.SignedConfig
	}{
		{"shadow", shadowCfg},
		{"observe", observeCfg},
	}
	for i := range rungs {
		rung := &rungs[i]
		if rung.cfg.Mode.RequiresLiveExecution() { // defense-in-depth: a demotion never is
			return steps, "", errCoordinatorRehearsalLiveTarget
		}
		cfg := rung.cfg
		if cerr := r.commitRolloutTransitionCore(tgt, &cfg, "coordinator-rollback-rehearsal", now, rollout.OriginSynthetic); cerr != nil {
			return steps, "", fmt.Errorf("coordinator rehearsal %s: %w", rung.step, cerr)
		}
		if scratchSt.CurrentMode() != cfg.Mode {
			return steps, "", fmt.Errorf("coordinator rehearsal %s did not round-trip: scratch mode %s", rung.step, scratchSt.CurrentMode())
		}
		steps = append(steps, rung.step)
	}

	// Recovery: the coordinator persisted each committed rung to the scratch file. Restore a FRESH state
	// from it through the REAL production restore path and require it to land at the bottom of the
	// ladder — proving the durable persist+recover, not just the in-memory transitions.
	fresh := rollout.NewState(capb, lim)
	if ok, rerr := restoreRolloutStateFrom(fresh, scratch); rerr != nil || !ok {
		return steps, "", fmt.Errorf("coordinator rehearsal recover: ok=%v err=%w", ok, rerr)
	}
	recoveredMode = fresh.CurrentMode().String()
	if recoveredMode != canary.CoordinatorRecoveredMode() {
		return steps, recoveredMode, fmt.Errorf("coordinator rehearsal recovered mode %q, want %q", recoveredMode, canary.CoordinatorRecoveredMode())
	}
	return steps, recoveredMode, nil
}

// recordCoordinatorRehearsal runs the authoritative coordinator-routed rollback rehearsal and, ONLY on
// full success, writes durable build-bound evidence for row 20. It mirrors recordRehearsal's fail-closed
// contract: a drill or evidence-write failure records no valid PASS, and a persist that lands but cannot
// be crash-synced is durably invalidated so a restart cannot resurrect a record the operator was told
// failed. It holds durableMu across the whole sequence so the coordinator core (which requires it) runs
// without re-locking and the read/quarantine of the evidence is race-free against a concurrent writer.
func (r *mcpRollout) recordCoordinatorRehearsal(capb rollout.Capability) error {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	steps, recovered, err := r.executeCoordinatorRollbackRehearsalLocked(capb, time.Now())
	if err != nil {
		logger.Printf("MCP rollout authoritative rollback rehearsal for %s failed (no evidence recorded): %q", capb.String(), sanitizeLog(err.Error()))
		r.invalidatePriorCoordinatorRehearsalLocked(capb)
		return fmt.Errorf("%w: %v", errRolloutPersistFailed, err)
	}
	rec := canary.CoordinatorRollbackRehearsalRecord{
		SchemaVersion:       canary.CoordinatorRollbackRehearsalSchemaVersion,
		Capability:          capb.String(),
		Identity:            currentRuntimeIdentity(),
		Routed:              true,
		Steps:               steps,
		RecoveredMode:       recovered,
		RehearsedAtUnixNano: time.Now().UnixNano(),
	}
	if serr := saveCoordinatorRehearsal(capb, &rec); serr != nil {
		logger.Printf("MCP rollout authoritative rollback rehearsal for %s: evidence write failed: %q", capb.String(), sanitizeLog(serr.Error()))
		r.invalidatePriorCoordinatorRehearsalLocked(capb)
		return fmt.Errorf("%w: %v", errRolloutPersistFailed, serr)
	}
	// A fresh, valid, durable record was just written (the volume is writable), so any prior in-memory
	// poison from an earlier failed re-run is superseded and must be cleared.
	delete(r.coordRehearsalStalePoison, capb)
	return nil
}

// invalidatePriorCoordinatorRehearsalLocked durably invalidates any existing coordinator-rehearsal
// record after a failed rehearsal attempt, so a fresh failure can never leave an earlier PASS for this
// build still qualifying row 20 (Codex P2). It is best-effort: the residual case where even the durable
// content-invalidation fails is logged loudly (a crash could then expose a record the operator was told
// is stale — re-run the rehearsal), but the attempt already returns an error to the caller regardless.
// Callers hold r.durableMu; the helper only touches the fixed operator-owned evidence file.
func (r *mcpRollout) invalidatePriorCoordinatorRehearsalLocked(capb rollout.Capability) {
	if rerr := removeCoordinatorRehearsalDurable(capb); rerr != nil {
		// The prior record could not be durably invalidated (e.g. a read-only volume that also failed the
		// drill/evidence write). It may still be readable on disk, so latching an IN-MEMORY poison here is
		// the only way to keep row 20 fail-closed against the surviving record without relying on the very
		// filesystem that is failing (Codex P2, 2nd round). coordinatorRollbackRehearsalAttestedLocked
		// consults this latch; a successful re-run clears it. Mirrors the mechanics path's write_failed
		// blocker and, like it, is lost on restart (documented residual, gated by durability-health rows).
		if r.coordRehearsalStalePoison == nil {
			r.coordRehearsalStalePoison = make(map[rollout.Capability]bool)
		}
		r.coordRehearsalStalePoison[capb] = true
		logger.Printf("MCP rollout coordinator rehearsal record for %s could not be durably invalidated after a failed rehearsal; row 20 is poisoned in-memory until a successful re-run (a restart on a still-broken volume could re-expose the stale record — re-run the rehearsal): %q", capb.String(), sanitizeLog(rerr.Error()))
		return
	}
	// The record is confirmed gone; clear any prior poison for this capability.
	delete(r.coordRehearsalStalePoison, capb)
}

// coordinatorRehearsalAtomicWrite is the durable-write seam for the coordinator-rehearsal record (tests
// inject failures, including fileutil.ErrReplacedNotSynced, to prove the write fails closed).
var coordinatorRehearsalAtomicWrite = fileutil.AtomicWrite

// saveCoordinatorRehearsal atomically writes the record (0600). Like the mechanics record, an
// ErrReplacedNotSynced (visible but not crash-durable) is returned as a failure AND the not-durable
// record is removed before returning, so a rehearsal reported as not recorded can never satisfy row 20.
func saveCoordinatorRehearsal(capb rollout.Capability, rec *canary.CoordinatorRollbackRehearsalRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	path := coordinatorRehearsalPath(capb)
	return removeVisibleFileAfterNotSyncedWrite(path, coordinatorRehearsalAtomicWrite(path, raw, 0o600))
}

// coordinatorRehearsalInvalidateContent is the durable content-invalidation seam for the coordinator
// rehearsal record. Tests inject a failure to simulate a read-only volume where the prior record cannot
// be truncated (proving row 20 still fails closed via the in-memory poison latch). Production is
// invalidateFileContentDurably.
var coordinatorRehearsalInvalidateContent = invalidateFileContentDurably

// removeCoordinatorRehearsalDurable fails a coordinator-rehearsal record CLOSED (durably invalidate the
// content first, then best-effort remove + dir sync), mirroring removeRollbackRehearsalDurable. It is
// called on every failure exit of recordCoordinatorRehearsal so a failed authoritative rehearsal cannot
// leave an EARLIER build-bound PASS still satisfying row 20 (Codex P2): the operator was just told the
// rehearsal failed, so productionCoordinatorRollbackRehearsed must not keep returning true on stale
// evidence. invalidateFileContentDurably no-ops on a missing file, so this is safe when no prior record
// exists. Only the content invalidation failing is escalated to the caller.
func removeCoordinatorRehearsalDurable(capb rollout.Capability) error {
	path := coordinatorRehearsalPath(capb)
	if ierr := coordinatorRehearsalInvalidateContent(path); ierr != nil {
		return ierr
	}
	if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		logger.Printf("MCP rollout coordinator rehearsal record for %s was durably invalidated but its removal failed (fail-closed holds): %q", capb.String(), sanitizeLog(rerr.Error()))
		return nil
	}
	_ = syncParentDir(path)
	return nil
}

// loadCoordinatorRehearsal reads the durable coordinator-rehearsal record. A missing file returns
// (nil, nil) (the fail-closed default). A corrupt/undecodable file is QUARANTINED and returns (nil, nil).
// A transient read error on an existing file is returned so the caller does not misread it as "absent".
func loadCoordinatorRehearsal(capb rollout.Capability) (*canary.CoordinatorRollbackRehearsalRecord, error) {
	path := coordinatorRehearsalPath(capb)
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed operator-owned path under dataDir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var rec canary.CoordinatorRollbackRehearsalRecord
	if derr := strictDecodeCoordinatorRehearsalJSON(raw, &rec); derr != nil {
		// The only reader (coordinatorRollbackRehearsalAttested) runs under durableMu, the same lock the
		// only writer holds, so this read+quarantine is race-free against a concurrent write.
		quarantineCorruptStateFile("mcp_coordinator_rollback_rehearsal", path, derr)
		return nil, nil
	}
	return &rec, nil
}

// strictDecodeCoordinatorRehearsalJSON decodes exactly one JSON value, rejecting unknown fields and
// trailing data — a malformed or tampered record is corruption, not silently accepted.
func strictDecodeCoordinatorRehearsalJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

// coordinatorRollbackRehearsalAttested reports whether a durable, build-bound, coordinator-routed
// rollback-rehearsal record exists for the capability AND validates against the current runtime
// identity. Fail-closed: any load error, missing/corrupt record, wrong schema, wrong capability,
// not-routed flag, incomplete path, wrong recovered mode, or build mismatch returns false. It NEVER
// writes. This is the sole producer of the row-20 fact.
func (r *mcpRollout) coordinatorRollbackRehearsalAttested(capb rollout.Capability) bool {
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	return r.coordinatorRollbackRehearsalAttestedLocked(capb)
}

// coordinatorRollbackRehearsalAttestedLocked is coordinatorRollbackRehearsalAttested for a caller that
// ALREADY holds r.durableMu — the commit path's Canary activation gate (1c) evaluates the node facts
// INSIDE its serialized section, and durableMu is non-reentrant, so it must consult this locked variant
// rather than the locking wrapper (which would self-deadlock). The read is consistent against an
// in-flight rehearsal because that writer holds durableMu too.
func (r *mcpRollout) coordinatorRollbackRehearsalAttestedLocked(capb rollout.Capability) bool {
	// Fail closed if a failed re-run could not durably invalidate a prior record (the record may still be
	// readable on disk; the in-memory poison latch is the row-20 backstop — Codex P2, 2nd round).
	if r.coordRehearsalStalePoison[capb] {
		return false
	}
	rec, err := loadCoordinatorRehearsal(capb)
	if err != nil {
		return false
	}
	return canary.CoordinatorRehearsalValid(rec, capb.String(), currentRuntimeIdentity())
}
