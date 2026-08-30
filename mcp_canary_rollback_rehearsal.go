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

// Rollback-rehearsal executable evidence — durable root wiring (§5, Canary Activation Gate).
//
// canary.RollbackRehearsalRecord is the PURE, schema-versioned, build-bound record + validator.
// This file owns the actual DRILL — a real Canary → Shadow → Observe demotion driven through the
// REAL rollout persist/restore mechanics (ToPersist → AtomicWrite → ReadFile → LoadPersist) on a
// SCRATCH state and a SCRATCH file (never the live rollout state) — and the durable evidence I/O.
//
// This REPLACES the self-attested RollbackRehearsed marker as the readiness authority: the fact
// "rollback path healthy" now requires evidence that THIS build actually exercised the exact
// demotion ladder a first-Canary rollback needs, not that an operator toggled a boolean. Hard
// rules (never relax): the evidence is written ONLY after every step of the drill succeeds
// (fail-closed — a broken rollback path records nothing), it is bound to the current build
// identity (an ancient drill against a materially changed runtime does not satisfy readiness), and
// a corrupt/unknown-schema file is quarantined and treated as absent.

// shadowExitAttestationPath's sibling: the per-capability durable rehearsal-evidence path.
func rollbackRehearsalPath(capb rollout.Capability) string {
	name := "mcp_rollback_rehearsal_gateway.json"
	if capb == rollout.CapabilityManagement {
		name = "mcp_rollback_rehearsal_management.json"
	}
	return filepath.Join(dataDir, name)
}

// rollbackRehearsalScratchPath is the DRILL-scoped scratch file the demotion ladder persists to
// and restores from. It is deliberately DISTINCT from rolloutStateFileName so the drill can
// exercise the real persist/restore code without ever clobbering the live rollout state.
func rollbackRehearsalScratchPath(capb rollout.Capability) string {
	name := "mcp_rollback_rehearsal_scratch_gateway.json"
	if capb == rollout.CapabilityManagement {
		name = "mcp_rollback_rehearsal_scratch_management.json"
	}
	return filepath.Join(dataDir, name)
}

// rehearsalDrillConfigs returns the three ladder configs the drill drives, top→bottom: a
// Canary-configured state, its demotion to Shadow, and its demotion to Observe. Canary and Shadow
// require an ENUMERABLE scope (rollout.SignedConfig.Validate), so both carry a minimal concrete
// tenant+principal inclusion; Observe uses the empty scope. Every config starts from
// DisabledConfig so the selector schema and (Gateway) connector mode are correct by construction.
func rehearsalDrillConfigs(capb rollout.Capability) (canaryCfg, shadowCfg, observeCfg rollout.SignedConfig) {
	// The Canary rung uses a read-first (read-only) scope — the posture a real Canary requires.
	readFirst := rollout.ScopeSpec{
		Capability: capb,
		Tenants:    []string{"rehearsal-tenant"},
		Principals: []string{"rehearsal-principal"},
		Operations: []rollout.RiskClass{rollout.RiskRead},
	}
	// The Shadow rung must be genuinely Shadow-ELIGIBLE: the coordinator's usable-tool gate
	// (shadowScopeHasUsableTool -> Scope.AdmitsToolForEvaluation) requires the scope to admit the WRITE
	// risk class, because tools/call — the thing Shadow evaluates — is write-class; a read-only scope
	// targets no tools/call and would fail the real probe with no_usable_shadow_tools even AFTER the
	// tool-approval slice makes catalog tools Usable, permanently blocking row 20 (Codex P1). So the
	// Shadow scope admits read+write; HighRisk must be true for a write-admitting scope to compile.
	shadowScope := rollout.ScopeSpec{
		Capability: capb,
		Tenants:    []string{"rehearsal-tenant"},
		Principals: []string{"rehearsal-principal"},
		Operations: []rollout.RiskClass{rollout.RiskRead, rollout.RiskWrite},
		HighRisk:   true,
	}
	canaryCfg = rollout.DisabledConfig(capb)
	canaryCfg.Mode = rollout.ModeCanary
	canaryCfg.Scope = readFirst
	canaryCfg.ScopeRevision = 1

	shadowCfg = rollout.DisabledConfig(capb)
	shadowCfg.Mode = rollout.ModeShadow
	shadowCfg.Scope = shadowScope
	shadowCfg.ScopeRevision = 1

	observeCfg = rollout.DisabledConfig(capb)
	observeCfg.Mode = rollout.ModeObserve
	return canaryCfg, shadowCfg, observeCfg
}

// executeRollbackRehearsalDrill drives a SCRATCH rollout state down the required demotion ladder
// (Canary → Shadow → Observe), round-tripping EACH rung through the real persist/restore mechanics
// on a scratch file, and returns the ordered steps that actually round-tripped. It fails closed:
// the first step whose SetConfig, persist, restore, or mode-assertion fails returns an error (and
// the partial step list), so a rollback path that does not actually work records no evidence.
//
// It NEVER touches the live rollout state or the live rollout state file — it constructs its own
// throwaway rollout.State objects and writes to rollbackRehearsalScratchPath.
func executeRollbackRehearsalDrill(capb rollout.Capability) ([]string, error) {
	lim := rollout.DefaultLimits()
	canaryCfg, shadowCfg, observeCfg := rehearsalDrillConfigs(capb)
	scratch := rollbackRehearsalScratchPath(capb)
	// Remove the scratch file however the drill returns — it is transient by construction and
	// must not linger as node state.
	defer func() { _ = os.Remove(scratch) }()

	ladder := []struct {
		step string
		cfg  rollout.SignedConfig
	}{
		{"canary", canaryCfg},
		{"shadow", shadowCfg},
		{"observe", observeCfg},
	}

	steps := make([]string, 0, len(ladder))
	work := rollout.NewState(capb, lim)
	for i := range ladder {
		rung := ladder[i]
		if err := work.SetConfig(rung.cfg, "rollback-rehearsal", time.Now().UnixNano()); err != nil {
			return steps, fmt.Errorf("rehearsal set %s: %w", rung.step, err)
		}
		// Persist the current rung to the SCRATCH file through the REAL production persistence
		// (persistRolloutStateTo — the same ToPersist + marshal + AtomicWrite chain persistRolloutState
		// uses), so a regression in that wrapper is caught by the drill rather than hidden behind a
		// parallel implementation (Codex P1). Only the destination path is injected.
		if err := persistRolloutStateTo(work, scratch); err != nil {
			return steps, fmt.Errorf("rehearsal persist %s: %w", rung.step, err)
		}
		// Restore into a FRESH state through the REAL production restore (restoreRolloutStateFrom):
		// it re-validates + re-compiles and fails closed to Disabled on any error, so a rung that does
		// not survive the durable round-trip fails the mode assertion below.
		fresh := rollout.NewState(capb, lim)
		if ok, rerr := restoreRolloutStateFrom(fresh, scratch); rerr != nil || !ok {
			return steps, fmt.Errorf("rehearsal restore %s: ok=%v err=%w", rung.step, ok, rerr)
		}
		if fresh.CurrentMode() != rung.cfg.Mode {
			return steps, fmt.Errorf("rehearsal %s did not round-trip: restored mode %s", rung.step, fresh.CurrentMode())
		}
		steps = append(steps, rung.step)
	}
	return steps, nil
}

// rehearseRollback executes the drill and, ONLY on full success, writes durable build-bound
// evidence. A drill failure returns the error and writes nothing (fail-closed). It is the single
// producer of a rollback-rehearsal record.
func rehearseRollback(capb rollout.Capability) (canary.RollbackRehearsalRecord, error) {
	steps, err := executeRollbackRehearsalDrill(capb)
	if err != nil {
		return canary.RollbackRehearsalRecord{}, err
	}
	rec := canary.RollbackRehearsalRecord{
		SchemaVersion:       canary.RollbackRehearsalSchemaVersion,
		Capability:          capb.String(),
		Identity:            currentRuntimeIdentity(),
		Executed:            true,
		Steps:               steps,
		RehearsedAtUnixNano: time.Now().UnixNano(),
	}
	if serr := saveRollbackRehearsal(capb, &rec); serr != nil {
		return canary.RollbackRehearsalRecord{}, serr
	}
	return rec, nil
}

// saveRollbackRehearsal atomically writes the rehearsal record (0600). The rehearsal is a DURABLE
// Canary prerequisite that a later activation consumes, so a write that is visible but not
// crash-durable must NOT be certified: fileutil.ErrReplacedNotSynced (the replacement landed but the
// parent-dir fsync failed) is returned as a failure like any other, so recordRehearsal never reports
// a drill as durably recorded when an immediate crash could lose it (Codex P1).
func saveRollbackRehearsal(capb rollout.Capability, rec *canary.RollbackRehearsalRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	// ErrReplacedNotSynced is POST-rename, so a not-durable rehearsal record is already visible at the
	// target — remove it before returning the failure so a drill reported as not recorded cannot be
	// consumed by the activation gate (Codex P1).
	path := rollbackRehearsalPath(capb)
	return removeVisibleFileAfterNotSyncedWrite(path, rehearsalAtomicWrite(path, raw, 0o600))
}

// rehearsalAtomicWrite is the durable-write seam for the rehearsal record (tests inject failures,
// including fileutil.ErrReplacedNotSynced, to prove the write fails closed).
var rehearsalAtomicWrite = fileutil.AtomicWrite

// removeRollbackRehearsalDurable fails a rehearsal record CLOSED so a restart cannot let a still-present
// valid record satisfy the activation gate after the operator was told the rehearsal failed (Codex P1).
// The in-memory "unhealthy" blocker (persistStatus write_failed) does NOT survive a restart, so the
// on-disk record must be made restart-durably invalid. It mirrors removeVisibleFileAfterNotSyncedWrite:
// DURABLY INVALIDATE THE CONTENT FIRST — truncate the record to empty and fsync the FILE inode, which
// is independent of the parent-directory fsync — so even if the unlink or its dir-sync below cannot be
// confirmed, a crash-restored directory entry points to an EMPTY file that strictDecode rejects
// (quarantined on read → not attested). Only that content-invalidation failing is escalated to the
// caller; a best-effort remove/dir-sync failure afterwards cannot expose a VALID record and is logged,
// not returned. A missing file is success (nothing to invalidate).
func removeRollbackRehearsalDurable(capb rollout.Capability) error {
	path := rollbackRehearsalPath(capb)
	if ierr := invalidateFileContentDurably(path); ierr != nil {
		return ierr // the record could not be made durably invalid — the caller must escalate
	}
	// Best-effort remove the now-empty file + dir sync for cleanliness. The content is already durably
	// invalid, so a failure here no longer risks a valid record surviving a crash — log, do not escalate.
	if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		logger.Printf("MCP rollout rehearsal record for %s was durably invalidated but its removal failed (fail-closed holds): %q", capb.String(), sanitizeLog(rerr.Error()))
		return nil
	}
	_ = syncParentDir(path)
	return nil
}

// loadRollbackRehearsal reads the durable rehearsal record. A missing file returns (nil, nil) (no
// evidence — the fail-closed default). A corrupt/undecodable file is QUARANTINED (moved aside) and
// returns (nil, nil) so a tampered record never satisfies readiness. A transient read error on an
// existing file is returned so the caller does not misread it as "absent".
func loadRollbackRehearsal(capb rollout.Capability) (*canary.RollbackRehearsalRecord, error) {
	path := rollbackRehearsalPath(capb)
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed operator-owned path under dataDir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var rec canary.RollbackRehearsalRecord
	if derr := strictDecodeRehearsalJSON(raw, &rec); derr != nil {
		// Quarantine the corrupt record. Unlike the attestation, this read/quarantine has NO
		// concurrent-writer race: rollbackRehearsalAttested (its only caller) runs exclusively from
		// rollbackPathReadyLocked, which holds mcpRollout.durableMu — the SAME lock recordRehearsal
		// (the only writer) holds — so the read and any write are already mutually exclusive and a
		// valid replacement can never be installed between this read and the rename (Codex P2).
		quarantineCorruptStateFile("mcp_rollback_rehearsal", path, derr)
		return nil, nil
	}
	return &rec, nil
}

// strictDecodeRehearsalJSON decodes exactly one JSON value into v, rejecting unknown fields and
// trailing data — the same discipline the Shadow Exit attestation uses so a malformed or tampered
// record is corruption, not silently accepted.
func strictDecodeRehearsalJSON(raw []byte, v any) error {
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

// rollbackRehearsalAttested reports whether a durable, build-bound rollback-rehearsal record
// exists for the capability AND validates against the current runtime identity. Fail-closed: any
// load error, missing/corrupt record, wrong schema, wrong capability, incomplete path, or build
// mismatch returns false. It NEVER writes.
func rollbackRehearsalAttested(capb rollout.Capability) bool {
	rec, err := loadRollbackRehearsal(capb)
	if err != nil {
		return false
	}
	return canary.RehearsalValid(rec, capb.String(), currentRuntimeIdentity())
}
