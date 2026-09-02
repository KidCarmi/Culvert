package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Restart-durable MCP rollout state (B-MECH-3).
//
// Rollout mode, kill-switch state, and the continuous evidence window (Shadow/
// Canary/soak start timestamps + origin) MUST survive a process restart, or any
// claimed >=14-day continuous Shadow qualification window is mechanically invalid:
// a restart would silently reset the window to zero. The rollout.StatePersist DTO
// already exists (ToPersist/LoadPersist); this file is the missing production
// writer + restore path.
//
// Storage: one 0600 JSON file per capability under <dataDir>, written atomically via
// fileutil.AtomicWrite (rename-into-place; never a torn file). The DTO is versioned
// and capability-checked on load. Corrupt/invalid/version-mismatched state FAILS
// CLOSED: LoadPersist re-validates and degrades to Disabled rather than silently
// restoring a more permissive mode. No secret, token, credential, or request payload
// is ever written (StatePersist carries only mode/scope-config/evidence/history).

// rolloutStateFileName returns the per-capability durable state path under dataDir.
func rolloutStateFileName(capb rollout.Capability) string {
	name := "mcp_rollout_state_gateway.json"
	if capb == rollout.CapabilityManagement {
		name = "mcp_rollout_state_management.json"
	}
	return filepath.Join(dataDir, name)
}

// persistRolloutState atomically writes the capability's restart-durable rollout
// state. It returns an error on any write/serialize failure so the caller can fail
// the transition closed (no externally-acknowledged transition may exist only in
// RAM). The file is 0600 (mode/evidence are node-local operator state).
func persistRolloutState(st *rollout.State) error {
	if st == nil {
		return fmt.Errorf("rollout persist: nil state")
	}
	return persistRolloutStateTo(st, rolloutStateFileName(st.Capability()))
}

// persistRolloutStateTo is the path-injectable core of persistRolloutState: it serializes st and
// atomically writes it to path. Production persistence uses persistRolloutState (the canonical
// per-capability path); the rollback-rehearsal drill (mcp_canary_rollback_rehearsal.go) uses this
// with a scratch path so it exercises the REAL persistence code — the same ToPersist + marshal +
// AtomicWrite chain — rather than a parallel implementation that could drift from production (Codex
// P1). A nil state is a programmer error, not a durable-write failure.
func persistRolloutStateTo(st *rollout.State, path string) error {
	if st == nil {
		return fmt.Errorf("rollout persist: nil state")
	}
	p := st.ToPersist()
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("rollout persist: marshal: %w", err)
	}
	if err := rolloutStateAtomicWrite(path, data, 0o600); err != nil {
		return fmt.Errorf("rollout persist: write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// rolloutStateAtomicWrite is the durable-write seam for the rollout state file. Production is
// fileutil.AtomicWrite; tests inject a failure to exercise the coordinator's fail-closed durability
// gate (a rollback that cannot be durably persisted must be rejected — for a real transition and for
// the authoritative rehearsal alike, since both run through the same core).
var rolloutStateAtomicWrite = fileutil.AtomicWrite

// restoreRolloutState reads and restores a capability's durable rollout state into
// st. A MISSING file is a genuinely-new state and is NOT an error (returns false,
// nil — keep the Disabled default). A present-but-corrupt/invalid file FAILS CLOSED:
// LoadPersist re-validates and degrades to Disabled, and a decode error is reported
// so the operator can see degraded persistence (the caller keeps the safe Disabled
// default). It never silently promotes to a more permissive mode.
func restoreRolloutState(st *rollout.State) (restored bool, err error) {
	return restoreRolloutStateFrom(st, rolloutStateFileName(st.Capability()))
}

// restoreRolloutStateFrom is the path-injectable core of restoreRolloutState (see that function for
// the fail-closed contract). The rollback-rehearsal drill uses it with a scratch path so it restores
// through the SAME production read + unmarshal + LoadPersist chain it is meant to prove (Codex P1).
func restoreRolloutStateFrom(st *rollout.State, path string) (restored bool, err error) {
	data, rerr := os.ReadFile(path) // #nosec G304 -- fixed operator-owned path under dataDir
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return false, nil // fresh state; not an error
		}
		return false, fmt.Errorf("rollout restore: read %s: %w", filepath.Base(path), rerr)
	}
	var p rollout.StatePersist
	if uerr := json.Unmarshal(data, &p); uerr != nil {
		// Corrupt file: fail closed — leave st at its Disabled default and report.
		return false, fmt.Errorf("rollout restore: corrupt %s (kept Disabled): %w", filepath.Base(path), uerr)
	}
	if lerr := st.LoadPersist(p); lerr != nil {
		// Invalid/mismatched persisted state: LoadPersist already degraded to Disabled.
		return false, fmt.Errorf("rollout restore: invalid %s (kept Disabled): %w", filepath.Base(path), lerr)
	}
	return true, nil
}
