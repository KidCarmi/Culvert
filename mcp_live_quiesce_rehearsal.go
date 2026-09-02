package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// CANARY-ROLLBACK-LIVE-QUIESCE-REHEARSAL — durable, build-bound evidence (§15).
//
// The prior phase recorded this as a HARD prerequisite deferred to the live-tier phase: the
// authoritative coordinator rollback rehearsal (CANARY-ROLLBACK-COORDINATOR-REHEARSAL) proves the
// Canary→Shadow→Observe demotion works with the live tier OFF, but it could not rehearse the
// LIVE-ARMED "quiesce-then-demote" sequence because the live tier did not exist. This phase composes
// the live tier, so that sequence is now rehearsable: arm → drive controlled synthetic executions →
// QUIESCE (un-arm + drain in-flight, live now OFF) → drive the authoritative coordinator demotion →
// persist/recover proving a restart does not re-arm. The rehearsal uses ONLY a synthetic recording
// upstream and never a real credential (§19), so it is a QUALIFICATION drill, not a production admin
// action; its durable evidence is written when the drill's proofs all hold.
//
// The record is bound to the current build identity: a build change disarms it (a materially changed
// runtime does not inherit a prior build's rehearsal), and a corrupt/unknown-schema record is
// quarantined (fail-closed). liveQuiesceRehearsed() reads it for the operator/status surface and for
// the readiness ledger, which flips from OPEN to CLOSED once a build has a valid record.

const liveQuiesceRehearsalSchemaVersion = 1

// liveQuiesceRehearsalRecord is the durable, node-local, build-bound evidence of a successful
// live-armed quiesce-then-demote rehearsal. It carries NO tenant/subject/secret.
type liveQuiesceRehearsalRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Capability    string `json:"capability"`
	BuildVersion  string `json:"build_version"`
	// Proofs is the ordered list of the drill's asserted proofs (bounded, fixed vocabulary), so the
	// evidence names exactly what the rehearsal established.
	Proofs      []string `json:"proofs"`
	RehearsedAt int64    `json:"rehearsed_at_unix"`
}

// liveQuiesceRehearsalPath is the per-capability durable evidence path (a sibling of the coordinator
// rehearsal record — the two never share a file).
func liveQuiesceRehearsalPath(capb rollout.Capability) string {
	name := "mcp_live_quiesce_rehearsal_gateway.json"
	if capb == rollout.CapabilityManagement {
		name = "mcp_live_quiesce_rehearsal_management.json"
	}
	return filepath.Join(dataDir, name)
}

// liveQuiesceRehearsalAtomicWrite is the durable-write seam (tests inject failures).
var liveQuiesceRehearsalAtomicWrite = fileutil.AtomicWrite

// recordLiveQuiesceRehearsal writes the durable build-bound evidence after a successful drill. A
// not-synced replacement is removed so a write reported failed leaves no consumable record.
func recordLiveQuiesceRehearsal(capb rollout.Capability, proofs []string, now time.Time) error {
	rec := liveQuiesceRehearsalRecord{
		SchemaVersion: liveQuiesceRehearsalSchemaVersion,
		Capability:    capb.String(),
		BuildVersion:  currentRuntimeIdentity().BuildVersion,
		Proofs:        proofs,
		RehearsedAt:   now.Unix(),
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	path := liveQuiesceRehearsalPath(capb)
	return removeVisibleFileAfterNotSyncedWrite(path, liveQuiesceRehearsalAtomicWrite(path, raw, 0o600))
}

// liveQuiesceRehearsed reports whether a VALID, current-build live-quiesce rehearsal record exists.
// Fail-closed: a missing, corrupt, unknown-schema, capability-mismatched, or foreign-build record
// reads false. This is what flips CANARY-ROLLBACK-LIVE-QUIESCE-REHEARSAL from OPEN to CLOSED for a
// build.
func liveQuiesceRehearsed(capb rollout.Capability) bool {
	path := liveQuiesceRehearsalPath(capb)
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed operator-owned path under dataDir
	if err != nil {
		return false
	}
	var rec liveQuiesceRehearsalRecord
	if derr := strictDecodeLiveQuiesceRehearsalJSON(raw, &rec); derr != nil {
		return false
	}
	if rec.SchemaVersion != liveQuiesceRehearsalSchemaVersion || rec.Capability != capb.String() {
		return false
	}
	if rec.BuildVersion != currentRuntimeIdentity().BuildVersion {
		return false // a materially changed build does not inherit a prior build's rehearsal
	}
	return len(rec.Proofs) > 0
}

// strictDecodeLiveQuiesceRehearsalJSON rejects unknown fields and trailing data (a tampered record is
// corruption → fail-closed).
func strictDecodeLiveQuiesceRehearsalJSON(raw []byte, v any) error {
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
