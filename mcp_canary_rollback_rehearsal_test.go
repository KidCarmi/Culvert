package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// withRehearsalTestEnv points dataDir at a temp dir and pins a deterministic build version,
// restoring both on cleanup (the same isolation the attestation tests use).
func withRehearsalTestEnv(t *testing.T, buildVer string) {
	t.Helper()
	prevDir, prevVer := dataDir, version
	dataDir = t.TempDir()
	version = buildVer
	t.Cleanup(func() { dataDir = prevDir; version = prevVer })
}

// TestRollbackRehearsal_NotAttestedByDefault is the dormancy proof: with no drill run, the
// rollback path is NOT attested for either capability — nothing is created merely by asking.
func TestRollbackRehearsal_NotAttestedByDefault(t *testing.T) {
	withRehearsalTestEnv(t, "v9.9.9")
	for _, capb := range []rollout.Capability{rollout.CapabilityGateway, rollout.CapabilityManagement} {
		if rollbackRehearsalAttested(capb) {
			t.Fatalf("%s: with no drill run, the rollback path must not be attested", capb)
		}
		if _, err := os.Stat(rollbackRehearsalPath(capb)); !os.IsNotExist(err) {
			t.Fatalf("%s: reading attestation status must not create the evidence file", capb)
		}
	}
}

// TestRollbackRehearsal_ExecutableDrillProducesValidEvidence proves the real drill: rehearseRollback
// drives Canary→Shadow→Observe through the persist/restore path, the recorded evidence carries the
// exact required demotion ladder, is bound to the current build, validates, and survives a reload.
func TestRollbackRehearsal_ExecutableDrillProducesValidEvidence(t *testing.T) {
	withRehearsalTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	rec, err := rehearseRollback(capb)
	if err != nil {
		t.Fatalf("rehearseRollback: %v", err)
	}
	if !rec.Executed {
		t.Fatal("a successful drill must record Executed=true")
	}
	want := canary.RequiredRollbackPath()
	if len(rec.Steps) != len(want) {
		t.Fatalf("drill steps = %v, want %v", rec.Steps, want)
	}
	for i := range want {
		if rec.Steps[i] != want[i] {
			t.Fatalf("drill steps = %v, want %v", rec.Steps, want)
		}
	}
	// The durable record validates against the current build after reload (a fresh process would
	// call rollbackRehearsalAttested() → true).
	if !rollbackRehearsalAttested(capb) {
		t.Fatal("a durable, build-bound, fully-executed rehearsal must attest after reload")
	}
	// The scratch file must NOT linger as node state.
	if _, err := os.Stat(rollbackRehearsalScratchPath(capb)); !os.IsNotExist(err) {
		t.Fatal("the drill scratch file must be removed after the drill")
	}
	// The live rollout state file must NOT have been written by the drill (it uses a scratch path).
	if _, err := os.Stat(rolloutStateFileName(capb)); !os.IsNotExist(err) {
		t.Fatal("the drill must not touch the live rollout state file")
	}
}

// TestRollbackRehearsal_BuildMismatchDoesNotAttest proves the identity binding: a drill recorded
// under a different build does not satisfy the current runtime's readiness (a rollback path can
// regress between builds — an ancient drill must not vouch for a materially changed runtime).
func TestRollbackRehearsal_BuildMismatchDoesNotAttest(t *testing.T) {
	withRehearsalTestEnv(t, "v2.0.0")
	capb := rollout.CapabilityGateway
	// Hand-write a well-formed record bound to an OLD build.
	rec := &canary.RollbackRehearsalRecord{
		SchemaVersion:       canary.RollbackRehearsalSchemaVersion,
		Capability:          capb.String(),
		Identity:            canary.RuntimeIdentity{BuildVersion: "v1.0.0"},
		Executed:            true,
		Steps:               canary.RequiredRollbackPath(),
		RehearsedAtUnixNano: 1,
	}
	if err := saveRollbackRehearsal(capb, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	if rollbackRehearsalAttested(capb) {
		t.Fatal("SECURITY: a rehearsal bound to a different build must not attest the current runtime")
	}
}

// TestRollbackRehearsal_IncompletePathDoesNotAttest proves a truncated drill (a record whose steps
// do not cover the full required ladder) never satisfies readiness — a partial reversal is not a
// proven rollback path.
func TestRollbackRehearsal_IncompletePathDoesNotAttest(t *testing.T) {
	withRehearsalTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	rec := &canary.RollbackRehearsalRecord{
		SchemaVersion:       canary.RollbackRehearsalSchemaVersion,
		Capability:          capb.String(),
		Identity:            currentRuntimeIdentity(),
		Executed:            true,
		Steps:               []string{"canary", "shadow"}, // stopped short of Observe
		RehearsedAtUnixNano: 1,
	}
	if err := saveRollbackRehearsal(capb, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	if rollbackRehearsalAttested(capb) {
		t.Fatal("SECURITY: an incomplete demotion ladder must not attest a rollback path")
	}
}

// TestRollbackRehearsal_WrongCapabilityDoesNotAttest proves a gateway drill does not satisfy the
// management rollback path and vice versa (evidence is capability-bound).
func TestRollbackRehearsal_WrongCapabilityDoesNotAttest(t *testing.T) {
	withRehearsalTestEnv(t, "v9.9.9")
	// Run the drill for Gateway only.
	if _, err := rehearseRollback(rollout.CapabilityGateway); err != nil {
		t.Fatalf("rehearseRollback(gateway): %v", err)
	}
	if !rollbackRehearsalAttested(rollout.CapabilityGateway) {
		t.Fatal("gateway drill must attest gateway")
	}
	if rollbackRehearsalAttested(rollout.CapabilityManagement) {
		t.Fatal("a gateway drill must not attest the management rollback path")
	}
}

// TestRollbackRehearsal_CorruptIsQuarantinedAndFailsClosed proves a corrupt/tampered evidence file
// never attests: it is quarantined (moved aside) and treated as absent.
func TestRollbackRehearsal_CorruptIsQuarantinedAndFailsClosed(t *testing.T) {
	withRehearsalTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	path := rollbackRehearsalPath(capb)
	// A well-formed executed record with an extra unknown field is corruption under the strict
	// decoder — the classic tamper shape.
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"capability":"gateway","identity":{"build_version":"v9.9.9"},"executed":true,"steps":["canary","shadow","observe"],"rehearsed_at_unix_nano":1,"injected":true}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if rollbackRehearsalAttested(capb) {
		t.Fatal("SECURITY: a tampered (unknown-field) rehearsal record must not attest")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a corrupt rehearsal record must be quarantined (moved aside)")
	}
	if matches, _ := filepath.Glob(path + ".corrupt.*"); len(matches) == 0 {
		t.Fatal("a corrupt rehearsal record must leave a .corrupt.* quarantine copy")
	}
}

// TestRollbackRehearsal_GarbageBytesFailClosed proves non-JSON garbage never attests.
func TestRollbackRehearsal_GarbageBytesFailClosed(t *testing.T) {
	withRehearsalTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	if err := os.WriteFile(rollbackRehearsalPath(capb), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if rollbackRehearsalAttested(capb) {
		t.Fatal("SECURITY: garbage bytes must never attest a rollback path")
	}
}

// TestRollbackRehearsal_ManagementDrillExecutes proves the drill also round-trips the Management
// ladder (a capability-appropriate enumerable scope), so the rehearsal mechanism is not
// gateway-only by construction.
func TestRollbackRehearsal_ManagementDrillExecutes(t *testing.T) {
	withRehearsalTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityManagement
	if _, err := rehearseRollback(capb); err != nil {
		t.Fatalf("rehearseRollback(management): %v", err)
	}
	if !rollbackRehearsalAttested(capb) {
		t.Fatal("a management drill must attest the management rollback path")
	}
}
