package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/canary"
)

// testEvidenceDigest is a canonical 64-char lowercase-hex SHA-256 digest used by attestation test
// fixtures so they satisfy canary.ValidEvidenceDigest (Codex P2, round-11).
const testEvidenceDigest = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

// TestShadowExitAttestation_WriteSerializedWithDurableMu is the Codex P1 (round-8) proof: the
// attestation write + compensating cleanup runs under mcpRollout.durableMu — the same lock the
// activation commit holds while it reads the attestation — so a commit can never observe the
// transient visible replacement of a not-synced write. Structural gate: while durableMu is held the
// write must BLOCK, and it must complete once the lock is released.
func TestShadowExitAttestation_WriteSerializedWithDurableMu(t *testing.T) {
	withAttestationTestEnv(t, "v9.9.9")
	rr := getMCPRollout()
	a := &canary.ShadowExitAttestation{
		SchemaVersion: canary.ShadowExitAttestationSchemaVersion,
		Status:        canary.ShadowExitStatusPassed,
		ReviewID:      "SXR-serialize",
		Identity:      currentRuntimeIdentity(),
	}
	rr.durableMu.Lock()
	done := make(chan error, 1)
	go func() { done <- saveShadowExitAttestation(a) }()
	select {
	case <-done:
		rr.durableMu.Unlock()
		t.Fatal("saveShadowExitAttestation must block while durableMu is held (write is not serialized with the commit)")
	case <-time.After(200 * time.Millisecond):
		// Expected: the write is blocked on durableMu.
	}
	rr.durableMu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("save after releasing durableMu must succeed, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("saveShadowExitAttestation must complete once durableMu is released")
	}
}

// TestShadowExitAttestation_NotSyncedWriteFails is the Codex P1 (round-6) durability proof: the
// attestation authorizes a live-mode transition, so a write that is visible but not crash-durable
// (fileutil.ErrReplacedNotSynced) must be returned as a FAILURE — the POST handler then reports
// persisted:false rather than certifying a record a crash could lose.
func TestShadowExitAttestation_NotSyncedWriteFails(t *testing.T) {
	withAttestationTestEnv(t, "v9.9.9")
	prev := attestationAtomicWrite
	attestationAtomicWrite = func(_ string, _ []byte, _ os.FileMode) error { return fileutil.ErrReplacedNotSynced }
	t.Cleanup(func() { attestationAtomicWrite = prev })
	a := &canary.ShadowExitAttestation{
		SchemaVersion: canary.ShadowExitAttestationSchemaVersion,
		Status:        canary.ShadowExitStatusPassed,
		ReviewID:      "SXR-notsynced",
		Identity:      currentRuntimeIdentity(),
	}
	if err := saveShadowExitAttestation(a); err == nil {
		t.Fatal("a not-durably-synced attestation write must be returned as a failure, not certified as persisted")
	}
}

// TestShadowExitAttestation_NotSyncedWriteRemovesVisibleRecord is the Codex P1 (round-7) proof:
// fileutil.ErrReplacedNotSynced is a POST-rename error, so the not-durable record is visible at the
// target. A write reported as failed must not leave a readable record the gate could consume, so the
// possibly-installed record is removed before the error is returned.
func TestShadowExitAttestation_NotSyncedWriteRemovesVisibleRecord(t *testing.T) {
	withAttestationTestEnv(t, "v9.9.9")
	prev := attestationAtomicWrite
	attestationAtomicWrite = func(path string, data []byte, perm os.FileMode) error {
		_ = os.WriteFile(path, data, perm) // the replacement landed and is visible…
		return fileutil.ErrReplacedNotSynced
	}
	t.Cleanup(func() { attestationAtomicWrite = prev })
	a := &canary.ShadowExitAttestation{
		SchemaVersion: canary.ShadowExitAttestationSchemaVersion,
		Status:        canary.ShadowExitStatusPassed,
		ReviewID:      "SXR-notsynced-visible",
		Identity:      currentRuntimeIdentity(),
	}
	if err := saveShadowExitAttestation(a); err == nil {
		t.Fatal("a not-durably-synced attestation write must return an error")
	}
	if _, err := os.Stat(shadowExitAttestationPath()); !os.IsNotExist(err) {
		t.Fatal("a not-synced attestation write must remove the visible record it left")
	}
	if shadowExitReviewAttested() {
		t.Fatal("SECURITY: the gate must not read an attestation the write reported as not persisted")
	}
}

// TestShadowExitAttestation_SweepSerializedWithDurableMu is the Codex P2 (round-10) proof: the
// corrupt-attestation quarantine (sweep) holds mcpRollout.durableMu across its read + rename, so it
// is atomic against a concurrent admin POST/DELETE and can never move aside a valid replacement
// installed after a stale read. Structural gate: while durableMu is held the sweep must BLOCK.
func TestShadowExitAttestation_SweepSerializedWithDurableMu(t *testing.T) {
	withAttestationTestEnv(t, "v9.9.9")
	if err := os.WriteFile(shadowExitAttestationPath(), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	rr := getMCPRollout()
	rr.durableMu.Lock()
	done := make(chan struct{}, 1)
	go func() { sweepCorruptShadowExitAttestation(); done <- struct{}{} }()
	select {
	case <-done:
		rr.durableMu.Unlock()
		t.Fatal("sweepCorruptShadowExitAttestation must block while durableMu is held (quarantine is not serialized)")
	case <-time.After(200 * time.Millisecond):
		// Expected: the sweep is blocked on durableMu.
	}
	rr.durableMu.Unlock()
	select {
	case <-done:
		// Completed once the lock was released.
	case <-time.After(5 * time.Second):
		t.Fatal("sweepCorruptShadowExitAttestation must complete once durableMu is released")
	}
	if _, err := os.Stat(shadowExitAttestationPath()); !os.IsNotExist(err) {
		t.Fatal("the sweep must have quarantined the corrupt file once it acquired the lock")
	}
}

// TestShadowExitAttestation_RevokeIsDurable proves revocation removes the record and syncs the parent
// directory (Codex P1, round-6): removeAttestationDurable deletes the file and returns nil on success,
// so a subsequent readiness read fails closed to not-attested.
func TestShadowExitAttestation_RevokeIsDurable(t *testing.T) {
	withAttestationTestEnv(t, "v9.9.9")
	a := &canary.ShadowExitAttestation{
		SchemaVersion: canary.ShadowExitAttestationSchemaVersion,
		Status:        canary.ShadowExitStatusPassed,
		ReviewID:      "SXR-revoke",
		Identity:      currentRuntimeIdentity(),
	}
	if err := saveShadowExitAttestation(a); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := removeAttestationDurable(); err != nil {
		t.Fatalf("durable revoke must succeed, got %v", err)
	}
	if _, err := os.Stat(shadowExitAttestationPath()); !os.IsNotExist(err) {
		t.Fatal("revocation must remove the durable attestation file")
	}
	if shadowExitReviewAttested() {
		t.Fatal("after revocation the node must fail closed to not-attested")
	}
	// Revoking again (already absent) is still a durable success (nothing to remove).
	if err := removeAttestationDurable(); err != nil {
		t.Fatalf("revoking an absent attestation must be a durable success, got %v", err)
	}
}

// withAttestationTestEnv points dataDir at a temp dir and pins a deterministic build version,
// restoring both on cleanup so the process-global state is not polluted.
func withAttestationTestEnv(t *testing.T, buildVer string) {
	t.Helper()
	prevDir, prevVer := dataDir, version
	dataDir = t.TempDir()
	version = buildVer
	t.Cleanup(func() { dataDir = prevDir; version = prevVer })
}

// TestShadowExitAttestation_NeverAttestedByDefault is the load-bearing dormancy proof: with no
// attestation on disk (the shipped default), the Shadow Exit prerequisite is NOT satisfied —
// nothing is auto-created on startup or because tests pass.
func TestShadowExitAttestation_NeverAttestedByDefault(t *testing.T) {
	withAttestationTestEnv(t, "v9.9.9")
	if shadowExitReviewAttested() {
		t.Fatal("SECURITY: with no attestation on disk, shadowExitReviewAttested() must be false")
	}
	// And no file was created merely by asking.
	if _, err := os.Stat(shadowExitAttestationPath()); !os.IsNotExist(err) {
		t.Fatal("reading attestation status must not create the attestation file")
	}
}

// TestShadowExitAttestation_DurableRoundTrip proves a saved attestation validates and survives
// a reload (new process would call shadowExitReviewAttested() → true).
func TestShadowExitAttestation_DurableRoundTrip(t *testing.T) {
	withAttestationTestEnv(t, "v9.9.9")
	a := &canary.ShadowExitAttestation{
		SchemaVersion:      canary.ShadowExitAttestationSchemaVersion,
		Status:             canary.ShadowExitStatusPassed,
		ReviewID:           "SXR-1",
		EvidenceDigest:     testEvidenceDigest,
		Identity:           currentRuntimeIdentity(),
		AttestedBy:         "admin",
		AttestedAtUnixNano: 1,
	}
	if err := saveShadowExitAttestation(a); err != nil {
		t.Fatalf("save: %v", err)
	}
	if !shadowExitReviewAttested() {
		t.Fatal("a durable PASSED attestation bound to the current build must attest after reload")
	}
}

// TestShadowExitAttestation_BuildMismatchDoesNotAttest proves the identity binding: an
// attestation made against a different build does not cover the current runtime.
func TestShadowExitAttestation_BuildMismatchDoesNotAttest(t *testing.T) {
	withAttestationTestEnv(t, "v2.0.0")
	a := &canary.ShadowExitAttestation{
		SchemaVersion:  canary.ShadowExitAttestationSchemaVersion,
		Status:         canary.ShadowExitStatusPassed,
		ReviewID:       "SXR-1",
		EvidenceDigest: testEvidenceDigest,
		Identity:       canary.RuntimeIdentity{BuildVersion: "v1.0.0"}, // an OLD build
		AttestedBy:     "admin",
	}
	if err := saveShadowExitAttestation(a); err != nil {
		t.Fatalf("save: %v", err)
	}
	if shadowExitReviewAttested() {
		t.Fatal("SECURITY: an attestation bound to a different build must not attest the current runtime")
	}
}

// TestShadowExitAttestation_CorruptIsQuarantinedAndFailsClosed proves a corrupt/tampered file
// never attests: it is moved aside and treated as absent.
func TestShadowExitAttestation_CorruptIsQuarantinedAndFailsClosed(t *testing.T) {
	withAttestationTestEnv(t, "v9.9.9")
	path := shadowExitAttestationPath()
	// Unknown-field tampering: a well-formed PASSED record with an extra field is corruption
	// under the strict decoder.
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"status":"shadow_exit_review_passed","review_id":"x","evidence_digest":"y","identity":{"build_version":"v9.9.9"},"attested_by":"a","injected":true}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The pure read fails closed to not-attested WITHOUT quarantining (quarantine is the sweep's job,
	// serialized under durableMu — Codex P2).
	if shadowExitReviewAttested() {
		t.Fatal("SECURITY: a tampered (unknown-field) attestation must not attest")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the pure read must NOT move the corrupt file aside; the serialized sweep does that")
	}
	// The serialized sweep (invoked by the admin GET surface) quarantines it.
	sweepCorruptShadowExitAttestation()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the sweep must quarantine a corrupt attestation (moved aside)")
	}
	matches, _ := filepath.Glob(path + ".corrupt.*")
	if len(matches) == 0 {
		t.Fatal("a corrupt attestation must leave a .corrupt.* quarantine copy")
	}
}

// TestShadowExitAttestation_GarbageBytesFailClosed proves non-JSON garbage never attests.
func TestShadowExitAttestation_GarbageBytesFailClosed(t *testing.T) {
	withAttestationTestEnv(t, "v9.9.9")
	if err := os.WriteFile(shadowExitAttestationPath(), []byte("not json at all"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if shadowExitReviewAttested() {
		t.Fatal("SECURITY: garbage bytes must never attest")
	}
}
