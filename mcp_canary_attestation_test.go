package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
)

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
		EvidenceDigest:     "deadbeef",
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
		EvidenceDigest: "deadbeef",
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
	if shadowExitReviewAttested() {
		t.Fatal("SECURITY: a tampered (unknown-field) attestation must not attest")
	}
	// The corrupt file must have been quarantined (moved aside), not left in place.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a corrupt attestation must be quarantined (moved aside)")
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
