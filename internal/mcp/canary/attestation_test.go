package canary

import "testing"

// canonicalTestDigest is a valid 64-char lowercase-hex SHA-256 digest for attestation fixtures
// (satisfies ValidEvidenceDigest — Codex P2, round-11).
const canonicalTestDigest = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

// validTestCommit is a lowercase-hex commit digest; validTestBuild is the composed display/equality
// stamp. Valid() checks the RAW commit (the Commit field), not a parse of BuildVersion — Codex
// round-23 P1 — so a valid test identity must set BOTH (validTestIdentity).
const (
	validTestCommit = "abc123def456"
	validTestBuild  = "v1.2.3+" + validTestCommit
)

// validTestIdentity is a valid, unique runtime identity (composed BuildVersion + raw Commit).
func validTestIdentity() RuntimeIdentity {
	return RuntimeIdentity{BuildVersion: validTestBuild, Commit: validTestCommit}
}

func validAttestation() *ShadowExitAttestation {
	return &ShadowExitAttestation{
		SchemaVersion:      ShadowExitAttestationSchemaVersion,
		Status:             ShadowExitStatusPassed,
		ReviewID:           "SXR-2026-001",
		EvidenceDigest:     canonicalTestDigest,
		Identity:           validTestIdentity(),
		AttestedBy:         "admin@culvert",
		AttestedAtUnixNano: 1_700_000_000_000_000_000,
	}
}

func curIdentity() RuntimeIdentity { return validTestIdentity() }

func TestValidateAttestation_ValidPasses(t *testing.T) {
	if r := ValidateAttestation(validAttestation(), curIdentity()); r != AttestationOK {
		t.Fatalf("a well-formed PASSED attestation bound to the current build must validate, got %q", r)
	}
	if !AttestationValid(validAttestation(), curIdentity()) {
		t.Fatal("AttestationValid must be true for a valid attestation")
	}
}

// TestValidateAttestation_ForgedMissingStaleCorrupt is the §1 mutation proof: a forged (wrong
// schema/status), missing (nil), stale (build mismatch), or field-stripped record must NOT
// satisfy readiness.
func TestValidateAttestation_ForgedMissingStaleCorrupt(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ShadowExitAttestation)
		nilRec bool
		want   AttestationReason
	}{
		{"missing", nil, true, AttestationMissing},
		{"schema_newer", func(a *ShadowExitAttestation) { a.SchemaVersion = ShadowExitAttestationSchemaVersion + 1 }, false, AttestationSchemaUnknown},
		{"schema_older", func(a *ShadowExitAttestation) { a.SchemaVersion = 0 }, false, AttestationSchemaUnknown},
		{"not_passed", func(a *ShadowExitAttestation) { a.Status = ShadowExitStatusUnset }, false, AttestationNotPassed},
		{"forged_status", func(a *ShadowExitAttestation) { a.Status = "totally_passed_trust_me" }, false, AttestationNotPassed},
		{"no_review_id", func(a *ShadowExitAttestation) { a.ReviewID = "" }, false, AttestationNoReviewID},
		{"no_evidence", func(a *ShadowExitAttestation) { a.EvidenceDigest = "" }, false, AttestationNoEvidence},
		{"no_attestor", func(a *ShadowExitAttestation) { a.AttestedBy = "" }, false, AttestationNoAttestor},
		{"stale_build", func(a *ShadowExitAttestation) { a.Identity.BuildVersion = "v1.2.2" }, false, AttestationIdentityMismatch},
		{"empty_build", func(a *ShadowExitAttestation) { a.Identity.BuildVersion = "" }, false, AttestationIdentityMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var a *ShadowExitAttestation
			if !tc.nilRec {
				a = validAttestation()
				tc.mutate(a)
			}
			if r := ValidateAttestation(a, curIdentity()); r != tc.want {
				t.Fatalf("ValidateAttestation(%s) = %q, want %q", tc.name, r, tc.want)
			}
			if AttestationValid(a, curIdentity()) {
				t.Fatalf("%s must not be a valid attestation", tc.name)
			}
		})
	}
}

// TestValidateAttestation_CurrentIdentityMustBeConcrete proves that even a perfect record does
// not attest against an empty current identity (a build with no stamp cannot be attested-for).
func TestValidateAttestation_CurrentIdentityMustBeConcrete(t *testing.T) {
	if r := ValidateAttestation(validAttestation(), RuntimeIdentity{}); r != AttestationIdentityMismatch {
		t.Fatalf("an empty current identity must fail closed, got %q", r)
	}
}

// TestValidEvidenceDigest is the Codex P2 (round-11) proof: only a canonical 64-char lowercase-hex
// digest is accepted, and ValidateAttestation rejects a nonempty-but-malformed digest with
// AttestationBadEvidence rather than attesting a review against an unidentifiable evidence reference.
func TestValidEvidenceDigest(t *testing.T) {
	if !ValidEvidenceDigest(canonicalTestDigest) {
		t.Fatal("a canonical 64-char lowercase-hex digest must be valid")
	}
	bad := []string{
		"",
		"x",
		"not-a-digest",
		"deadbeef", // too short
		"A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90", // uppercase not canonical
		canonicalTestDigest + "0",      // too long
		canonicalTestDigest[:63],       // one short
		canonicalTestDigest[:63] + "g", // non-hex char
	}
	for _, s := range bad {
		if ValidEvidenceDigest(s) {
			t.Fatalf("%q must be rejected as a non-canonical digest", s)
		}
	}
	// ValidateAttestation surfaces a bad digest as AttestationBadEvidence (durable defense-in-depth).
	a := validAttestation()
	a.EvidenceDigest = "deadbeef"
	if r := ValidateAttestation(a, curIdentity()); r != AttestationBadEvidence {
		t.Fatalf("a bad digest must yield AttestationBadEvidence, got %q", r)
	}
	a.EvidenceDigest = canonicalTestDigest
	if r := ValidateAttestation(a, curIdentity()); r != AttestationOK {
		t.Fatalf("a valid digest must validate, got %q", r)
	}
}

// TestRuntimeIdentity_RequiresImmutableCommit is the Codex P1 proof (round-12 placeholder set,
// tightened round-22, made unambiguous round-23): a valid identity must carry a concrete lowercase-hex
// commit digest in the dedicated Commit field. Valid() reads that field DIRECTLY — it never infers the
// commit from BuildVersion — so a build with no commit is never unique regardless of what its version
// string looks like, and one build can never cover materially changed code.
func TestRuntimeIdentity_RequiresImmutableCommit(t *testing.T) {
	// No commit (Commit == "") is never valid, whatever the version string is — INCLUDING a SemVer
	// version whose own "+<metadata>" is all hex (the round-23 reuse hole: it must NOT be read as a
	// commit). This is the load-bearing case.
	for _, bv := range []string{"", "dev", "v1.2.3", "v2.0.0-rc1", "v1.2.3+deadbeef", "v1.2.3+abc123def456"} {
		if (RuntimeIdentity{BuildVersion: bv}).Valid() { // Commit deliberately unset
			t.Fatalf("a build with no Commit (BuildVersion %q) must not be a valid unique identity", bv)
		}
	}
	// A real hex commit in the Commit field IS valid — the commit is the sole uniqueness anchor, so the
	// version part is irrelevant (even "dev", or empty, is valid when a real commit is present).
	for _, c := range []string{validTestCommit, "deadbeefcafe", "abcdef1234567890"} {
		if !(RuntimeIdentity{BuildVersion: "v1.2.3+" + c, Commit: c}).Valid() {
			t.Fatalf("an identity with a real hex commit %q must be valid", c)
		}
	}
	if !(RuntimeIdentity{BuildVersion: "dev+abc123def456", Commit: "abc123def456"}).Valid() {
		t.Fatal("a dev version with a real commit is a unique identity and must be valid")
	}
	// A Commit that is not a real digest is rejected: empty, too short, a placeholder, uppercase, or
	// otherwise non-lowercase-hex.
	for _, c := range []string{"", "abc", "dev", "none", "ABCDEF123456", "nothexZ12345", "abc 123 def"} {
		if (RuntimeIdentity{BuildVersion: "v1.2.3+" + c, Commit: c}).Valid() {
			t.Fatalf("Commit %q is not a real hex digest and must not be valid", c)
		}
	}
	// An attestation bound to a commitless build fails the identity binding (fail closed), even when
	// the current build carries the same commitless stamp.
	a := validAttestation()
	a.Identity = RuntimeIdentity{BuildVersion: "dev"}
	if r := ValidateAttestation(a, RuntimeIdentity{BuildVersion: "dev"}); r != AttestationIdentityMismatch {
		t.Fatalf("a commitless attestation must fail the identity binding, got %q", r)
	}
}
