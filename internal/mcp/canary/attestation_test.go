package canary

import "testing"

// canonicalTestDigest is a valid 64-char lowercase-hex SHA-256 digest for attestation fixtures
// (satisfies ValidEvidenceDigest — Codex P2, round-11).
const canonicalTestDigest = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

// validTestBuild is a composed "<version>+<commit>" identity with a lowercase-hex commit digest,
// the form Valid() now REQUIRES (a bare version is not a unique identity — Codex P1, round-22).
const validTestBuild = "v1.2.3+abc123def456"

func validAttestation() *ShadowExitAttestation {
	return &ShadowExitAttestation{
		SchemaVersion:      ShadowExitAttestationSchemaVersion,
		Status:             ShadowExitStatusPassed,
		ReviewID:           "SXR-2026-001",
		EvidenceDigest:     canonicalTestDigest,
		Identity:           RuntimeIdentity{BuildVersion: validTestBuild},
		AttestedBy:         "admin@culvert",
		AttestedAtUnixNano: 1_700_000_000_000_000_000,
	}
}

func curIdentity() RuntimeIdentity { return RuntimeIdentity{BuildVersion: validTestBuild} }

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
	if r := ValidateAttestation(a, RuntimeIdentity{BuildVersion: a.Identity.BuildVersion}); r != AttestationBadEvidence {
		t.Fatalf("a bad digest must yield AttestationBadEvidence, got %q", r)
	}
	a.EvidenceDigest = canonicalTestDigest
	if r := ValidateAttestation(a, RuntimeIdentity{BuildVersion: a.Identity.BuildVersion}); r != AttestationOK {
		t.Fatalf("a valid digest must validate, got %q", r)
	}
}

// TestRuntimeIdentity_RequiresImmutableCommit is the Codex P1 proof (round-12 placeholder set,
// tightened round-22): a valid identity must carry the immutable COMMIT component, not merely a
// non-placeholder version. A bare version — placeholder OR concrete — is NOT unique (a `.git`-less
// build stamps an empty commit that collapses to the bare version, and one tag can cover many
// commits), so it fails closed and an old attestation can never cover materially changed code.
func TestRuntimeIdentity_RequiresImmutableCommit(t *testing.T) {
	// BARE stamps (no "+<commit>") are never valid — the placeholder fillers AND a concrete tag.
	for _, s := range []string{"", "dev", "unknown", "none", "latest", "v1.2.3", "v2.0.0-rc1"} {
		if (RuntimeIdentity{BuildVersion: s}).Valid() {
			t.Fatalf("a bare build stamp %q (no commit component) must not be a valid unique identity", s)
		}
	}
	// A composed "<version>+<hexcommit>" IS valid — the commit is the uniqueness anchor. Even a "dev"
	// version is valid when it carries a real commit (a genuinely unique build).
	for _, s := range []string{validTestBuild, "dev+abc123def456", "v9.9.9+deadbeefcafe"} {
		if !(RuntimeIdentity{BuildVersion: s}).Valid() {
			t.Fatalf("a composed version+commit stamp %q must be a valid unique identity", s)
		}
	}
	// A composed stamp whose commit component is NOT a real digest is rejected: empty, too short, a
	// placeholder, or non-hex (so a version's own "+<metadata>" cannot masquerade as a commit).
	for _, s := range []string{"v1.2.3+", "v1.2.3+dev", "v1.2.3+abc", "v1.2.3+build.7", "v1.2.3+ABCDEF123456", "v1.2.3+nothexZ12345"} {
		if (RuntimeIdentity{BuildVersion: s}).Valid() {
			t.Fatalf("a stamp %q without a real hex commit digest must not be valid", s)
		}
	}
	// An attestation bound to a bare/placeholder build fails the identity binding (fail closed), even
	// when the current build carries the same bare stamp.
	a := validAttestation()
	a.Identity = RuntimeIdentity{BuildVersion: "dev"}
	if r := ValidateAttestation(a, RuntimeIdentity{BuildVersion: "dev"}); r != AttestationIdentityMismatch {
		t.Fatalf("a dev-stamped attestation must fail the identity binding, got %q", r)
	}
}
