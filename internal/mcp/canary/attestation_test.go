package canary

import "testing"

func validAttestation() *ShadowExitAttestation {
	return &ShadowExitAttestation{
		SchemaVersion:      ShadowExitAttestationSchemaVersion,
		Status:             ShadowExitStatusPassed,
		ReviewID:           "SXR-2026-001",
		EvidenceDigest:     "abc123",
		Identity:           RuntimeIdentity{BuildVersion: "v1.2.3"},
		AttestedBy:         "admin@culvert",
		AttestedAtUnixNano: 1_700_000_000_000_000_000,
	}
}

func curIdentity() RuntimeIdentity { return RuntimeIdentity{BuildVersion: "v1.2.3"} }

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
