package canary

import "testing"

func validRehearsal() *RollbackRehearsalRecord {
	return &RollbackRehearsalRecord{
		SchemaVersion:       RollbackRehearsalSchemaVersion,
		Capability:          "gateway",
		Identity:            RuntimeIdentity{BuildVersion: validTestBuild},
		Executed:            true,
		Steps:               RequiredRollbackPath(),
		RehearsedAtUnixNano: 1_700_000_000_000_000_000,
	}
}

func TestValidateRehearsal_ValidPasses(t *testing.T) {
	if r := ValidateRehearsal(validRehearsal(), "gateway", RuntimeIdentity{BuildVersion: validTestBuild}); r != RehearsalOK {
		t.Fatalf("a fully-executed, current-build rehearsal must validate, got %q", r)
	}
	if !RehearsalValid(validRehearsal(), "gateway", RuntimeIdentity{BuildVersion: validTestBuild}) {
		t.Fatal("RehearsalValid must be true for a valid record")
	}
}

// TestValidateRehearsal_Rejections is the §5 mutation proof: a missing, wrong-schema, wrong-
// capability, not-executed, incomplete-path, or stale-build record must NOT satisfy readiness.
func TestValidateRehearsal_Rejections(t *testing.T) {
	cur := RuntimeIdentity{BuildVersion: validTestBuild}
	cases := []struct {
		name   string
		cap    string
		mutate func(*RollbackRehearsalRecord)
		nilRec bool
		want   RehearsalReason
	}{
		{"missing", "gateway", nil, true, RehearsalMissing},
		{"schema_newer", "gateway", func(r *RollbackRehearsalRecord) { r.SchemaVersion = RollbackRehearsalSchemaVersion + 1 }, false, RehearsalSchemaUnknown},
		{"schema_zero", "gateway", func(r *RollbackRehearsalRecord) { r.SchemaVersion = 0 }, false, RehearsalSchemaUnknown},
		{"no_capability", "gateway", func(r *RollbackRehearsalRecord) { r.Capability = "" }, false, RehearsalNoCapability},
		{"wrong_capability", "management", func(r *RollbackRehearsalRecord) {}, false, RehearsalCapabilityWrong},
		{"not_executed", "gateway", func(r *RollbackRehearsalRecord) { r.Executed = false }, false, RehearsalNotExecuted},
		{"incomplete_path", "gateway", func(r *RollbackRehearsalRecord) { r.Steps = []string{"canary", "shadow"} }, false, RehearsalIncompletePath},
		{"reordered_path", "gateway", func(r *RollbackRehearsalRecord) { r.Steps = []string{"observe", "shadow", "canary"} }, false, RehearsalIncompletePath},
		{"empty_path", "gateway", func(r *RollbackRehearsalRecord) { r.Steps = nil }, false, RehearsalIncompletePath},
		{"stale_build", "gateway", func(r *RollbackRehearsalRecord) { r.Identity.BuildVersion = "v1.2.2" }, false, RehearsalIdentityMismatch},
		{"empty_build", "gateway", func(r *RollbackRehearsalRecord) { r.Identity.BuildVersion = "" }, false, RehearsalIdentityMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec *RollbackRehearsalRecord
			if !tc.nilRec {
				rec = validRehearsal()
				tc.mutate(rec)
			}
			if r := ValidateRehearsal(rec, tc.cap, cur); r != tc.want {
				t.Fatalf("ValidateRehearsal(%s) = %q, want %q", tc.name, r, tc.want)
			}
			if RehearsalValid(rec, tc.cap, cur) {
				t.Fatalf("%s must not be a valid rehearsal", tc.name)
			}
		})
	}
}

// TestValidateRehearsal_CurrentIdentityMustBeConcrete proves a perfect record does not attest
// against an empty current identity (a build with no stamp cannot be attested-for).
func TestValidateRehearsal_CurrentIdentityMustBeConcrete(t *testing.T) {
	if r := ValidateRehearsal(validRehearsal(), "gateway", RuntimeIdentity{}); r != RehearsalIdentityMismatch {
		t.Fatalf("an empty current identity must fail closed, got %q", r)
	}
}
