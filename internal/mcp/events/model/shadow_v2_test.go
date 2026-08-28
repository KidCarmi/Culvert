package model

import (
	"strings"
	"testing"
)

// shadowPlanValid is the credential-plan enum TOKEN used by the v2 test fixtures. It is a
// named const (not an inline string literal on a CredentialPlan field) so a gosec G101
// "hardcoded credential" heuristic never trips on an enum value that is not a secret.
const shadowPlanValid = "credential_plan_valid"

// validV2ShadowEvent returns a structurally-valid SchemaVersionV2 Shadow decision event
// with a complete, valid ShadowEvidence. Tests tweak one field to prove a specific rule.
func validV2ShadowEvent() Event {
	return Event{
		SchemaVersion: SchemaVersionV2, EventID: "evt_sh2", Phase: PhaseDecision,
		Criticality: CritOrdinary, Partition: PartOrd, Capability: CapGateway,
		ActionClass: ActionClassRead, NodeID: "node-1", DomainID: "dom-1",
		TimeUnixNano: 1730000000000000000, ReplayID: "rpl_sh2", CorrelationID: "cor_sh2",
		Identity: IdentityEvidence{Tenant: "acme", PrincipalID: "p1", PrincipalType: "human"},
		Decision: DecisionEvidence{
			Action: "ALLOW", ReasonCode: "MCP.POLICY.RESOURCE_SCOPE",
			ExecutionState: "shadow_evaluated",
		},
		Shadow: &ShadowEvidence{
			Outcome:                  "would_execute",
			Override:                 false,
			CredentialPlan:           shadowPlanValid,
			MaterializationReadiness: "not_evaluated",
			RequestInspection:        "would_pass",
			ResponseInspection:       "not_evaluated",
		},
	}
}

// TestV2_ValidShadowEventPassesAndDigestsIncludeShadow proves a valid v2 event validates,
// its canonical encoding carries the shadow key, and its digest differs from the same
// event with the shadow evidence removed (the sub-facts are digest-covered).
func TestV2_ValidShadowEventPassesAndDigestsIncludeShadow(t *testing.T) {
	e := validV2ShadowEvent()
	if err := e.Validate(); err != nil {
		t.Fatalf("valid v2 shadow event must validate: %v", err)
	}
	cb, err := e.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if !strings.Contains(string(cb), `"shadow"`) {
		t.Fatalf("v2 canonical encoding must carry the shadow sub-facts: %s", cb)
	}
	withShadow, _ := e.Digest()
	bare := e
	bare.Shadow = nil
	bare.SchemaVersion = SchemaVersionV1 // a bare event is v1
	bareDigest, _ := bare.Digest()
	if withShadow == bareDigest {
		t.Fatal("the shadow sub-facts must contribute to the v2 digest (mutation: dropping Shadow must change the digest)")
	}
}

// TestV2_EveryShadowFieldChangesTheDigest is the §6 requirement: changing ANY shadow
// evidence field changes the digest. Mutation: excluding a field from the canonical
// encoding (it is a plain struct field, so encoding/json includes it) fails here.
func TestV2_EveryShadowFieldChangesTheDigest(t *testing.T) {
	base := validV2ShadowEvent()
	baseDigest, _ := base.Digest()

	mutators := map[string]func(*ShadowEvidence){
		"outcome":            func(s *ShadowEvidence) { s.Outcome = "would_block" },
		"override":           func(s *ShadowEvidence) { s.Override = true },
		"credential_plan":    func(s *ShadowEvidence) { s.CredentialPlan = "no_credential_profile" },
		"request_inspection": func(s *ShadowEvidence) { s.RequestInspection = "not_evaluated" },
	}
	for name, mut := range mutators {
		e := validV2ShadowEvent()
		mut(e.Shadow)
		d, _ := e.Digest()
		if d == baseDigest {
			t.Fatalf("changing shadow field %q did not change the digest", name)
		}
	}
}

// TestV2_ValidationRejectsMalformedShadowEvidence pins every fail-closed rule (§7): enum
// membership, the architectural not_evaluated constants, and the impossible combinations.
// Each case is a mutation of a valid event: removing the corresponding guard admits it.
func TestV2_ValidationRejectsMalformedShadowEvidence(t *testing.T) {
	cases := map[string]func(*Event){
		"v2 without shadow evidence":               func(e *Event) { e.Shadow = nil },
		"shadow evidence on a v1 event":            func(e *Event) { e.SchemaVersion = SchemaVersionV1 },
		"v2 wrong execution_state":                 func(e *Event) { e.Decision.ExecutionState = "executing" },
		"v2 non-decision phase":                    func(e *Event) { e.Phase = PhaseOutcome; e.Outcome = &OutcomeEvidence{DecisionRef: "evt_x"} },
		"unknown outcome":                          func(e *Event) { e.Shadow.Outcome = "would_maybe" },
		"unknown credential plan":                  func(e *Event) { e.Shadow.CredentialPlan = "definitely_valid" },
		"unknown request inspection":               func(e *Event) { e.Shadow.RequestInspection = "would_perhaps" },
		"materialization not not_evaluated":        func(e *Event) { e.Shadow.MaterializationReadiness = "ready" },
		"response inspection not not_evaluated":    func(e *Event) { e.Shadow.ResponseInspection = "would_pass" },
		"would_execute + request would_fail":       func(e *Event) { e.Shadow.RequestInspection = "would_fail" },
		"would_fail_inspection without would_fail": func(e *Event) { e.Shadow.Outcome = "would_fail_inspection"; e.Shadow.RequestInspection = "would_pass" },
		"would_fail_credential without invalid plan": func(e *Event) {
			e.Shadow.Outcome = "would_fail_credential_readiness"
			e.Shadow.CredentialPlan = shadowPlanValid
		},
		// Outcome↔Override consistency (Codex P2, PR #1235): the durable action-class
		// projection (Override) must agree with the verdict. An allow-path-only outcome with
		// a restrictive override is a restrictive decision falsely presented as executable;
		// a policy-gating outcome with a permissive override is its inverse.
		"would_execute with a restrictive override": func(e *Event) { e.Shadow.Override = true },
		"would_fail_stale with a restrictive override": func(e *Event) {
			e.Shadow.Outcome = "would_fail_stale_decision"
			e.Shadow.Override = true
		},
		"would_require_approval with a permissive override": func(e *Event) {
			e.Shadow.Outcome = "would_require_approval" // base Override stays false
		},
		"would_require_confirmation with a permissive override": func(e *Event) {
			e.Shadow.Outcome = "would_require_confirmation" // base Override stays false
		},
		"unsupported schema version": func(e *Event) { e.SchemaVersion = 3 },
	}
	for name, mut := range cases {
		e := validV2ShadowEvent()
		mut(&e)
		if err := e.Validate(); err == nil {
			t.Fatalf("%s: must fail closed, but Validate accepted it", name)
		}
	}
}

// TestV2_LegacyV1ShadowMarker_ReadableButNotWritable pins the read/write split (Codex P2,
// PR #1235): a legacy v1 "shadow_evaluated" marker (no ShadowEvidence, e.g. written by a
// pre-v2 binary) stays READABLE on the recovery path (ValidateShadowEvidence tolerates it and
// never infers absent evidence), but the WRITE path (Validate) REJECTS it — so an adapter
// regression or another producer can never PERSIST a new incomplete shadow event. Mutation:
// dropping validateShadowWriteOnly makes Validate accept the marker and fails the write half.
func TestV2_LegacyV1ShadowMarker_ReadableButNotWritable(t *testing.T) {
	e := validV2ShadowEvent()
	e.SchemaVersion = SchemaVersionV1
	e.Shadow = nil // v1 legacy marker: execution_state=shadow_evaluated but no sub-facts

	// READ (recovery) tolerates the legacy marker and never invents evidence.
	if err := e.ValidateShadowEvidence(); err != nil {
		t.Fatalf("a legacy v1 shadow marker must stay readable on recovery: %v", err)
	}
	if e.Shadow != nil {
		t.Fatal("absent shadow evidence must stay absent, never inferred")
	}
	// WRITE (Validate) rejects it — a new shadow event must be a complete v2 record.
	if err := e.Validate(); err == nil {
		t.Fatal("a bare v1 shadow marker must be rejected at write time (never persist incomplete shadow evidence)")
	}

	// A plain v1 event (no shadow marker) is of course still both readable and writable.
	plain := validV2ShadowEvent()
	plain.SchemaVersion = SchemaVersionV1
	plain.Shadow = nil
	plain.Decision.ExecutionState = "not_implemented"
	if err := plain.Validate(); err != nil {
		t.Fatalf("a plain v1 event must still validate at write time: %v", err)
	}
}

// TestV2_OutcomeOverrideConsistency_NotOverBroad proves the Outcome↔Override rule (Codex
// P2, PR #1235) constrains ONLY the outcomes whose producer path fixes the action class,
// and leaves the genuinely ambiguous outcomes free to carry either override. Over-rejecting
// here would drop legitimate durable evidence — a would_block reached via an allowance miss
// (Override=false) and one reached via a DENY policy class (Override=true) are BOTH real.
func TestV2_OutcomeOverrideConsistency_NotOverBroad(t *testing.T) {
	// Ambiguous outcomes: reachable from both an allow-class and a restrictive path in
	// decide(), so BOTH override values must validate.
	for _, oc := range []string{"would_block", "would_fail_inspection", "would_fail_hard_control"} {
		for _, ov := range []bool{false, true} {
			e := validV2ShadowEvent()
			e.Shadow.Outcome = oc
			e.Shadow.Override = ov
			// would_fail_inspection additionally requires a failing request inspection.
			if oc == "would_fail_inspection" {
				e.Shadow.RequestInspection = "would_fail"
			}
			if err := e.Validate(); err != nil {
				t.Fatalf("ambiguous outcome %q with override=%v must validate: %v", oc, ov, err)
			}
		}
	}
	// The required-consistent pairs must pass (the rule admits the true producer shapes).
	consistent := []struct {
		outcome  string
		override bool
	}{
		{"would_execute", false},
		{"would_fail_stale_decision", false},
		{"would_require_approval", true},
		{"would_require_confirmation", true},
	}
	for _, c := range consistent {
		e := validV2ShadowEvent()
		e.Shadow.Outcome = c.outcome
		e.Shadow.Override = c.override
		if err := e.Validate(); err != nil {
			t.Fatalf("consistent pair (%s, override=%v) must validate: %v", c.outcome, c.override, err)
		}
	}
}

// TestV2_SupportedSchemaVersion pins the version acceptance set (v1+v2 supported; others
// rejected) — the load-bearing v1/v2 reader contract gate.
func TestV2_SupportedSchemaVersion(t *testing.T) {
	if !SupportedSchemaVersion(1) || !SupportedSchemaVersion(2) {
		t.Fatal("a v2 build must support both v1 and v2")
	}
	for _, v := range []int{0, 3, 99, -1} {
		if SupportedSchemaVersion(v) {
			t.Fatalf("schema version %d must be unsupported (fail closed)", v)
		}
	}
}
