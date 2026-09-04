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
		// The credential biconditional (Codex P2, PR #1235): an invalid plan implies the
		// credential-readiness failure outcome, so pairing it with any other outcome is
		// impossible readiness evidence. Base Override stays false (allow-class outcomes).
		"invalid plan with would_execute": func(e *Event) {
			e.Shadow.CredentialPlan = "credential_plan_invalid" // base Outcome stays would_execute
		},
		"invalid plan with would_fail_stale": func(e *Event) {
			e.Shadow.CredentialPlan = "credential_plan_invalid"
			e.Shadow.Outcome = "would_fail_stale_decision"
		},
		// The inspection biconditional's reverse half (Codex P2, PR #1235): a failing request
		// inspection is handled first in decide() and always yields would_fail_inspection, so
		// pairing would_fail with any other outcome is impossible. These isolate the new guard
		// (would_fail_hard_control / would_fail_stale trip no other rule with Override=false).
		"failed inspection with would_fail_hard_control": func(e *Event) {
			e.Shadow.RequestInspection = "would_fail"
			e.Shadow.Outcome = "would_fail_hard_control"
		},
		"failed inspection with would_fail_stale": func(e *Event) {
			e.Shadow.RequestInspection = "would_fail"
			e.Shadow.Outcome = "would_fail_stale_decision"
		},
		// Outcome↔Override consistency (Codex P2, PR #1235): the durable action-class
		// projection (Override) must agree with the verdict. An allow-path-only outcome with
		// a restrictive override is a restrictive decision falsely presented as executable;
		// a policy-gating outcome with a permissive override is its inverse. Action is set to a
		// restrictive code (DENY) so the Action↔Override binding is SATISFIED and only the
		// Outcome↔Override guard fires — the case isolates that guard, not the action binding.
		"would_execute with a restrictive override": func(e *Event) {
			e.Decision.Action = "DENY"
			e.Shadow.Override = true
		},
		"would_fail_stale with a restrictive override": func(e *Event) {
			e.Decision.Action = "DENY"
			e.Shadow.Outcome = "would_fail_stale_decision"
			e.Shadow.Override = true
		},
		"would_require_approval with a permissive override": func(e *Event) {
			e.Shadow.Outcome = "would_require_approval" // base Override stays false
			e.Shadow.CredentialPlan = "no_credential_profile"
		},
		"would_require_confirmation with a permissive override": func(e *Event) {
			e.Shadow.Outcome = "would_require_confirmation" // base Override stays false
			e.Shadow.CredentialPlan = "no_credential_profile"
		},
		// A pre-credential-step outcome must carry no_credential_profile (Codex P2, PR #1235):
		// a valid/no_planner status on it falsely claims readiness was evaluated. These isolate
		// the new guard — would_block leaves Override free, and would_require_approval sets
		// Override=true, so no other rule fires.
		"valid plan on a would_block outcome": func(e *Event) {
			e.Shadow.Outcome = "would_block" // ambiguous override, base false is fine
			// base CredentialPlan stays credential_plan_valid → impossible for a pre-planning outcome
		},
		"valid plan on a would_require_approval outcome": func(e *Event) {
			e.Decision.Action = "REQUIRE_APPROVAL" // satisfy the Action↔Override binding (restrictive ⇒ Override=true)
			e.Shadow.Outcome = "would_require_approval"
			e.Shadow.Override = true // satisfy the restrictive-override rule so only the new guard fires
			// base CredentialPlan stays credential_plan_valid
		},
		// Action↔Override binding (Codex round, PR #1235): the durable Override must equal
		// !isAllowClass(Decision.Action). These isolate the new guard — the outcome/sub-facts
		// stay internally consistent so ONLY the action binding rejects them.
		//
		// A restrictive action (DENY) presented as an override-free (executable-class) decision.
		// This is the round-12 case the Outcome↔Override rule alone did not reject: would_execute
		// is allow-class-only and Override=false is consistent WITH that outcome, so nothing but
		// the action binding catches the DENY.
		"deny action with a permissive override": func(e *Event) {
			e.Decision.Action = "DENY" // base Override=false, base Outcome=would_execute
		},
		// An allow-class action (ALLOW) mislabelled with a restrictive override. would_block is
		// ambiguous w.r.t. Override, so the Outcome↔Override guard does not fire — only the
		// action binding does.
		"allow action with a restrictive override": func(e *Event) {
			e.Shadow.Override = true // base Action=ALLOW
			e.Shadow.Outcome = "would_block"
			e.Shadow.CredentialPlan = "no_credential_profile"
		},
		// An action outside the nine-code taxonomy: the leaf model cannot classify it, so it
		// cannot prove the durable evidence consistent and must fail closed. A non-empty code is
		// used so validateDecisionPhase's action-present check does not fire first.
		"unknown decision action": func(e *Event) {
			e.Decision.Action = "FROBNICATE" // base Override=false, base Outcome=would_execute
		},
		// Shadow routing (Codex round, PR #1235): a v2 Shadow event is a Gateway ordinary/critical
		// decision, never a Management event and never a denial. These would land durable v2 evidence
		// in a partition (Management subtree / Gateway P-DEN) the downgrade runbook preserves, so the
		// validator must reject them. Each isolates the routing guard.
		"v2 shadow on the Management capability": func(e *Event) {
			e.Capability = CapManagement // base Criticality=CritOrdinary/PartOrd stays consistent
		},
		"v2 shadow as a denial criticality": func(e *Event) {
			// Route it to P-DEN so the criticality→partition binding is satisfied and ONLY the
			// Shadow routing guard fires (a denial is never a Shadow decision).
			e.Criticality = CritDenial
			e.Partition = PartDen
		},
		// Gated-outcome exact-action binding (Codex round, PR #1235): would_require_approval /
		// would_require_confirmation have a 1:1 correspondence with REQUIRE_APPROVAL /
		// REQUIRE_CONFIRMATION in the producer, so a restrictive-but-different action misstates a
		// denial/quarantine as an approval/confirmation gate. The class-only Action↔Override
		// binding can't catch it (both actions are restrictive). Each case is isolated — Override
		// stays true (satisfies Action↔Override + Outcome↔Override) and the plan is unplanned, so
		// only the new exact-action guard fires.
		"deny action on a would_require_approval outcome": func(e *Event) {
			e.Decision.Action = "DENY"
			e.Shadow.Override = true
			e.Shadow.Outcome = "would_require_approval"
			e.Shadow.CredentialPlan = "no_credential_profile"
		},
		"quarantine action on a would_require_confirmation outcome": func(e *Event) {
			e.Decision.Action = "QUARANTINE"
			e.Shadow.Override = true
			e.Shadow.Outcome = "would_require_confirmation"
			e.Shadow.CredentialPlan = "no_credential_profile"
		},
		// Redaction reachability (Codex round, PR #1235): ALLOW_WITH_REDACTION is allow-class (so
		// Override=false) but the live layer fails it closed, so the producer gates it to
		// would_block and it never reaches an allow-path outcome. would_execute is allow-class-only
		// with Override=false (consistent with the base), so only the new redaction guard rejects
		// this — the class-only Action↔Override binding cannot.
		"redaction action with an executable outcome": func(e *Event) {
			e.Decision.Action = "ALLOW_WITH_REDACTION" // base Override=false, base Outcome=would_execute, plan valid
		},
		// would_block reachability (Codex round, PR #1235): an unconditional ALLOW carries no
		// allowance, so the producer never resolves it to would_block — it continues to
		// hard-control/credential/stale/execute. Isolated: Override=false is consistent with ALLOW
		// (allow-class), would_block is Override-ambiguous, and no_credential_profile satisfies the
		// pre-planning rule, so only the new block-reachability guard rejects it.
		"unconditional allow with a would_block outcome": func(e *Event) {
			e.Decision.Action = "ALLOW"
			e.Shadow.Outcome = "would_block"
			e.Shadow.CredentialPlan = "no_credential_profile"
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
	// decide(), so BOTH override values must validate. The Action↔Override binding still
	// applies, so each override value is paired with a consistent action (an allow-class
	// action for Override=false, a restrictive one for Override=true) — the outcome remains
	// ambiguous, the action binding is satisfied, and validation must accept both.
	for _, oc := range []string{"would_block", "would_fail_inspection", "would_fail_hard_control"} {
		// The allow-class representative is ALLOW_ONCE, not ALLOW: all three outcomes are reachable
		// for it (would_block via an allowance miss, the two hard-fails via step 1), whereas an
		// unconditional ALLOW can never reach would_block (validateShadowBlockOutcome).
		for _, tc := range []struct {
			action   string
			override bool
		}{{"ALLOW_ONCE", false}, {"DENY", true}} {
			e := validV2ShadowEvent()
			e.Decision.Action = tc.action
			e.Shadow.Outcome = oc
			e.Shadow.Override = tc.override
			// These are all pre-credential-step outcomes, so the plan must be unplanned.
			e.Shadow.CredentialPlan = "no_credential_profile"
			// would_fail_inspection additionally requires a failing request inspection.
			if oc == "would_fail_inspection" {
				e.Shadow.RequestInspection = "would_fail"
			}
			if err := e.Validate(); err != nil {
				t.Fatalf("ambiguous outcome %q with action=%s override=%v must validate: %v", oc, tc.action, tc.override, err)
			}
		}
	}
	// The required-consistent pairs must pass (the rule admits the true producer shapes). Each
	// carries the action whose class matches the override (Override == !isAllowClass(action)).
	consistent := []struct {
		action   string
		outcome  string
		override bool
		plan     string // pre-planning outcomes must carry the unplanned default
	}{
		{"ALLOW", "would_execute", false, "credential_plan_valid"},
		{"ALLOW", "would_fail_stale_decision", false, "credential_plan_valid"},
		{"REQUIRE_APPROVAL", "would_require_approval", true, "no_credential_profile"},
		{"REQUIRE_CONFIRMATION", "would_require_confirmation", true, "no_credential_profile"},
		// The one reachable ALLOW_WITH_REDACTION shape: allow-class (Override=false) but gated to
		// would_block by the producer, so its true durable form must still validate (the redaction
		// guard rejects only the allow-path outcomes, not would_block).
		{"ALLOW_WITH_REDACTION", "would_block", false, "no_credential_profile"},
		// An allowance-bearing allow-class action reaching would_block via an allowance miss:
		// allow-class (Override=false) and a reachable would_block action, so it must still validate.
		{"ALLOW_ONCE", "would_block", false, "no_credential_profile"},
	}
	for _, c := range consistent {
		e := validV2ShadowEvent()
		e.Decision.Action = c.action
		e.Shadow.Outcome = c.outcome
		e.Shadow.Override = c.override
		e.Shadow.CredentialPlan = c.plan
		if err := e.Validate(); err != nil {
			t.Fatalf("consistent pair (%s, action=%s, override=%v) must validate: %v", c.outcome, c.action, c.override, err)
		}
	}
	// The one consistent invalid-plan shape — the credential-readiness failure — must validate
	// (the biconditional admits its true producer shape, not just rejects the false ones).
	e := validV2ShadowEvent()
	e.Shadow.Outcome = "would_fail_credential_readiness"
	e.Shadow.CredentialPlan = "credential_plan_invalid"
	if err := e.Validate(); err != nil {
		t.Fatalf("would_fail_credential_readiness with an invalid plan must validate: %v", err)
	}
}

// TestV2_SupportedSchemaVersion pins the version acceptance set (v1+v2+v3 supported;
// others rejected) — the load-bearing reader contract gate. v3 moved from the
// rejected set to the supported set when the First-Canary attempt evidence was
// introduced; every version ABOVE this build's own stays rejected, which is the half
// that must never weaken.
func TestV2_SupportedSchemaVersion(t *testing.T) {
	if !SupportedSchemaVersion(1) || !SupportedSchemaVersion(2) || !SupportedSchemaVersion(3) {
		t.Fatal("this build must support v1, v2 and v3")
	}
	for _, v := range []int{0, 4, 99, -1} {
		if SupportedSchemaVersion(v) {
			t.Fatalf("schema version %d must be unsupported (fail closed)", v)
		}
	}
}
