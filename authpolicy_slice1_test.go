package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Phase 1 Slice 1 — AuthOutcome resolver CONTRACT tests (pure, no wiring).
// These prove the enum is frozen, the model round-trips, and that the resolver
// returns Default for every request today — including when an (inert) auth rule
// is present — so proxy.go behavior is unchanged.

func TestAuthOutcome_FrozenValues(t *testing.T) {
	if string(OutcomeDefault) != "Default" {
		t.Errorf("OutcomeDefault = %q, want Default", OutcomeDefault)
	}
	if string(OutcomeExempt) != "Exempt" {
		t.Errorf("OutcomeExempt = %q, want Exempt", OutcomeExempt)
	}
	if string(OutcomeCredentialRequired) != "CredentialRequired" { // #nosec G101 -- enum value, not a credential
		t.Errorf("OutcomeCredentialRequired = %q, want CredentialRequired", OutcomeCredentialRequired)
	}
	if string(OutcomeSSORequired) != "SSORequired" {
		t.Errorf("OutcomeSSORequired = %q, want SSORequired", OutcomeSSORequired)
	}
}

func TestResolveAuthOutcomeFrom_EmptyRuleset_Default(t *testing.T) {
	d := resolveAuthOutcomeFrom(nil, RequestContext{ClientIP: "10.0.5.7", Host: "example.com"})
	if d.Outcome != OutcomeDefault {
		t.Fatalf("empty ruleset: outcome = %q, want Default", d.Outcome)
	}
	if d.Rule != nil {
		t.Errorf("Default decision must carry no rule, got %+v", d.Rule)
	}
}

func TestResolveAuthOutcomeFrom_AccessRulesOnly_Default(t *testing.T) {
	rules := []PolicyRule{
		{Priority: 1, Name: "allow-all", Action: ActionAllow}, // RuleType "" = access
		{Priority: 2, Name: "block-fb", RuleType: ruleTypeAccess, DestFQDN: "facebook.com", Action: ActionDrop},
	}
	d := resolveAuthOutcomeFrom(rules, RequestContext{ClientIP: "1.2.3.4", Host: "facebook.com"})
	if d.Outcome != OutcomeDefault {
		t.Fatalf("access-only ruleset: outcome = %q, want Default", d.Outcome)
	}
}

// Even a fully-formed, enabled auth/exempt rule must NOT change the outcome in
// Slice 1: the matcher is not wired yet, so the request still resolves to
// Default (Exempt is modeled, not active).
func TestResolveAuthOutcomeFrom_AuthExemptRulePresent_StillDefault(t *testing.T) {
	enabled := true
	rules := []PolicyRule{
		{
			Priority: 1,
			Name:     "legacy-printer",
			RuleType: ruleTypeAuth,
			Enabled:  &enabled,
			SubjectMatch: &SubjectMatch{
				SchemaVersion: 1,
				All:           []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}},
			},
			DestFQDN: "updates.example.com",
			Auth: &AuthRuleSpec{
				Outcome: OutcomeExempt,
				Owner:   "ops",
				Reason:  "legacy firmware",
			},
		},
	}
	// A request that WOULD match this rule once the matcher lands.
	d := resolveAuthOutcomeFrom(rules, RequestContext{ClientIP: "10.0.5.50", Host: "updates.example.com", Protocol: "http"})
	if d.Outcome != OutcomeDefault {
		t.Fatalf("Slice 1 must not activate Exempt: outcome = %q, want Default", d.Outcome)
	}
}

func TestResolveAuthOutcome_GlobalEmptyStore_Default(t *testing.T) {
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })
	policyStore.ReplaceAll(nil)

	d := resolveAuthOutcome(RequestContext{ClientIP: "10.0.5.7", Host: "example.com"})
	if d.Outcome != OutcomeDefault {
		t.Fatalf("global empty store: outcome = %q, want Default", d.Outcome)
	}
}

func TestAuthRuleSpec_JSONRoundTrip(t *testing.T) {
	in := AuthRuleSpec{
		Outcome:        OutcomeExempt,
		Protocol:       "connect",
		Method:         "GET",
		Owner:          "ops",
		Reason:         "legacy",
		ExpiresAt:      "2027-01-01T00:00:00Z",
		BroadExemption: true,
		IdPRef:         "okta-prod",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out AuthRuleSpec
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
	// IdPRef is reserved but must survive serialization for forward-compat.
	if !strings.Contains(string(b), `"idpRef":"okta-prod"`) {
		t.Errorf("IdPRef not serialized: %s", b)
	}
}

// An access rule (Auth == nil) must not emit an "auth" key — additive,
// zero-behavior-change on the wire for existing rules.
func TestPolicyRule_AuthFieldOmitsWhenNil(t *testing.T) {
	b, err := json.Marshal(PolicyRule{Priority: 1, Name: "plain", Action: ActionAllow})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"auth"`) {
		t.Errorf("nil Auth should be omitted, got: %s", b)
	}
}
