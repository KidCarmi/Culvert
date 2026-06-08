package main

import (
	"strings"
	"testing"
	"time"
)

// Phase 1 Slice 2 — auth (Exempt) rule VALIDATION tests. Pure validation; no
// runtime wiring (resolveAuthOutcome still returns Default).

func validExemptRule() PolicyRule {
	return PolicyRule{
		Priority: 1,
		Name:     "legacy-printer",
		RuleType: ruleTypeAuth,
		SubjectMatch: &SubjectMatch{
			SchemaVersion: 1,
			All:           []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}},
		},
		DestFQDN: "updates.example.com",
		Auth:     &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "legacy firmware"},
	}
}

func warnsContain(ws []string, sub string) bool {
	for _, w := range ws {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestValidateAuthRule_ValidExemptPasses(t *testing.T) {
	warnings, err := validateAuthRule(validExemptRule())
	if err != nil {
		t.Fatalf("valid exempt rule rejected: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("valid scoped /24 rule should warn nothing, got: %v", warnings)
	}
}

// validatePolicyRule GATES auth rules in Slice 2: even a fully-valid exempt rule
// is rejected at the accept path, because the persistence guards (Load/ReplaceAll)
// and the runtime resolver are not auth-aware yet (accepted auth rules would be
// silently dropped). The validation logic itself is exercised via validateAuthRule.
func TestValidatePolicyRule_GatesAuthRules(t *testing.T) {
	// A valid exempt rule still passes the dedicated validator...
	if _, err := validateAuthRule(validExemptRule()); err != nil {
		t.Fatalf("validateAuthRule should accept a valid exempt rule: %v", err)
	}
	// ...but validatePolicyRule must reject it (gated, not yet accepted).
	err := validatePolicyRule(validExemptRule(), nil, -1)
	if err == nil {
		t.Fatal("validatePolicyRule must gate (reject) auth rules in Slice 2")
	}
	if !strings.Contains(err.Error(), "not yet accepted") {
		t.Errorf("gate error should explain auth rules are not yet accepted, got: %v", err)
	}
	// The gate is independent of rule validity: an INVALID auth rule is also
	// rejected here (without needing a spec), proving acceptance is gated wholesale.
	r := validExemptRule()
	r.Auth = nil
	if err := validatePolicyRule(r, nil, -1); err == nil {
		t.Fatal("validatePolicyRule must reject auth rules regardless of validity")
	}
}

func TestValidateAuthRule_MissingSpecRejected(t *testing.T) {
	r := validExemptRule()
	r.Auth = nil
	if _, err := validateAuthRule(r); err == nil {
		t.Fatal("auth rule without an AuthRuleSpec must be rejected")
	}
}

func TestValidateAuthRule_UnsupportedOutcomeRejected(t *testing.T) {
	r := validExemptRule()
	r.Auth.Outcome = "Bogus"
	if _, err := validateAuthRule(r); err == nil {
		t.Fatal("unsupported outcome must be rejected")
	}
}

func TestValidateAuthRule_ReservedOutcomesRejected(t *testing.T) {
	for _, oc := range []AuthOutcome{OutcomeCredentialRequired, OutcomeSSORequired} {
		r := validExemptRule()
		r.Auth.Outcome = oc
		_, err := validateAuthRule(r)
		if err == nil {
			t.Errorf("outcome %q must be rejected as reserved in Slice 2", oc)
		}
		if err != nil && !strings.Contains(err.Error(), "reserved") {
			t.Errorf("outcome %q should be rejected as reserved, got: %v", oc, err)
		}
	}
}

func TestValidateAuthRule_IdPRefReserved(t *testing.T) {
	r := validExemptRule()
	r.Auth.IdPRef = "okta-prod"
	if _, err := validateAuthRule(r); err == nil {
		t.Fatal("idpRef is reserved and must be rejected when set")
	}
}

func TestValidateAuthRule_MissingSubjectMatchRejected(t *testing.T) {
	r := validExemptRule()
	r.SubjectMatch = nil
	if _, err := validateAuthRule(r); err == nil {
		t.Fatal("exempt rule without a subjectMatch must be rejected")
	}
}

func TestValidateAuthRule_NonCIDRPredicateRejected(t *testing.T) {
	r := validExemptRule()
	r.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: "tag", Values: []string{"no-idp"}}}}
	if _, err := validateAuthRule(r); err == nil {
		t.Fatal("non-CIDR (unsupported) predicate must be rejected")
	}
}

func TestValidateAuthRule_IdentityPredicatesRejected(t *testing.T) {
	for _, typ := range []string{"directory_group", "identity", "group", "user", "email", "sub"} {
		r := validExemptRule()
		r.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: typ, Values: []string{"x"}}}}
		_, err := validateAuthRule(r)
		if err == nil {
			t.Errorf("identity-dependent predicate %q must be rejected on an auth rule", typ)
		}
		if err != nil && !strings.Contains(err.Error(), "identity-dependent") {
			t.Errorf("predicate %q should be rejected as identity-dependent, got: %v", typ, err)
		}
	}
}

func TestValidateAuthRule_MissingDestinationRejectedUnlessBroad(t *testing.T) {
	r := validExemptRule()
	r.DestFQDN = ""
	r.DestCategory = ""
	r.DestCategoryGroup = ""
	if _, err := validateAuthRule(r); err == nil {
		t.Fatal("exempt rule with no destination and no broadExemption must be rejected")
	}

	// With explicit broadExemption it is accepted but warned.
	r.Auth.BroadExemption = true
	warnings, err := validateAuthRule(r)
	if err != nil {
		t.Fatalf("broadExemption=true should be accepted, got: %v", err)
	}
	if !warnsContain(warnings, "broadExemption") {
		t.Errorf("broadExemption=true must produce a warning, got: %v", warnings)
	}
}

func TestValidateAuthRule_DestinationViaCategoryOrGroup(t *testing.T) {
	r := validExemptRule()
	r.DestFQDN = ""
	r.DestCategory = CategorySocial
	if _, err := validateAuthRule(r); err != nil {
		t.Errorf("destCategory should satisfy destination scoping: %v", err)
	}
	r.DestCategory = ""
	r.DestCategoryGroup = "vendor-cloud"
	if _, err := validateAuthRule(r); err != nil {
		t.Errorf("destCategoryGroup should satisfy destination scoping: %v", err)
	}
	// CategoryAny must NOT count as a destination scope.
	r.DestCategoryGroup = ""
	r.DestCategory = CategoryAny
	if _, err := validateAuthRule(r); err == nil {
		t.Error("destCategory=Any must not satisfy destination scoping")
	}
}

func TestValidateAuthRule_MissingOwnerOrReasonRejected(t *testing.T) {
	r := validExemptRule()
	r.Auth.Owner = "  "
	if _, err := validateAuthRule(r); err == nil {
		t.Error("missing owner must be rejected")
	}
	r = validExemptRule()
	r.Auth.Reason = ""
	if _, err := validateAuthRule(r); err == nil {
		t.Error("missing reason must be rejected")
	}
}

func TestValidateAuthRule_ExpiresAt(t *testing.T) {
	// Bad format rejected.
	r := validExemptRule()
	r.Auth.ExpiresAt = "not-a-date"
	if _, err := validateAuthRule(r); err == nil {
		t.Error("malformed expiresAt must be rejected")
	}
	// Valid future expiry: accepted, no expiry warning.
	r = validExemptRule()
	r.Auth.ExpiresAt = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	if warnings, err := validateAuthRule(r); err != nil {
		t.Errorf("valid future expiresAt rejected: %v", err)
	} else if warnsContain(warnings, "expired") {
		t.Errorf("future expiry must not warn expired: %v", warnings)
	}
	// Expired rule: VALID to store, but warned (it will not match later).
	r = validExemptRule()
	r.Auth.ExpiresAt = time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	warnings, err := validateAuthRule(r)
	if err != nil {
		t.Fatalf("expired rule must remain valid to store, got: %v", err)
	}
	if !warnsContain(warnings, "expired") {
		t.Errorf("expired rule must produce an 'expired' warning, got: %v", warnings)
	}
}

func TestValidateAuthRule_Protocol(t *testing.T) {
	for _, p := range []string{"", "http", "connect"} {
		r := validExemptRule()
		r.Auth.Protocol = p
		if _, err := validateAuthRule(r); err != nil {
			t.Errorf("protocol %q should be allowed: %v", p, err)
		}
	}
	// socks5 rejected.
	r := validExemptRule()
	r.Auth.Protocol = "socks5"
	if _, err := validateAuthRule(r); err == nil {
		t.Error(`protocol "socks5" must be rejected in Phase 1`)
	}
	// unknown protocol rejected.
	r = validExemptRule()
	r.Auth.Protocol = "ftp"
	if _, err := validateAuthRule(r); err == nil {
		t.Error("unknown protocol must be rejected")
	}
	// method with connect → warning (not fatal).
	r = validExemptRule()
	r.Auth.Protocol = "connect"
	r.Auth.Method = "GET"
	warnings, err := validateAuthRule(r)
	if err != nil {
		t.Fatalf("connect+method should be valid: %v", err)
	}
	if !warnsContain(warnings, "method is ignored") {
		t.Errorf("connect+method should warn method ignored, got: %v", warnings)
	}
}

func TestValidateAuthRule_BroadCIDRWarns(t *testing.T) {
	r := validExemptRule()
	r.Auth.BroadExemption = true // keep destination optional for this source-breadth check
	r.DestFQDN = ""
	r.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"0.0.0.0/0"}}}}
	warnings, err := validateAuthRule(r)
	if err != nil {
		t.Fatalf("0.0.0.0/0 source should validate (with warning): %v", err)
	}
	if !warnsContain(warnings, "all addresses") {
		t.Errorf("0.0.0.0/0 must warn, got: %v", warnings)
	}
}

// ── Access-rule behavior ──

func TestValidatePolicyRule_AccessRuleUnchanged(t *testing.T) {
	// A normal access rule (no subjectMatch, no auth) still validates.
	ok := PolicyRule{Priority: 1, Name: "allow-all", Action: ActionAllow}
	if err := validatePolicyRule(ok, nil, -1); err != nil {
		t.Errorf("normal access rule must validate: %v", err)
	}
	// Invalid action still rejected.
	bad := PolicyRule{Priority: 2, Name: "bad", Action: "Nope"}
	if err := validatePolicyRule(bad, nil, -1); err == nil {
		t.Error("invalid action must still be rejected")
	}
}

func TestValidatePolicyRule_AccessRuleWithSubjectMatchRejected(t *testing.T) {
	r := PolicyRule{
		Priority: 1, Name: "scoped-access", Action: ActionAllow,
		SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.0.0/8"}}}},
	}
	if err := validatePolicyRule(r, nil, -1); err == nil {
		t.Fatal("access rule with subjectMatch must be rejected until the access matcher lands")
	}
}

func TestValidatePolicyRule_AccessRuleWithAuthSpecRejected(t *testing.T) {
	r := PolicyRule{
		Priority: 1, Name: "weird", Action: ActionAllow,
		Auth: &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "x", Reason: "y"},
	}
	if err := validatePolicyRule(r, nil, -1); err == nil {
		t.Fatal("access rule carrying an auth spec must be rejected")
	}
}
