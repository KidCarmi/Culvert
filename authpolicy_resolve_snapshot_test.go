package main

// Stage-1 runtime resolver — snapshot-path equivalence tests.
//
// resolveAuthOutcome moved from resolveAuthOutcomeFrom(policyStore.List(), ctx)
// — which deep-cloned and re-sorted the ENTIRE rulebase on every
// un-credentialed request — to resolveAuthOutcomeSnapshot over the store's
// published evaluation snapshot (the same zero-copy view Evaluate uses). These
// tests pin that the two resolvers are decision-equivalent over a matrix of
// rule shapes and request contexts, and that the snapshot path returns a
// detached rule copy (never a published definition).

import (
	"fmt"
	"testing"
)

// buildAuthResolveStore returns a store with nAccess non-matching access rules
// (priorities 100+) plus the given auth rules, installed through ReplaceAll —
// the production bulk mutator — so the published definitions carry the
// sortLocked precomputes exactly as at runtime.
func buildAuthResolveStore(nAccess int, authRules ...PolicyRule) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, 0, nAccess+len(authRules))
	for i := 0; i < nAccess; i++ {
		rules = append(rules, PolicyRule{
			Priority: 100 + i,
			Name:     fmt.Sprintf("access-%d", i),
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		})
	}
	rules = append(rules, authRules...)
	ps.ReplaceAll(rules)
	return ps
}

// authResolveFixtureRules returns a spread of persistable auth-rule shapes:
// scoped Exempt, CR, SSO, a wildcard-FQDN Exempt, a broad exemption, a
// protocol-scoped CR, a disabled Exempt, and an expired Exempt.
func authResolveFixtureRules() []PolicyRule {
	disabled := false
	return []PolicyRule{
		{
			Priority: 1, Name: "auth-exempt-scoped", RuleType: ruleTypeAuth,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}}},
			DestFQDN:     "updates.example.com",
			Auth:         &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "fixture"},
		},
		{
			Priority: 2, Name: "auth-cr-scoped", RuleType: ruleTypeAuth,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.6.0/24", "192.0.2.7"}}}},
			DestFQDN:     "vendor.example.com",
			Auth:         &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "secops", Reason: "fixture"},
		},
		{
			Priority: 3, Name: "auth-sso-scoped", RuleType: ruleTypeAuth,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.7.0/24"}}}},
			DestFQDN:     "portal.example.com",
			Auth:         &AuthRuleSpec{Outcome: OutcomeSSORequired, Owner: "secops", Reason: "fixture"},
		},
		{
			Priority: 4, Name: "auth-exempt-wildcard", RuleType: ruleTypeAuth,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.1.0.0/16"}}}},
			DestFQDN:     "*.wild.example.com",
			Auth:         &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "fixture"},
		},
		{
			Priority: 5, Name: "auth-exempt-broad", RuleType: ruleTypeAuth,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.2.0.0/16"}}}},
			Auth:         &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "fixture", BroadExemption: true},
		},
		{
			Priority: 6, Name: "auth-cr-connect-only", RuleType: ruleTypeAuth,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}}},
			DestFQDN:     "tunnel.example.com",
			Auth:         &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "secops", Reason: "fixture", Protocol: "connect"},
		},
		{
			Priority: 7, Name: "auth-exempt-disabled", RuleType: ruleTypeAuth, Enabled: &disabled,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}}},
			DestFQDN:     "disabled.example.com",
			Auth:         &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "fixture"},
		},
		{
			Priority: 8, Name: "auth-exempt-expired", RuleType: ruleTypeAuth,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}}},
			DestFQDN:     "expired.example.com",
			Auth:         &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "fixture", ExpiresAt: "2001-01-01T00:00:00Z"},
		},
	}
}

func authResolveFixtureContexts() []RequestContext {
	return []RequestContext{
		// Scoped exempt: subject+dest match.
		{ClientIP: "10.0.5.50", Host: "updates.example.com", Protocol: "http", Method: "GET"},
		// Same dest with a port (CONNECT authority form is port-stripped by
		// authRequestContext, but the resolver must behave identically on raw input).
		{ClientIP: "10.0.5.50", Host: "updates.example.com", Protocol: "connect", Method: "CONNECT"},
		// Mixed-case host — exercises normalization on both resolver paths.
		{ClientIP: "10.0.5.50", Host: "UPDATES.Example.COM", Protocol: "http", Method: "GET"},
		// CR by CIDR and by the bare-IP predicate value.
		{ClientIP: "10.0.6.9", Host: "vendor.example.com", Protocol: "http", Method: "GET"},
		{ClientIP: "192.0.2.7", Host: "vendor.example.com", Protocol: "http", Method: "POST"},
		// SSO.
		{ClientIP: "10.0.7.1", Host: "portal.example.com", Protocol: "http", Method: "GET"},
		// Wildcard FQDN: subdomain, exact base, and a non-matching cousin.
		{ClientIP: "10.1.3.4", Host: "a.wild.example.com", Protocol: "http", Method: "GET"},
		{ClientIP: "10.1.3.4", Host: "wild.example.com", Protocol: "http", Method: "GET"},
		{ClientIP: "10.1.3.4", Host: "notwild.example.com", Protocol: "http", Method: "GET"},
		// Broad exemption: any destination for the 10.2/16 subject.
		{ClientIP: "10.2.9.9", Host: "anything.example.org", Protocol: "http", Method: "GET"},
		// Protocol scope: connect-only CR must not fire on plain http and must
		// fire on CONNECT.
		{ClientIP: "10.0.5.50", Host: "tunnel.example.com", Protocol: "http", Method: "GET"},
		{ClientIP: "10.0.5.50", Host: "tunnel.example.com", Protocol: "connect", Method: "CONNECT"},
		// Disabled / expired rules must not fire.
		{ClientIP: "10.0.5.50", Host: "disabled.example.com", Protocol: "http", Method: "GET"},
		{ClientIP: "10.0.5.50", Host: "expired.example.com", Protocol: "http", Method: "GET"},
		// Subject miss, dest miss, invalid client IP (fails closed on both paths).
		{ClientIP: "203.0.113.7", Host: "updates.example.com", Protocol: "http", Method: "GET"},
		{ClientIP: "10.0.5.50", Host: "other.example.com", Protocol: "http", Method: "GET"},
		{ClientIP: "not-an-ip", Host: "updates.example.com", Protocol: "http", Method: "GET"},
		{ClientIP: "", Host: "", Protocol: "http", Method: "GET"},
	}
}

// TestResolveAuthOutcome_SnapshotEquivalentToPure pins decision equivalence
// between the runtime snapshot resolver and the pure List()-based resolver the
// simulator uses, across the full fixture matrix, with the Exempt kill switch
// both released and engaged.
func TestResolveAuthOutcome_SnapshotEquivalentToPure(t *testing.T) {
	ps := buildAuthResolveStore(25, authResolveFixtureRules()...)
	defer setAuthExemptDisabled(false)
	for _, killSwitch := range []bool{false, true} {
		setAuthExemptDisabled(killSwitch)
		for i, ctx := range authResolveFixtureContexts() {
			pure := resolveAuthOutcomeFrom(ps.List(), ctx)
			snap := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
			if snap.Outcome != pure.Outcome {
				t.Errorf("kill=%v ctx[%d] %+v: snapshot outcome %q != pure outcome %q",
					killSwitch, i, ctx, snap.Outcome, pure.Outcome)
			}
			if (snap.Rule == nil) != (pure.Rule == nil) {
				t.Errorf("kill=%v ctx[%d] %+v: snapshot rule nil=%v != pure rule nil=%v",
					killSwitch, i, ctx, snap.Rule == nil, pure.Rule == nil)
				continue
			}
			if snap.Rule != nil && snap.Rule.Name != pure.Rule.Name {
				t.Errorf("kill=%v ctx[%d] %+v: snapshot matched %q, pure matched %q",
					killSwitch, i, ctx, snap.Rule.Name, pure.Rule.Name)
			}
		}
	}
}

// TestResolveAuthOutcomeSnapshot_ReturnsDetachedRule pins the PolicyMatch-style
// detachment contract: mutating the returned rule (including nested spec
// values) must never write through to the store's published definitions.
func TestResolveAuthOutcomeSnapshot_ReturnsDetachedRule(t *testing.T) {
	ps := buildAuthResolveStore(3, authResolveFixtureRules()...)
	ctx := RequestContext{ClientIP: "10.0.5.50", Host: "updates.example.com", Protocol: "http", Method: "GET"}
	d := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
	if d.Outcome != OutcomeExempt || d.Rule == nil {
		t.Fatalf("fixture must resolve to a scoped Exempt match, got %+v", d)
	}
	d.Rule.Name = "mutated"
	d.Rule.Auth.Outcome = OutcomeCredentialRequired
	d.Rule.SubjectMatch.All[0].Values[0] = "0.0.0.0/0"

	again := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
	if again.Outcome != OutcomeExempt || again.Rule == nil || again.Rule.Name != "auth-exempt-scoped" {
		t.Fatalf("published definition was mutated through the decision snapshot: %+v", again)
	}
	if again.Rule.SubjectMatch.All[0].Values[0] != "10.0.5.0/24" {
		t.Fatalf("nested SubjectMatch leaked by reference: %q", again.Rule.SubjectMatch.All[0].Values[0])
	}
}

// TestResolveAuthOutcomeSnapshot_PriorityOrder pins that the snapshot path
// honors the store's priority order without re-sorting: a higher-priority
// (lower value) CR rule beats a lower-priority Exempt rule for the same
// request, and vice versa — mirroring the resolveAuthOutcomeFrom contract
// tests in authpolicy_phase2_slice2_test.go.
func TestResolveAuthOutcomeSnapshot_PriorityOrder(t *testing.T) {
	mk := func(name string, prio int, outcome AuthOutcome) PolicyRule {
		return PolicyRule{
			Priority: prio, Name: name, RuleType: ruleTypeAuth,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}}},
			DestFQDN:     "updates.example.com",
			Auth:         &AuthRuleSpec{Outcome: outcome, Owner: "ops", Reason: "fixture"},
		}
	}
	ctx := RequestContext{ClientIP: "10.0.5.50", Host: "updates.example.com", Protocol: "http", Method: "GET"}

	ps := buildAuthResolveStore(0, mk("cr", 2, OutcomeCredentialRequired), mk("ex", 1, OutcomeExempt))
	if d := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx); d.Outcome != OutcomeExempt {
		t.Fatalf("priority-1 Exempt must beat priority-2 CR, got %q", d.Outcome)
	}
	ps = buildAuthResolveStore(0, mk("ex", 2, OutcomeExempt), mk("cr", 1, OutcomeCredentialRequired))
	if d := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx); d.Outcome != OutcomeCredentialRequired {
		t.Fatalf("priority-1 CR must beat priority-2 Exempt, got %q", d.Outcome)
	}
}
