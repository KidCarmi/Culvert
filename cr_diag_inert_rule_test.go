package main

import (
	"strings"
	"testing"
	"time"
)

// TestCRDiag_DisabledRuleNoFalsePositive proves the bug:
// authCredentialRequiredDiagnostics must NOT produce findings for a disabled CR
// rule — a disabled rule cannot fire at runtime (authRuleMatches checks
// ruleIsEnabled), so reporting auth_cr_no_credential_provider (FAIL) or
// auth_cr_dead_under_unauth_mode (WARN) on it is a false positive that misleads
// the operator.
//
// The equivalent authSSORequiredDiagnostics function introduced in Phase 3
// Slice 5 correctly skips disabled rules (it carries the guard
// "if !ruleIsEnabled(r) || !authRuleNotExpired(r.Auth) { continue }").
// authCredentialRequiredDiagnostics predates that guard and is missing it.
func TestCRDiag_DisabledRuleNoFalsePositive(t *testing.T) {
	disabled := false
	rule := validCRRule()
	rule.Enabled = &disabled // explicitly disabled — cannot fire at runtime

	// No credential provider configured (worst case: would trigger auth_cr_no_credential_provider).
	checks := authCredentialRequiredDiagnostics([]PolicyRule{rule}, false /*unauthMode*/, false /*no credProvider*/)
	if _, found := hasCheck(checks, "auth_cr_no_credential_provider"); found {
		t.Error("disabled CR rule must NOT trigger auth_cr_no_credential_provider FAIL — the rule cannot fire")
	}

	// UnauthMode should also produce no false WARN for a disabled rule.
	checks2 := authCredentialRequiredDiagnostics([]PolicyRule{rule}, true /*unauthMode*/, true /*credProvider*/)
	if _, found := hasCheck(checks2, "auth_cr_dead_under_unauth_mode"); found {
		t.Error("disabled CR rule must NOT trigger auth_cr_dead_under_unauth_mode WARN — the rule cannot fire")
	}
}

// TestCRDiag_ExpiredRuleNoFalsePositive proves the same bug for expired rules.
// An already-expired CR rule will never match (authRuleMatches checks
// authRuleNotExpired), so it is inert and must not produce diagnostic findings.
func TestCRDiag_ExpiredRuleNoFalsePositive(t *testing.T) {
	rule := validCRRule()
	rule.Auth.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) // expired 1h ago

	checks := authCredentialRequiredDiagnostics([]PolicyRule{rule}, false, false)
	if _, found := hasCheck(checks, "auth_cr_no_credential_provider"); found {
		t.Error("expired CR rule must NOT trigger auth_cr_no_credential_provider FAIL — the rule cannot fire")
	}

	checks2 := authCredentialRequiredDiagnostics([]PolicyRule{rule}, true, true)
	if _, found := hasCheck(checks2, "auth_cr_dead_under_unauth_mode"); found {
		t.Error("expired CR rule must NOT trigger auth_cr_dead_under_unauth_mode WARN — the rule cannot fire")
	}
}

// TestCRDiag_MixedRules_OnlyActiveRulesCount verifies that when both a disabled
// (inert) CR rule and an enabled (active) CR rule are present, only the active
// rule contributes to the diagnostic findings.
func TestCRDiag_MixedRules_OnlyActiveRulesCount(t *testing.T) {
	disabled := false

	activeRule := validCRRule()
	activeRule.Name = "active-cr"

	inactiveRule := validCRRule()
	inactiveRule.Priority = 2
	inactiveRule.Name = "disabled-cr"
	inactiveRule.Enabled = &disabled

	// With a credential provider configured: no FAIL expected (active rule is satisfied).
	checksWithProvider := authCredentialRequiredDiagnostics([]PolicyRule{activeRule, inactiveRule}, false, true)
	if _, found := hasCheck(checksWithProvider, "auth_cr_no_credential_provider"); found {
		t.Error("active+disabled, credProvider=true: must NOT FAIL auth_cr_no_credential_provider")
	}

	// Without a credential provider: FAIL expected ONLY because of the active rule.
	checksNoProvider := authCredentialRequiredDiagnostics([]PolicyRule{activeRule, inactiveRule}, false, false)
	c, found := hasCheck(checksNoProvider, "auth_cr_no_credential_provider")
	if !found || c.Status != diagFail {
		t.Error("active CR rule with no credProvider must still FAIL auth_cr_no_credential_provider")
	}
	// The disabled rule's name must NOT appear in the failure message.
	if found && strings.Contains(c.Message, "disabled-cr") {
		t.Error("disabled CR rule name must not appear in auth_cr_no_credential_provider message")
	}
}
