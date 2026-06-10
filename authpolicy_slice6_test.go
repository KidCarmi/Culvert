package main

import (
	"strings"
	"testing"
	"time"
)

// Phase 1 Slice 6 — Auth Exempt kill switch + risk diagnostics (no runtime wiring).
//
// Proves: (1) the kill switch forces the pure resolver to Default (fail closed to
// auth-required); (2) the risk diagnostics WARN (never mutate) on the documented
// risky postures. Neither is wired into proxy.go or the served /api/diagnostics.

// ── Kill switch ──────────────────────────────────────────────────────────────

func TestSlice6_KillSwitch_RuntimeToggleForcesDefault(t *testing.T) {
	t.Cleanup(func() { setAuthExemptDisabled(false) })

	// Precondition: with the kill switch off, a matching rule resolves to Exempt.
	if d := resolveAuthOutcomeFrom([]PolicyRule{authRule()}, matchingCtx()); d.Outcome != OutcomeExempt {
		t.Fatalf("precondition: expected Exempt, got %q", d.Outcome)
	}

	// Engaged: every request fails closed to Default, with no rule attached.
	setAuthExemptDisabled(true)
	d := resolveAuthOutcomeFrom([]PolicyRule{authRule()}, matchingCtx())
	if d.Outcome != OutcomeDefault {
		t.Fatalf("kill switch must force Default, got %q", d.Outcome)
	}
	if d.Rule != nil {
		t.Errorf("kill-switch Default must carry no rule, got %+v", d.Rule)
	}

	// Released: the matcher resumes returning Exempt.
	setAuthExemptDisabled(false)
	if d := resolveAuthOutcomeFrom([]PolicyRule{authRule()}, matchingCtx()); d.Outcome != OutcomeExempt {
		t.Fatalf("releasing the kill switch must restore Exempt, got %q", d.Outcome)
	}
}

func TestSlice6_KillSwitchEngaged_Composition(t *testing.T) {
	t.Cleanup(func() { setAuthExemptDisabled(false) })

	setAuthExemptDisabled(false)
	// With the runtime toggle off, engagement equals the (read-once) env switch,
	// which is unset in the test environment → not engaged.
	if authExemptDisabledRuntimeState() {
		t.Error("runtime state must be false after setAuthExemptDisabled(false)")
	}
	if authExemptKillSwitchEngaged() != authBypassDisabled() {
		t.Error("with the runtime toggle off, engagement must equal the env kill switch")
	}

	setAuthExemptDisabled(true)
	if !authExemptDisabledRuntimeState() {
		t.Error("runtime state getter must reflect the enabled toggle")
	}
	if !authExemptKillSwitchEngaged() {
		t.Error("the runtime toggle must engage the kill switch")
	}
}

// ── Risk diagnostics ─────────────────────────────────────────────────────────

func hasCheck(checks []OperatorContractCheck, code string) (OperatorContractCheck, bool) {
	for i := range checks {
		if checks[i].Code == code {
			return checks[i], true
		}
	}
	return OperatorContractCheck{}, false
}

func mustWarn(t *testing.T, checks []OperatorContractCheck, code string) {
	t.Helper()
	c, ok := hasCheck(checks, code)
	if !ok {
		t.Fatalf("expected diagnostic %q, got %+v", code, checks)
	}
	if c.Status != diagWarn {
		t.Errorf("diagnostic %q must be warn, got %q", code, c.Status)
	}
	if c.OperatorAction == "" {
		t.Errorf("diagnostic %q must carry an operator action", code)
	}
}

func TestSlice6_Diag_NoExpiryOnly(t *testing.T) {
	// A plain, scoped exempt rule with no expiry: only the no-expiry risk fires.
	checks := authExemptDiagnostics([]PolicyRule{authRule()}, ActionDrop)
	mustWarn(t, checks, "auth_exempt_no_expiry")
	for _, unexpected := range []string{
		"auth_exempt_broad_exemption", "auth_exempt_any_source", "auth_exempt_wide_source",
		"auth_exempt_broad_destination", "auth_exempt_expired", "auth_exempt_default_allow",
	} {
		if _, ok := hasCheck(checks, unexpected); ok {
			t.Errorf("did not expect %q for a scoped, non-expired, deny-default rule", unexpected)
		}
	}
}

func TestSlice6_Diag_BroadExemption(t *testing.T) {
	r := authRule()
	r.DestFQDN = ""
	r.Auth.BroadExemption = true
	checks := authExemptDiagnostics([]PolicyRule{r}, ActionDrop)
	mustWarn(t, checks, "auth_exempt_broad_exemption")
	mustWarn(t, checks, "auth_exempt_broad_destination") // no destination selector
}

func TestSlice6_Diag_AnySource(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		r := authRule()
		r.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{cidr}}}}
		mustWarn(t, authExemptDiagnostics([]PolicyRule{r}, ActionDrop), "auth_exempt_any_source")
	}
}

func TestSlice6_Diag_WideSource(t *testing.T) {
	r := authRule()
	r.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.0.0/8"}}}}
	checks := authExemptDiagnostics([]PolicyRule{r}, ActionDrop)
	mustWarn(t, checks, "auth_exempt_wide_source")
	if _, ok := hasCheck(checks, "auth_exempt_any_source"); ok {
		t.Error("/8 is wide but not any-source")
	}
}

func TestSlice6_Diag_BroadDestinationViaAny(t *testing.T) {
	r := authRule()
	r.DestFQDN = ""
	r.DestCategory = CategoryAny
	mustWarn(t, authExemptDiagnostics([]PolicyRule{r}, ActionDrop), "auth_exempt_broad_destination")
}

func TestSlice6_Diag_Expired(t *testing.T) {
	r := authRule()
	r.Auth.ExpiresAt = time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	checks := authExemptDiagnostics([]PolicyRule{r}, ActionDrop)
	mustWarn(t, checks, "auth_exempt_expired")
	// The rule HAS an expiry, so the no-expiry risk must not fire.
	if _, ok := hasCheck(checks, "auth_exempt_no_expiry"); ok {
		t.Error("a rule with expiresAt set must not trigger no_expiry")
	}
}

func TestSlice6_Diag_DefaultAllowWithExempt(t *testing.T) {
	mustWarn(t, authExemptDiagnostics([]PolicyRule{authRule()}, ActionAllow), "auth_exempt_default_allow")
}

func TestSlice6_Diag_NoExemptRulesNoChecks(t *testing.T) {
	// Default Allow but no exempt rules → no checks at all (default_allow only
	// fires when exemptions exist).
	rules := []PolicyRule{{Priority: 1, Name: "access-allow", Action: ActionAllow}}
	if checks := authExemptDiagnostics(rules, ActionAllow); checks != nil {
		t.Errorf("no exempt rules must yield no checks, got %+v", checks)
	}
}

func TestSlice6_Diag_AccessRulesIgnored(t *testing.T) {
	rules := []PolicyRule{
		{Priority: 1, Name: "access-allow", Action: ActionAllow},                           // access — ignored
		{Priority: 2, Name: "access-scoped", RuleType: ruleTypeAccess, Action: ActionDrop}, // access — ignored
		authRule(), // exempt, no expiry
	}
	checks := authExemptDiagnostics(rules, ActionDrop)
	mustWarn(t, checks, "auth_exempt_no_expiry")
	for i := range checks {
		if strings.Contains(checks[i].Message, "access-allow") || strings.Contains(checks[i].Message, "access-scoped") {
			t.Errorf("access rules must not appear in auth-exempt diagnostics: %q", checks[i].Message)
		}
	}
}

// Diagnostics must only WARN and must never mutate the rules they inspect.
func TestSlice6_Diag_DoNotMutateAndOnlyWarn(t *testing.T) {
	r := authRule()
	r.DestFQDN = ""
	r.Auth.BroadExemption = true
	enabledBefore := *r.Enabled
	broadBefore := r.Auth.BroadExemption

	checks := authExemptDiagnostics([]PolicyRule{r}, ActionAllow)
	if *r.Enabled != enabledBefore || r.Auth.BroadExemption != broadBefore {
		t.Error("diagnostics must not mutate inspected rules")
	}
	if len(checks) == 0 {
		t.Fatal("expected warnings for a broad-exemption + default-allow scenario")
	}
	for i := range checks {
		if checks[i].Status != diagWarn {
			t.Errorf("diagnostics must only warn (never fail/ok-activate), got %q for %q", checks[i].Status, checks[i].Code)
		}
	}
}

// ── helper units ─────────────────────────────────────────────────────────────

func TestSlice6_SubjectSourceBreadth(t *testing.T) {
	anySrc, wide := subjectSourceBreadth(&SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"0.0.0.0/0"}}}})
	if !anySrc || wide {
		t.Errorf("0.0.0.0/0: any=%v wide=%v, want any=true wide=false", anySrc, wide)
	}
	anySrc, wide = subjectSourceBreadth(&SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.0.0/8"}}}})
	if anySrc || !wide {
		t.Errorf("10.0.0.0/8: any=%v wide=%v, want any=false wide=true", anySrc, wide)
	}
	anySrc, wide = subjectSourceBreadth(&SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}}})
	if anySrc || wide {
		t.Errorf("/24: any=%v wide=%v, want both false", anySrc, wide)
	}
	if a, w := subjectSourceBreadth(nil); a || w {
		t.Error("nil subject must be neither any nor wide")
	}
}

func TestSlice6_AuthExemptExpired(t *testing.T) {
	if authExemptExpired(&AuthRuleSpec{}) {
		t.Error("empty expiry must not be considered expired")
	}
	past := &AuthRuleSpec{ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}
	if !authExemptExpired(past) {
		t.Error("past expiry must be expired")
	}
	future := &AuthRuleSpec{ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if authExemptExpired(future) {
		t.Error("future expiry must not be expired")
	}
	if !authExemptExpired(&AuthRuleSpec{ExpiresAt: "garbage"}) {
		t.Error("unparseable expiry must be treated as expired (fail-closed)")
	}
}
