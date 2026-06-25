package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Phase 3 Slice 5 — SSORequired + auth-rule shadow/overlap diagnostics. These are
// report-only operator-contract rows; they never mutate rules or touch the
// request path.

// authRuleAt builds an enabled auth rule at a priority, scoped to cidrs → fqdn.
func authRuleAt(outcome AuthOutcome, name string, prio int, cidrs []string, fqdn string) PolicyRule {
	en := true
	return PolicyRule{
		Priority: prio, Name: name, ID: "id-" + name, RuleType: ruleTypeAuth, Enabled: &en,
		SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: cidrs}}},
		DestFQDN:     fqdn,
		Auth:         &AuthRuleSpec{Outcome: outcome, Owner: "ops", Reason: "test"},
	}
}

func diagHas(t *testing.T, checks []OperatorContractCheck, code, wantStatus string) OperatorContractCheck {
	t.Helper()
	c, ok := hasCheck(checks, code)
	if !ok {
		t.Fatalf("expected diagnostic %q, got: %+v", code, checks)
	}
	if c.Status != wantStatus {
		t.Errorf("%s status = %q, want %q", code, c.Status, wantStatus)
	}
	return c
}

func diagAbsent(t *testing.T, checks []OperatorContractCheck, code string) {
	t.Helper()
	if _, ok := hasCheck(checks, code); ok {
		t.Errorf("diagnostic %q must NOT be present", code)
	}
}

// ── SSORequired diagnostics ──────────────────────────────────────────────────

func TestP3S5_SSO_NoRulesNoChecks(t *testing.T) {
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	if got := authSSORequiredDiagnostics([]PolicyRule{validExemptRule()}, false); got != nil {
		t.Errorf("no SSO rules → no SSO checks, got %+v", got)
	}
}

func TestP3S5_SSO_NoIdP_Fail(t *testing.T) {
	withSSORegistry(t) // empty registry — no interactive IdP
	checks := authSSORequiredDiagnostics([]PolicyRule{validSSORule()}, false)
	diagHas(t, checks, "auth_sso_no_idp", diagFail)
}

func TestP3S5_SSO_WithIdP_NoNoIdPFail(t *testing.T) {
	withSSORegistry(t, idp("corp", IdPTypeSAML, true))
	checks := authSSORequiredDiagnostics([]PolicyRule{validSSORule()}, false)
	diagAbsent(t, checks, "auth_sso_no_idp")
}

// Disabled or expired SSORequired rules cannot fire, so they must produce NO
// diagnostics — even with no IdP configured (otherwise an inert rule would
// falsely FAIL the operator contract). Mirrors the runtime authRuleMatches gate.
func TestP3S5_SSO_InactiveRulesIgnored(t *testing.T) {
	withSSORegistry(t) // empty registry — would FAIL for an active rule

	disabled := validSSORule()
	off := false
	disabled.Enabled = &off
	if got := authSSORequiredDiagnostics([]PolicyRule{disabled}, false); got != nil {
		t.Errorf("disabled SSO rule must produce no diagnostics, got %+v", got)
	}

	expired := validSSORule()
	expired.Auth.ExpiresAt = "2000-01-01T00:00:00Z"
	if got := authSSORequiredDiagnostics([]PolicyRule{expired}, false); got != nil {
		t.Errorf("expired SSO rule must produce no diagnostics, got %+v", got)
	}
}

func TestP3S5_SSO_DeadUnderUnauthMode_Warn(t *testing.T) {
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	checks := authSSORequiredDiagnostics([]PolicyRule{validSSORule()}, true /*unauthMode*/)
	diagHas(t, checks, "auth_sso_dead_under_unauth_mode", diagWarn)
}

func TestP3S5_SSO_ProviderRefs_UnavailableAndDead(t *testing.T) {
	withSSORegistry(t, idp("corp-a", IdPTypeOIDC, true), idp("old", IdPTypeOIDC, false))

	// Some refs unavailable (corp-a enabled, old disabled) → WARN, not FAIL.
	r := validSSORule()
	r.Auth.ProviderRefs = []string{"corp-a", "old"}
	checks := authSSORequiredDiagnostics([]PolicyRule{r}, false)
	diagHas(t, checks, "auth_sso_providerref_unavailable", diagWarn)
	diagAbsent(t, checks, "auth_sso_rule_no_eligible_provider")

	// All refs unavailable → FAIL (rule always fails closed).
	r2 := validSSORule()
	r2.Auth.ProviderRefs = []string{"old", "ghost"}
	checks = authSSORequiredDiagnostics([]PolicyRule{r2}, false)
	diagHas(t, checks, "auth_sso_rule_no_eligible_provider", diagFail)
}

func TestP3S5_SSO_MayMatchNonBrowser(t *testing.T) {
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))

	// protocol "" (any) → WARN.
	rAny := validSSORule()
	rAny.Auth.Protocol = ""
	diagHas(t, authSSORequiredDiagnostics([]PolicyRule{rAny}, false), "auth_sso_may_match_non_browser", diagWarn)

	// protocol "connect" → WARN.
	rConn := validSSORule()
	rConn.Auth.Protocol = "connect"
	diagHas(t, authSSORequiredDiagnostics([]PolicyRule{rConn}, false), "auth_sso_may_match_non_browser", diagWarn)

	// protocol "http" → no such WARN.
	rHTTP := validSSORule()
	rHTTP.Auth.Protocol = "http"
	diagAbsent(t, authSSORequiredDiagnostics([]PolicyRule{rHTTP}, false), "auth_sso_may_match_non_browser")
}

func TestP3S5_SSO_AmbiguousIdP(t *testing.T) {
	withSSORegistry(t, idp("corp-a", IdPTypeOIDC, true), idp("corp-b", IdPTypeSAML, true))
	r := validSSORule() // empty providerRefs
	r.Auth.Protocol = "http"
	diagHas(t, authSSORequiredDiagnostics([]PolicyRule{r}, false), "auth_sso_ambiguous_idp", diagWarn)
}

// End-to-end: a no-IdP SSO FAIL drives the operator-contract verdict to fail.
func TestP3S5_SSO_EndToEnd_FailVerdict(t *testing.T) {
	resetPolicyStoreForDiag(t)
	withSSORegistry(t) // empty registry
	policyStore.Add(validSSORule())

	w := httptest.NewRecorder()
	apiDiagnostics(w, viewerCtx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/diagnostics", http.NoBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("diagnostics = %d", w.Code)
	}
	c := decodeContract(t, w)
	if findDiagnosticCheck(c, "auth_sso_no_idp") == nil {
		t.Error("auth_sso_no_idp FAIL must appear in the operator contract")
	}
	if c.Verdict != diagFail {
		t.Errorf("a no-IdP SSORequired rule must drive the verdict to fail, got %q", c.Verdict)
	}
}

// ── Shadow/overlap diagnostics ───────────────────────────────────────────────

func TestP3S5_Shadow_ChallengeShadowsExempt(t *testing.T) {
	cidrs := []string{"10.0.5.0/24"}
	const host = "portal.example.com"
	for _, hi := range []AuthOutcome{OutcomeSSORequired, OutcomeCredentialRequired} {
		rules := []PolicyRule{
			authRuleAt(hi, "challenge-1", 1, cidrs, host),
			authRuleAt(OutcomeExempt, "exempt-2", 2, cidrs, host),
		}
		checks := authRuleShadowDiagnostics(rules)
		c := diagHas(t, checks, "auth_rule_shadowed", diagWarn)
		if !strings.Contains(c.Message, "exempt-2") || !strings.Contains(c.Message, "challenge-1") {
			t.Errorf("%s: shadow message must name both rules: %q", hi, c.Message)
		}
		if !strings.Contains(c.Message, "fully shadows") {
			t.Errorf("%s: equal scope must be a full shadow: %q", hi, c.Message)
		}
		if !strings.Contains(c.Message, "devices relying on the exemption") {
			t.Errorf("%s: Exempt-shadow message must flag device-breakage risk: %q", hi, c.Message)
		}
	}
}

func TestP3S5_Shadow_SSOShadowsCR(t *testing.T) {
	cidrs := []string{"10.0.5.0/24"}
	const host = "portal.example.com"
	rules := []PolicyRule{
		authRuleAt(OutcomeSSORequired, "sso-1", 1, cidrs, host),
		authRuleAt(OutcomeCredentialRequired, "cr-2", 2, cidrs, host),
	}
	diagHas(t, authRuleShadowDiagnostics(rules), "auth_rule_shadowed", diagWarn)
}

func TestP3S5_Shadow_CIDRContainmentFull(t *testing.T) {
	const host = "portal.example.com"
	rules := []PolicyRule{
		authRuleAt(OutcomeSSORequired, "broad-1", 1, []string{"10.0.0.0/16"}, host),
		authRuleAt(OutcomeExempt, "narrow-2", 2, []string{"10.0.5.0/24"}, host),
	}
	c := diagHas(t, authRuleShadowDiagnostics(rules), "auth_rule_shadowed", diagWarn)
	if !strings.Contains(c.Message, "fully shadows") {
		t.Errorf("a /16 containing a /24 (same dest) is a full shadow: %q", c.Message)
	}
}

func TestP3S5_Shadow_NoOverlapNoFinding(t *testing.T) {
	const host = "portal.example.com"
	rules := []PolicyRule{
		authRuleAt(OutcomeSSORequired, "sso-1", 1, []string{"10.0.5.0/24"}, host),
		authRuleAt(OutcomeExempt, "exempt-2", 2, []string{"192.168.0.0/24"}, host),
	}
	diagAbsent(t, authRuleShadowDiagnostics(rules), "auth_rule_shadowed")
}

func TestP3S5_Shadow_ScheduledShadowerIsPartial(t *testing.T) {
	cidrs := []string{"10.0.5.0/24"}
	const host = "portal.example.com"
	a := authRuleAt(OutcomeSSORequired, "sched-1", 1, cidrs, host)
	a.Schedule = &PolicySchedule{Days: []string{"Mon"}}
	rules := []PolicyRule{a, authRuleAt(OutcomeExempt, "exempt-2", 2, cidrs, host)}
	c := diagHas(t, authRuleShadowDiagnostics(rules), "auth_rule_shadowed", diagWarn)
	if !strings.Contains(c.Message, "partially shadows") {
		t.Errorf("a scheduled shadower must be a PARTIAL shadow: %q", c.Message)
	}
}

// An all-empty (non-nil) PolicySchedule is semantically identical to nil:
// matchSchedule returns true for it, so the shadower fires on every request.
// authRuleCovers must treat it as always-active → full shadow, not partial.
func TestP3S5_Shadow_EmptyScheduleCountsAsFullShadow(t *testing.T) {
	cidrs := []string{"10.0.5.0/24"}
	const host = "portal.example.com"
	a := authRuleAt(OutcomeSSORequired, "sso-1", 1, cidrs, host)
	a.Schedule = &PolicySchedule{} // non-nil but all-empty → always active
	b := authRuleAt(OutcomeExempt, "exempt-2", 2, cidrs, host)
	c := diagHas(t, authRuleShadowDiagnostics([]PolicyRule{a, b}), "auth_rule_shadowed", diagWarn)
	if !strings.Contains(c.Message, "fully shadows") {
		t.Errorf("empty (always-active) schedule must be classified as a FULL shadow, got: %q", c.Message)
	}
}

// A schedule with an invalid IANA timezone is failed closed by authRuleMatches
// (via authScheduleParseable) — the rule never fires at runtime. It must NOT be
// classified as a full shadower (the lower rule IS still reachable).
func TestP3S5_Shadow_UnparseableTimezoneNotFullShadow(t *testing.T) {
	cidrs := []string{"10.0.5.0/24"}
	const host = "portal.example.com"
	a := authRuleAt(OutcomeSSORequired, "sso-1", 1, cidrs, host)
	a.Schedule = &PolicySchedule{Timezone: "Not/AZone"} // invalid tz → fails closed at runtime
	b := authRuleAt(OutcomeExempt, "exempt-2", 2, cidrs, host)
	c := diagHas(t, authRuleShadowDiagnostics([]PolicyRule{a, b}), "auth_rule_shadowed", diagWarn)
	if strings.Contains(c.Message, "fully shadows") {
		t.Errorf("rule with unparseable timezone cannot be a full shadower (never fires): %q", c.Message)
	}
}

func TestP3S5_Shadow_DisabledAndExpiredExcluded(t *testing.T) {
	cidrs := []string{"10.0.5.0/24"}
	const host = "portal.example.com"

	// Disabled higher-priority rule → not a shadower.
	dis := authRuleAt(OutcomeSSORequired, "disabled-1", 1, cidrs, host)
	off := false
	dis.Enabled = &off
	diagAbsent(t, authRuleShadowDiagnostics([]PolicyRule{dis, authRuleAt(OutcomeExempt, "ex-2", 2, cidrs, host)}), "auth_rule_shadowed")

	// Expired higher-priority rule → not a shadower.
	exp := authRuleAt(OutcomeSSORequired, "expired-1", 1, cidrs, host)
	exp.Auth.ExpiresAt = "2000-01-01T00:00:00Z"
	diagAbsent(t, authRuleShadowDiagnostics([]PolicyRule{exp, authRuleAt(OutcomeExempt, "ex-2", 2, cidrs, host)}), "auth_rule_shadowed")
}

// Conservative limit: different destination DIMENSIONS (FQDN vs category) are not
// flagged — no false positive (documented false-negative).
func TestP3S5_Shadow_DifferentDestDimensions_NoFalsePositive(t *testing.T) {
	cidrs := []string{"10.0.5.0/24"}
	a := authRuleAt(OutcomeSSORequired, "fqdn-1", 1, cidrs, "portal.example.com")
	b := authRuleAt(OutcomeExempt, "cat-2", 2, cidrs, "")
	b.DestCategory = "SocialMedia"
	diagAbsent(t, authRuleShadowDiagnostics([]PolicyRule{a, b}), "auth_rule_shadowed")
}

// ── Edge-case shadow tests ────────────────────────────────────────────────────

// A BroadExemption=true Exempt rule at higher priority matches ALL destinations at
// runtime (authRuleMatches skips the dest-required guard; matchDest returns true
// when no selector is set). If its source CIDR contains the lower-priority rule's
// CIDR, it fully shadows that rule — the SSO/CR requirement is silently bypassed.
// destCovers must return true for broadExemption rules with no destination selector
// so the shadow diagnostic fires.
func TestEdge_Shadow_BroadExemptionShadowsSSO(t *testing.T) {
	en := true
	// Rule A: Exempt for ALL destinations from 10.0.0.0/8 (broadExemption acknowledged).
	broadExempt := PolicyRule{
		Priority: 1, Name: "broad-exempt", ID: "id-broad-exempt",
		RuleType: ruleTypeAuth, Enabled: &en,
		SubjectMatch: &SubjectMatch{
			SchemaVersion: 1,
			All:           []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.0.0/8"}}},
		},
		Auth: &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "test", BroadExemption: true},
	}
	// Rule B: SSORequired for portal.example.com from 10.0.0.0/16 (⊂ Rule A's /8).
	sso := authRuleAt(OutcomeSSORequired, "sso-2", 2, []string{"10.0.0.0/16"}, "portal.example.com")

	c := diagHas(t, authRuleShadowDiagnostics([]PolicyRule{broadExempt, sso}), "auth_rule_shadowed", diagWarn)
	if !strings.Contains(c.Message, "fully shadows") {
		t.Errorf("broadExemption (all-dest, /8 ⊃ /16) must be a full shadow: %q", c.Message)
	}
}

// A non-wildcard FQDN like "example.com" implicitly covers all its subdomains at
// runtime (matchFQDN Palo Alto style: host == pattern || HasSuffix(host, "."+pattern)).
// destCovers must apply the same containment logic so "example.com" at prio 1 is
// flagged as shadowing "www.example.com" at prio 2.
func TestEdge_Shadow_PaloAltoSubdomainCoverage(t *testing.T) {
	cidrs := []string{"10.0.0.0/8"}
	// Rule A: prio 1, DestFQDN="example.com" — matches example.com AND *.example.com at runtime.
	a := authRuleAt(OutcomeSSORequired, "apex-1", 1, cidrs, "example.com")
	// Rule B: prio 2, DestFQDN="www.example.com" — subset of A's runtime match scope.
	b := authRuleAt(OutcomeExempt, "www-2", 2, cidrs, "www.example.com")
	c := diagHas(t, authRuleShadowDiagnostics([]PolicyRule{a, b}), "auth_rule_shadowed", diagWarn)
	if !strings.Contains(c.Message, "fully shadows") {
		t.Errorf("apex FQDN implicitly covers subdomains at runtime → full shadow: %q", c.Message)
	}
}
