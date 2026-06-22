package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Phase 3 Slice 3 — the FULL pure resolver returns SSORequired (priority-ordered)
// and observability serializes it, while the RUNTIME no-credentials path stays
// SSO-inert: SSORequired is excluded there (runtimeInertOutcomes) so it can
// neither win nor shadow a lower-priority Exempt/CredentialRequired rule.
// proxy.go/socks5.go are untouched and the SSO metric stays zero from the request
// path.

// ssoCtx matches validSSORule (10.0.5.0/24 → portal.example.com).
func ssoCtx() RequestContext {
	return RequestContext{ClientIP: "10.0.5.7", Host: "portal.example.com", Protocol: "http", Method: "GET"}
}

// scopeLocal scopes an auth rule to 127.0.0.0/8 → host (for handleRequest /
// resolveNoCredAuthOutcome tests, whose client IP is 127.0.0.1).
func scopeLocal(r PolicyRule, name, host string) PolicyRule {
	r.Name, r.DestFQDN = name, host
	r.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"127.0.0.0/8"}}}}
	return r
}

// ── Pure resolver returns SSORequired ────────────────────────────────────────

func TestP3S3_PureResolver_ReturnsSSORequired(t *testing.T) {
	d := resolveAuthOutcomeFrom([]PolicyRule{validSSORule()}, ssoCtx())
	if d.Outcome != OutcomeSSORequired {
		t.Fatalf("pure resolver must return SSORequired, got %q", d.Outcome)
	}
	if d.Rule == nil || d.Rule.Name != "require-sso-portal" {
		t.Errorf("decision must carry the matched rule: %+v", d.Rule)
	}
	// providerRefs ride along on the matched rule (no struct change needed).
	d.Rule.Auth.ProviderRefs = []string{"corp-oidc"}
	if got := resolveAuthOutcomeFrom([]PolicyRule{*d.Rule}, ssoCtx()); got.Rule == nil || len(got.Rule.Auth.ProviderRefs) != 1 {
		t.Errorf("matched rule must carry providerRefs: %+v", got.Rule)
	}
}

func TestP3S3_PureResolver_DisabledExpiredNonMatching_Default(t *testing.T) {
	disabled := validSSORule()
	off := false
	disabled.Enabled = &off

	expired := validSSORule()
	expired.Auth.ExpiresAt = "2000-01-01T00:00:00Z"

	nonMatchIP := ssoCtx()
	nonMatchIP.ClientIP = "192.0.2.1" // outside 10.0.5.0/24

	cases := map[string]struct {
		rules []PolicyRule
		ctx   RequestContext
	}{
		"disabled":     {[]PolicyRule{disabled}, ssoCtx()},
		"expired":      {[]PolicyRule{expired}, ssoCtx()},
		"non-matching": {[]PolicyRule{validSSORule()}, nonMatchIP},
	}
	for name, tc := range cases {
		if d := resolveAuthOutcomeFrom(tc.rules, tc.ctx); d.Outcome != OutcomeDefault {
			t.Errorf("%s: expected Default, got %q", name, d.Outcome)
		}
	}
}

// Priority ordering applies in the pure resolver: first matching auth rule wins,
// regardless of outcome class.
func TestP3S3_PureResolver_MixedPriority(t *testing.T) {
	mk := func(base PolicyRule, name string, prio int) PolicyRule {
		base.Name, base.Priority, base.DestFQDN = name, prio, "portal.example.com"
		base.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}}}
		return base
	}
	cases := []struct {
		name  string
		rules []PolicyRule
		want  AuthOutcome
	}{
		{"SSO@1 beats Exempt@2", []PolicyRule{mk(validSSORule(), "sso", 1), mk(validExemptRule(), "ex", 2)}, OutcomeSSORequired},
		{"Exempt@1 beats SSO@2", []PolicyRule{mk(validExemptRule(), "ex", 1), mk(validSSORule(), "sso", 2)}, OutcomeExempt},
		{"CR@1 beats SSO@2", []PolicyRule{mk(validCRRule(), "cr", 1), mk(validSSORule(), "sso", 2)}, OutcomeCredentialRequired},
		{"SSO@1 beats CR@2", []PolicyRule{mk(validSSORule(), "sso", 1), mk(validCRRule(), "cr", 2)}, OutcomeSSORequired},
	}
	for _, tc := range cases {
		if d := resolveAuthOutcomeFrom(tc.rules, ssoCtx()); d.Outcome != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, d.Outcome, tc.want)
		}
	}
}

// ── Runtime: SSORequired is active and wins by priority (Phase 3 Slice 4) ─────

func TestP3S3_Runtime_SSOWinsByPriority(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p3s3-shadow.example.test"
	mk := func(base PolicyRule, name string, prio int) PolicyRule {
		r := scopeLocal(base, name, host)
		r.Priority = prio
		return r
	}

	// SSO@1 + Exempt@2 → SSO wins by priority (priority-only model, no special
	// Exempt precedence).
	withFreshPolicyStore(t)
	policyStore.Add(mk(validSSORule(), "sso-1", 1))
	policyStore.Add(mk(validExemptRule(), "ex-2", 2))
	if d := resolveNoCredAuthOutcome(makeRequest("http://"+host+"/", nil), "127.0.0.1"); d.Outcome != OutcomeSSORequired {
		t.Errorf("runtime: SSO@1 must win over Exempt@2 by priority; got %q", d.Outcome)
	}

	// SSO@1 + CR@2 → SSO wins by priority.
	withFreshPolicyStore(t)
	policyStore.Add(mk(validSSORule(), "sso-1", 1))
	policyStore.Add(mk(validCRRule(), "cr-2", 2))
	if d := resolveNoCredAuthOutcome(makeRequest("http://"+host+"/", nil), "127.0.0.1"); d.Outcome != OutcomeSSORequired {
		t.Errorf("runtime: SSO@1 must win over CR@2 by priority; got %q", d.Outcome)
	}

	// SSO-only → runtime resolves SSORequired (runtime-active).
	withFreshPolicyStore(t)
	policyStore.Add(mk(validSSORule(), "sso-only", 1))
	if d := resolveNoCredAuthOutcome(makeRequest("http://"+host+"/", nil), "127.0.0.1"); d.Outcome != OutcomeSSORequired {
		t.Errorf("runtime: SSO-only must resolve SSORequired (active); got %q", d.Outcome)
	}
}

func TestP3S3_Runtime_ExemptCRUnchanged(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p3s3-unchanged.example.test"

	withFreshPolicyStore(t)
	policyStore.Add(scopeLocal(validExemptRule(), "ex", host))
	if d := resolveNoCredAuthOutcome(makeRequest("http://"+host+"/", nil), "127.0.0.1"); d.Outcome != OutcomeExempt {
		t.Errorf("Exempt-only runtime must resolve Exempt; got %q", d.Outcome)
	}

	withFreshPolicyStore(t)
	policyStore.Add(scopeLocal(validCRRule(), "cr", host))
	if d := resolveNoCredAuthOutcome(makeRequest("http://"+host+"/", nil), "127.0.0.1"); d.Outcome != OutcomeCredentialRequired {
		t.Errorf("CR-only runtime must resolve CredentialRequired; got %q", d.Outcome)
	}

	// Presented credentials → header guard returns Default (resolver not consulted).
	r := makeRequest("http://"+host+"/", map[string]string{"Proxy-Authorization": "Basic Zm9vOmJhcg=="})
	if d := resolveNoCredAuthOutcome(r, "127.0.0.1"); d.Outcome != OutcomeDefault {
		t.Errorf("presented credentials must short-circuit to Default; got %q", d.Outcome)
	}
}

// ── Observability ────────────────────────────────────────────────────────────

func TestP3S3_Metric_ExposedAndIncrementsOnRuntimeSSO(t *testing.T) {
	old := metricsToken
	metricsToken = ""
	t.Cleanup(func() { metricsToken = old })

	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	const host = "p3s3-metric.example.test"
	policyStore.Add(scopeLocal(validSSORule(), "sso-metric", host))

	start := atomic.LoadInt64(&statAuthSSORequired)
	// A live request matching the SSO rule now increments the counter (Phase 3
	// Slice 4 — a non-browser SSO request fails closed 403 and counts).
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"User-Agent": "curl/8.0"}))
	if got := atomic.LoadInt64(&statAuthSSORequired); got != start+1 {
		t.Errorf("runtime SSO response must increment statAuthSSORequired: %d → %d", start, got)
	}

	// Exposed in the metrics output.
	mw := httptest.NewRecorder()
	handleMetrics(mw, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	body := mw.Body.String()
	for _, want := range []string{
		"# TYPE culvert_auth_sso_required_total counter",
		"culvert_auth_sso_required_total ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

func TestP3S3_AuthLogFieldsFor_SerializesSSORequired(t *testing.T) {
	sso := validSSORule()
	sso.ID = "rule-sso-1"
	d := AuthDecision{Outcome: OutcomeSSORequired, Rule: &sso}
	f := authLogFieldsFor(d)
	if f.Outcome != OutcomeSSORequired {
		t.Errorf("auth_outcome must serialize SSORequired, got %q", f.Outcome)
	}
	if f.PolicyRuleID != "rule-sso-1" || f.PolicyRuleName != "require-sso-portal" {
		t.Errorf("rule id/name not serialized: %+v", f)
	}
	if len(f.SubjectMatchTypes) != 1 || f.SubjectMatchTypes[0] != subjectPredicateCIDR {
		t.Errorf("subject predicate types not serialized low-cardinality: %+v", f.SubjectMatchTypes)
	}
}

func TestP3S3_Simulator_ShowsSSORequiredSeparateFromStage2(t *testing.T) {
	withFreshPolicyStore(t)
	setDefaultPolicyAction("deny")
	policyStore.Add(validSSORule()) // 10.0.5.0/24 → portal.example.com

	resp := runSim(t, map[string]any{"sourceIP": "10.0.5.7", "host": "portal.example.com"})
	if resp.Auth.Outcome != "SSORequired" {
		t.Fatalf("simulator Stage-1 outcome = %q, want SSORequired", resp.Auth.Outcome)
	}
	if !strings.Contains(resp.Auth.Note, "NOT Allow") || !strings.Contains(resp.Auth.Note, "302") {
		t.Errorf("SSORequired note must frame it as not-Allow and describe the 302/403 challenge: %q", resp.Auth.Note)
	}
	// Stage-2 stays separate: SSORequired must not borrow the exempt authSource,
	// and default-deny still applies independently.
	if resp.Auth.Stage2AuthSource == "exempt" {
		t.Errorf("SSORequired must not set stage2AuthSource=exempt")
	}
	if resp.Matched {
		t.Errorf("no access rule exists — Stage-2 must not match (SSORequired must not imply Allow)")
	}
}

// With SSORequired runtime-active (Phase 3 Slice 4), the simulator's reported
// outcome MATCHES the live gate — there is no longer any divergence. runtimeOutcome
// equals outcome for the priority winner (SSO beats lower Exempt/CR).
func TestP3S3_Simulator_RuntimeMatchesResolver(t *testing.T) {
	mk := func(base PolicyRule, name string, prio int) PolicyRule {
		base.Name, base.Priority, base.DestFQDN = name, prio, "portal.example.com"
		base.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}}}
		return base
	}

	// SSO@1 + Exempt@2: SSO wins by priority at runtime too — no divergence.
	withFreshPolicyStore(t)
	setDefaultPolicyAction("deny")
	policyStore.Add(mk(validSSORule(), "sso-1", 1))
	policyStore.Add(mk(validExemptRule(), "ex-2", 2))
	resp := runSim(t, map[string]any{"sourceIP": "10.0.5.7", "host": "portal.example.com"})
	if resp.Auth.Outcome != "SSORequired" || resp.Auth.RuntimeOutcome != "SSORequired" {
		t.Errorf("SSO@1+Exempt@2: outcome=%q runtimeOutcome=%q, want both SSORequired", resp.Auth.Outcome, resp.Auth.RuntimeOutcome)
	}
	// SSORequired does not authenticate the request: Stage-2 does not see exempt.
	if resp.Auth.Stage2AuthSource == "exempt" {
		t.Errorf("SSORequired must not set stage2AuthSource=exempt, got %q", resp.Auth.Stage2AuthSource)
	}

	// SSO@1 + CR@2: SSO wins by priority — no divergence.
	withFreshPolicyStore(t)
	policyStore.Add(mk(validSSORule(), "sso-1", 1))
	policyStore.Add(mk(validCRRule(), "cr-2", 2))
	resp = runSim(t, map[string]any{"sourceIP": "10.0.5.7", "host": "portal.example.com"})
	if resp.Auth.Outcome != "SSORequired" || resp.Auth.RuntimeOutcome != "SSORequired" {
		t.Errorf("SSO@1+CR@2: outcome=%q runtimeOutcome=%q, want both SSORequired", resp.Auth.Outcome, resp.Auth.RuntimeOutcome)
	}
}

func TestP3S3_KillSwitch_DoesNotSuppressSSORequired(t *testing.T) {
	setAuthExemptDisabled(true)
	t.Cleanup(func() { setAuthExemptDisabled(false) })
	if d := resolveAuthOutcomeFrom([]PolicyRule{validSSORule()}, ssoCtx()); d.Outcome != OutcomeSSORequired {
		t.Fatalf("Exempt kill switch must NOT suppress SSORequired; got %q", d.Outcome)
	}
}
