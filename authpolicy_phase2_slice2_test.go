package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Phase 2 Slice 2 — the pure resolver returns CredentialRequired for matching CR
// rules; observability + diagnostics + simulator surface it; but it stays
// runtime-inert (proxy.go consumes only Exempt, untouched). Kill switch disables
// Exempt only.

func p2s2CtxMatch() RequestContext {
	return RequestContext{ClientIP: "10.0.5.50", Host: "updates.example.com", Protocol: "http", Method: "GET"}
}

// ── Resolver: CR resolves; SSORequired/non-matching → Default ────────────────

func TestP2S2_Resolver_MatchingCRReturnsCredentialRequired(t *testing.T) {
	d := resolveAuthOutcomeFrom([]PolicyRule{validCRRule()}, p2s2CtxMatch())
	if d.Outcome != OutcomeCredentialRequired {
		t.Fatalf("matching CR rule: outcome = %q, want CredentialRequired", d.Outcome)
	}
	if d.Rule == nil || d.Rule.Name != "require-creds-vendor" {
		t.Fatalf("CR decision must carry the matched rule, got %+v", d.Rule)
	}
}

func TestP2S2_Resolver_DisabledExpiredNonMatchingCR_Default(t *testing.T) {
	disabled := validCRRule()
	f := false
	disabled.Enabled = &f
	expired := validCRRule()
	expired.Auth.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	cases := map[string]PolicyRule{
		"disabled":        disabled,
		"expired":         expired,
		"source mismatch": validCRRule(), // queried with a non-matching IP below
		"dest mismatch":   validCRRule(),
	}
	for name, r := range cases {
		ctx := p2s2CtxMatch()
		if name == "source mismatch" {
			ctx.ClientIP = "10.9.9.9"
		}
		if name == "dest mismatch" {
			ctx.Host = "other.example.com"
		}
		if d := resolveAuthOutcomeFrom([]PolicyRule{r}, ctx); d.Outcome != OutcomeDefault {
			t.Errorf("%s CR must resolve Default, got %q", name, d.Outcome)
		}
	}
}

func TestP2S2_Resolver_SSORequiredInert(t *testing.T) {
	r := validCRRule()
	r.Auth.Outcome = OutcomeSSORequired
	if d := resolveAuthOutcomeFrom([]PolicyRule{r}, p2s2CtxMatch()); d.Outcome != OutcomeDefault {
		t.Errorf("SSORequired must be inert (Default), got %q", d.Outcome)
	}
}

// ── Mixed Exempt/CR priority: first matching auth rule by priority wins ───────

func TestP2S2_Resolver_MixedPriority(t *testing.T) {
	mkExempt := func(name string, pri int) PolicyRule {
		r := validExemptRule()
		r.Name, r.Priority = name, pri
		return r
	}
	mkCR := func(name string, pri int) PolicyRule {
		r := validCRRule()
		r.Name, r.Priority = name, pri
		return r
	}
	// Exempt@1 + CR@2 → Exempt wins.
	d := resolveAuthOutcomeFrom([]PolicyRule{mkCR("cr", 2), mkExempt("ex", 1)}, p2s2CtxMatch())
	if d.Outcome != OutcomeExempt || d.Rule.Name != "ex" {
		t.Errorf("Exempt@1 must win over CR@2, got %q/%v", d.Outcome, d.Rule)
	}
	// CR@1 + Exempt@2 → CR wins (input order shuffled to prove sort-independence).
	d = resolveAuthOutcomeFrom([]PolicyRule{mkExempt("ex", 2), mkCR("cr", 1)}, p2s2CtxMatch())
	if d.Outcome != OutcomeCredentialRequired || d.Rule.Name != "cr" {
		t.Errorf("CR@1 must win over Exempt@2, got %q/%v", d.Outcome, d.Rule)
	}
}

// ── Kill switch disables Exempt only ─────────────────────────────────────────

func TestP2S2_KillSwitch_DisablesExemptNotCR(t *testing.T) {
	setAuthExemptDisabled(true)
	t.Cleanup(func() { setAuthExemptDisabled(false) })

	// Only-Exempt → suppressed → Default.
	if d := resolveAuthOutcomeFrom([]PolicyRule{validExemptRule()}, p2s2CtxMatch()); d.Outcome != OutcomeDefault {
		t.Errorf("kill switch must disable Exempt → Default, got %q", d.Outcome)
	}
	// Only-CR → CredentialRequired (kill switch does NOT disable CR).
	if d := resolveAuthOutcomeFrom([]PolicyRule{validCRRule()}, p2s2CtxMatch()); d.Outcome != OutcomeCredentialRequired {
		t.Errorf("kill switch must NOT disable CR, got %q", d.Outcome)
	}
	// Exempt@1 + CR@2: Exempt suppressed, CR@2 then wins.
	ex := validExemptRule()
	ex.Name, ex.Priority = "ex", 1
	cr := validCRRule()
	cr.Name, cr.Priority = "cr", 2
	d := resolveAuthOutcomeFrom([]PolicyRule{ex, cr}, p2s2CtxMatch())
	if d.Outcome != OutcomeCredentialRequired || d.Rule.Name != "cr" {
		t.Errorf("kill switch: suppressed Exempt@1 must fall through to CR@2, got %q/%v", d.Outcome, d.Rule)
	}
}

// ── Observability ────────────────────────────────────────────────────────────

func TestP2S2_AuthLogFieldsFor_CredentialRequired(t *testing.T) {
	rule := validCRRule()
	rule.ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	f := authLogFieldsFor(AuthDecision{Outcome: OutcomeCredentialRequired, Rule: &rule})
	if f.Outcome != OutcomeCredentialRequired || f.PolicyRuleID != rule.ID || f.PolicyRuleName != rule.Name {
		t.Errorf("CR log fields wrong: %+v", f)
	}
	if len(f.SubjectMatchTypes) != 1 || f.SubjectMatchTypes[0] != "cidr" || f.SchemaVersion != 1 {
		t.Errorf("CR subject fields wrong (low-cardinality types only): %+v", f)
	}
}

func TestP2S2_Metric_DefinedNotIncrementedByRuntime(t *testing.T) {
	old := metricsToken
	metricsToken = ""
	t.Cleanup(func() { metricsToken = old })

	start := atomic.LoadInt64(&statAuthCredentialRequired)
	// The request-logging path must not touch the CR counter.
	recordRequest("1.2.3.4", "GET", "example.com", "OK", "", "", "", "")
	if got := atomic.LoadInt64(&statAuthCredentialRequired); got != start {
		t.Errorf("request path must not increment statAuthCredentialRequired: %d → %d", start, got)
	}
	// Defined in the exposition.
	w := httptest.NewRecorder()
	handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	body := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_auth_credential_required_total counter",
		"culvert_auth_credential_required_total ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
	// The increment helper works (proves wiring exists for Slice 3, unused now).
	incAuthCredentialRequired()
	t.Cleanup(func() { atomic.AddInt64(&statAuthCredentialRequired, -1) })
	if got := atomic.LoadInt64(&statAuthCredentialRequired); got != start+1 {
		t.Errorf("incAuthCredentialRequired must bump the counter: %d → %d", start, got)
	}
}

// ── Diagnostics ──────────────────────────────────────────────────────────────

func TestP2S2_Diag_CRUnderUnauthMode_Warn(t *testing.T) {
	checks := authCredentialRequiredDiagnostics([]PolicyRule{validCRRule()}, true /*unauthMode*/, true /*hasCredProvider*/)
	if c, ok := hasCheck(checks, "auth_cr_dead_under_unauth_mode"); !ok || c.Status != diagWarn {
		t.Errorf("expected WARN auth_cr_dead_under_unauth_mode, got %+v", checks)
	}
}

func TestP2S2_Diag_CRNoCredentialProvider_Fail(t *testing.T) {
	checks := authCredentialRequiredDiagnostics([]PolicyRule{validCRRule()}, false, false /*no cred provider*/)
	c, ok := hasCheck(checks, "auth_cr_no_credential_provider")
	if !ok || c.Status != diagFail {
		t.Errorf("expected FAIL auth_cr_no_credential_provider, got %+v", checks)
	}
	// With a credential-capable provider, no FAIL.
	ok2 := func() bool {
		_, found := hasCheck(authCredentialRequiredDiagnostics([]PolicyRule{validCRRule()}, false, true), "auth_cr_no_credential_provider")
		return found
	}()
	if ok2 {
		t.Error("must not FAIL when a credential-capable provider exists")
	}
	// No CR rules → no checks at all.
	if got := authCredentialRequiredDiagnostics([]PolicyRule{validExemptRule()}, true, false); got != nil {
		t.Errorf("no CR rules → no CR checks, got %+v", got)
	}
}

// SAML-only does NOT count as credential-capable.
func TestP2S2_HasCredentialCapableProvider_SAMLExcluded(t *testing.T) {
	origReg, origCfg := idpRegistry, cfg
	t.Cleanup(func() { idpRegistry, cfg = origReg, origCfg })
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}} // no local user, no legacy provider

	// SAML-only registry → not credential-capable.
	idpRegistry = &IdPRegistry{profiles: []*IdPProfile{{ID: "s1", Name: "Corp SAML", Type: IdPTypeSAML, Enabled: true}}}
	if hasCredentialCapableProvider() {
		t.Error("SAML-only must NOT be credential-capable")
	}
	// Add an enabled OIDC profile → now credential-capable.
	idpRegistry = &IdPRegistry{profiles: []*IdPProfile{
		{ID: "s1", Name: "Corp SAML", Type: IdPTypeSAML, Enabled: true},
		{ID: "o1", Name: "Corp OIDC", Type: IdPTypeOIDC, Enabled: true},
	}}
	if !hasCredentialCapableProvider() {
		t.Error("an enabled OIDC profile must be credential-capable")
	}
}

// (Slice-2's runtime-inertness test was superseded by Phase 2 Slice 3, which
//  wires CR onto the hot path. The CR runtime challenge is covered exhaustively
//  in authpolicy_phase2_slice3_test.go.)

// Priority is now real (Phase 2 Slice 3): a higher-priority CR rule intentionally
// beats a lower-priority Exempt rule on the runtime no-credentials path. (The
// Slice-2 Exempt-only stopgap is removed now that proxy.go handles CR.)
func TestP2S3_RuntimePriority_CRBeatsLowerExempt(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p2s3-prio.example.test"
	cidr := []string{"127.0.0.0/8"}
	cr := validCRRule()
	cr.Name, cr.Priority, cr.DestFQDN = "cr-1", 1, host
	cr.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: cidr}}}
	ex := validExemptRule()
	ex.Name, ex.Priority, ex.DestFQDN = "exempt-2", 2, host
	ex.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: cidr}}}
	policyStore.Add(cr)
	policyStore.Add(ex)

	// The runtime resolver returns CR@1 (highest priority wins).
	if d := resolveNoCredAuthOutcome(makeRequest("http://"+host+"/", nil), "127.0.0.1"); d.Outcome != OutcomeCredentialRequired {
		t.Fatalf("runtime resolver: CR@1 must win over Exempt@2, got %q", d.Outcome)
	}
	// End-to-end: CR@1 wins → 407 challenge (not waived).
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("CR@1 must challenge (407), got %d", w.Code)
	}

	// Swap priorities: Exempt@1 + CR@2 → Exempt wins → waived (not 407).
	withFreshPolicyStore(t)
	ex.Priority, cr.Priority = 1, 2
	policyStore.Add(ex)
	policyStore.Add(cr)
	w = httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code == http.StatusProxyAuthRequired {
		t.Fatal("Exempt@1 must win over CR@2 — request waived, not 407'd")
	}
}

// ── Simulator: CR shown as a Stage-1 challenge, separate from Stage-2 ─────────

func TestP2S2_Simulator_ShowsCredentialRequired(t *testing.T) {
	withFreshPolicyStore(t)
	setDefaultPolicyAction("deny")
	policyStore.Add(validCRRule())

	resp := runSim(t, map[string]any{"sourceIP": "10.0.5.50", "host": "updates.example.com"})
	if resp.Auth.Outcome != "CredentialRequired" {
		t.Fatalf("simulator Stage-1 outcome = %q, want CredentialRequired", resp.Auth.Outcome)
	}
	if !strings.Contains(resp.Auth.Note, "challenge") || strings.Contains(resp.Auth.Note, "Allow") && !strings.Contains(resp.Auth.Note, "NOT Allow") {
		t.Errorf("CR note must frame it as a challenge, not Allow/Block: %q", resp.Auth.Note)
	}
	// Stage-1 must NOT set authSource=exempt for CR.
	if resp.Auth.Stage2AuthSource == "exempt" {
		t.Errorf("CR must not set stage2AuthSource=exempt")
	}
	// Stage-2 decision remains separate and denies (no access rule).
	if resp.Matched {
		t.Error("CR is a Stage-1 challenge, not an access decision — Stage-2 must be separate")
	}
	if resp.DefaultAction != "deny" {
		t.Errorf("Stage-2 defaultAction = %q, want deny", resp.DefaultAction)
	}
}
