package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Regression — Exempt kill switch must not fail OPEN on a no-backend deployment.
//
// Bug: on a deployment with NO credential backend and NO SSO provider whose
// global default is Exempt, engaging the Exempt kill switch
// (authExemptKillSwitchEngaged / CULVERT_AUTHBYPASS_DISABLE) forced the
// effective default Exempt→Default. Because the auth gate keyed ENTRY on that
// forced (post-kill-switch) default, dropping the Exempt term skipped the whole
// Stage-1 gate — so scoped CredentialRequired rules silently stopped challenging.
// The kill switch, which must be strictly MORE restrictive, instead WEAKENED
// enforcement (fail-open). The frozen spec
// (AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md §2) requires a scoped CR match to yield
// 407 with the kill switch engaged, and unmatched no-backend traffic to stay
// inert at Stage-2 (default-deny), NOT receive an unfulfillable 407.
//
// These tests are RED before the fix:
//   (a) pre-fix the gate is skipped, the scoped CR rule never fires, and the
//       request falls straight through to Stage-2 default-deny (403, no CR
//       metric) instead of the required 407 credential challenge.
//   (b) guards the no-backend inert path: once the gate is (correctly) entered on
//       the pre-kill-switch default, the no-rule Default arm must fall through to
//       Stage-2 rather than emit an unfulfillable 407 / dangling captive redirect.

// setupNoBackendKillSwitchTest configures a proxy with NO credential-capable
// validator (no local user, no legacy/OIDC provider) and NO interactive IdP,
// a global default of Exempt (open), a clean default-deny policy store, and a
// released kill switch. Each test engages the kill switch explicitly.
func setupNoBackendKillSwitchTest(t *testing.T) {
	t.Helper()
	setupProxyTest(t) // fresh cfg (no SetAuth), rules cleared, default action = deny

	// Guarantee no interactive IdP (ssoCapable=false); restore the global
	// registry on cleanup so we never leak into sibling tests.
	origRegistry := idpRegistry
	idpRegistry = &IdPRegistry{live: map[string]IdentityProvider{}}
	t.Cleanup(func() { idpRegistry = origRegistry })

	// Prove the no-backend precondition — the whole bug is scoped to it.
	if hasCredentialCapableProvider() {
		t.Fatal("precondition: expected NO credential-capable backend")
	}
	if len(idpRegistry.EnabledProviders()) != 0 {
		t.Fatal("precondition: expected NO interactive SSO provider")
	}

	// Global default Exempt (open) — the deployment shape where the kill switch
	// bug bites: originally-Exempt, forced to Default by the kill switch.
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })

	setAuthExemptDisabled(false)
	t.Cleanup(func() { setAuthExemptDisabled(false) })
}

// (a) No-backend Exempt + kill switch engaged + scoped CredentialRequired rule
// → the CR destination must still receive a 407 challenge (CR is never disabled
// by the kill switch). Pre-fix: 403 default-deny, CR metric flat.
func TestKillSwitchNoBackend_ScopedCR_Challenges407(t *testing.T) {
	setupNoBackendKillSwitchTest(t)
	const host = "ks-nobackend-cr.example.test"
	policyStore.Add(p2s3CR("cr-nobackend", host)) // scoped to 127.0.0.0/8 → host

	setAuthExemptDisabled(true) // engage the kill switch (cleanup in helper)

	startCR := crCount()
	startFail := atomic.LoadInt64(&statAuthFail)
	w := httptest.NewRecorder()
	r := nonBrowserReq(host)
	handleRequest(w, r)

	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("no-backend + kill switch + scoped CR must still 407, got %d "+
			"(pre-fix the gate is skipped and this falls through to Stage-2 default-deny 403)", w.Code)
	}
	if got := w.Header().Get("Proxy-Authenticate"); got != `Basic realm="Culvert"` {
		t.Errorf("CR 407 must carry Proxy-Authenticate, got %q", got)
	}
	if crCount() != startCR+1 {
		t.Errorf("CR metric must move — the scoped rule fired under the kill switch: %d → %d", startCR, crCount())
	}
	if atomic.LoadInt64(&statAuthFail) != startFail+1 {
		t.Errorf("statAuthFail must increment for 407-counter compatibility")
	}
	// No identity is ever created for a CR challenge.
	if got := r.Header.Get("X-User-Identity"); got != "" {
		t.Errorf("CR must not create an identity, got %q", got)
	}
	// Request-log record carries the distinct CRED_REQUIRED status.
	if e := findLogByHost(t, host); e.Status != "CRED_REQUIRED" {
		t.Errorf("expected CRED_REQUIRED request-log status, got %q", e.Status)
	}
}

// (b) No-backend Exempt + kill switch engaged + NO matching rule → the request
// must be INERT at Stage-2 (default-deny 403), with NO unfulfillable 407 and NO
// dangling captive-portal redirect. This guards the no-backend inert guard:
// entering the gate on the pre-kill-switch default must NOT synthesize a 407 the
// operator can never satisfy (there is no backend to authenticate against).
func TestKillSwitchNoBackend_NoRule_InertStage2(t *testing.T) {
	setupNoBackendKillSwitchTest(t)
	const host = "ks-nobackend-inert.example.test"
	// No auth rule and no Stage-2 allow rule → default-deny is the only backstop.

	setAuthExemptDisabled(true) // engage the kill switch (cleanup in helper)

	startFail := atomic.LoadInt64(&statAuthFail)
	startCR := crCount()
	w := httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host))

	// Inert Stage-2 default-deny — NOT an unfulfillable 407.
	if w.Code != http.StatusForbidden {
		t.Fatalf("no-backend unmatched traffic must be inert at Stage-2 default-deny (403), got %d "+
			"(a 407 here is an unfulfillable challenge — no backend can satisfy it)", w.Code)
	}
	if got := w.Header().Get("Proxy-Authenticate"); got != "" {
		t.Errorf("inert no-backend fall-through must not emit a 407 challenge header, got %q", got)
	}
	if got := w.Header().Get("Location"); got != "" {
		t.Errorf("inert no-backend fall-through must not emit a captive-portal redirect, got %q", got)
	}
	if atomic.LoadInt64(&statAuthFail) != startFail {
		t.Errorf("inert fall-through must not count an auth failure: %d → %d", startFail, atomic.LoadInt64(&statAuthFail))
	}
	if crCount() != startCR {
		t.Errorf("no CR rule matched — the CR metric must not move")
	}
	// Reached the Stage-2 default-deny backstop with authSource unauth (open ≠ allow).
	e := findLogByHost(t, host)
	if e.Status != "POLICY_DEFAULT_DENY" {
		t.Errorf("expected POLICY_DEFAULT_DENY status (inert Stage-2), got %q", e.Status)
	}
	if e.Identity != "" {
		t.Errorf("inert no-backend traffic must carry no identity, got %q", e.Identity)
	}
}
