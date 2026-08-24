package main

// ui_tls_fallback_preauth_test.go — SEC-TLSFB-1 regression wall.
//
// startUI records a self-sign failure in uiTLSFallbackActive/
// uiTLSFallbackReason so the login and setup overlays can warn an operator
// BEFORE a password travels over the plain-HTTP fallback. The flag belongs on
// those pre-auth surfaces; the REASON does not.
//
// /api/setup/status and /api/auth/status are both on uiAuthMiddleware's public
// allowlist (isPublicUIAuthPath), so every field they return is readable
// without any credential. uiTLSFallbackReason is a raw selfSignedTLS() error,
// and its realistic failure mode is x509.CreateCertificate refusing a SAN — it
// quotes the offending value, so the string can carry a -ui-san entry, a
// CULVERT_PUBLIC_IP entry, or the host's own name. That is the exact rule the
// unauthenticated readiness rows already follow ("FIXED detail because the
// endpoint is unauthenticated", healthcheck.go) and that checkIdentityBackend
// states outright: the cause goes to the log and to authenticated surfaces,
// never to a pre-auth one.
//
// These tests are written to FAIL against the shape that shipped the reason on
// both public endpoints.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tlsFallbackSentinel stands in for the kind of operator-configured value an
// x509 SAN-rejection error quotes back. Deliberately distinctive so the body
// scan cannot pass by accident.
const tlsFallbackSentinel = "x509: cannot parse dnsName \"internal-mgmt.corp.invalid\""

// withTLSFallback arms the fallback globals for one test and restores them.
func withTLSFallback(t *testing.T, active bool, reason string) {
	t.Helper()
	prevActive, prevReason := uiTLSFallbackActive, uiTLSFallbackReason
	uiTLSFallbackActive, uiTLSFallbackReason = active, reason
	t.Cleanup(func() { uiTLSFallbackActive, uiTLSFallbackReason = prevActive, prevReason })
}

// decodeJSONBody decodes a handler response into a generic map.
func decodeJSONBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not JSON: %v (body: %s)", err, w.Body.String())
	}
	return m
}

// assertNoReason is the core assertion: the flag is present and true, the
// reason key is absent, and the sentinel appears nowhere in the raw bytes (so
// a future rename of the field cannot smuggle the same string back).
func assertNoReason(t *testing.T, label string, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status = %d; want 200 (body: %s)", label, w.Code, w.Body.String())
	}
	body := decodeJSONBody(t, w)
	if got, ok := body["ui_tls_fallback"]; !ok || got != true {
		t.Errorf("%s: ui_tls_fallback = %v (present=%v); want true — the pre-auth WARNING must survive", got, ok, label)
	}
	if _, ok := body["ui_tls_fallback_reason"]; ok {
		t.Errorf("%s: ui_tls_fallback_reason is present on an UNAUTHENTICATED response; the cause belongs on /api/settings/network and the log only", label)
	}
	if strings.Contains(w.Body.String(), "internal-mgmt.corp.invalid") {
		t.Errorf("%s: raw body leaks the self-sign cause to an unauthenticated caller: %s", label, w.Body.String())
	}
}

// TestTLSFallback_PreAuthSurfacesCarryNoReason pins the whole contract: the
// premise (both routes really are public), then every branch of both handlers.
func TestTLSFallback_PreAuthSurfacesCarryNoReason(t *testing.T) {
	// Premise. If either path ever leaves the public allowlist this test's
	// reasoning changes, so assert it rather than assume it.
	for _, p := range []string{"/api/setup/status", "/api/auth/status"} {
		if !isPublicUIAuthPath(p) {
			t.Fatalf("premise broken: %s is no longer a public path", p)
		}
	}

	withTLSFallback(t, true, tlsFallbackSentinel)

	t.Run("setup status", func(t *testing.T) {
		w := httptest.NewRecorder()
		apiSetupStatus(w, httptest.NewRequest(http.MethodGet, "/api/setup/status", http.NoBody))
		assertNoReason(t, "apiSetupStatus", w)
	})

	// apiAuthStatus has three response branches and the reason was added to
	// ALL of them via jsonOKAuthStatus, so all three are exercised.
	t.Run("auth status not configured", func(t *testing.T) {
		prev := cfg
		cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}} // IsConfigured() == false
		t.Cleanup(func() { cfg = prev })

		w := httptest.NewRecorder()
		apiAuthStatus(w, httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody))
		assertNoReason(t, "apiAuthStatus (unconfigured)", w)
	})

	t.Run("auth status no session", func(t *testing.T) {
		prev := cfg
		cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
		cfg.SetDefaultAuthOutcome(OutcomeExempt) // IsConfigured() == true, no credential
		t.Cleanup(func() { cfg = prev })

		w := httptest.NewRecorder()
		apiAuthStatus(w, httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody))
		assertNoReason(t, "apiAuthStatus (anonymous)", w)
	})

	t.Run("auth status bad basic credentials", func(t *testing.T) {
		prev := cfg
		cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
		cfg.SetDefaultAuthOutcome(OutcomeExempt)
		t.Cleanup(func() { cfg = prev })

		r := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
		r.SetBasicAuth("nobody", "wrong-password")
		w := httptest.NewRecorder()
		apiAuthStatus(w, r)
		assertNoReason(t, "apiAuthStatus (bad basic)", w)
	})
}

// TestTLSFallback_AuthenticatedSurfaceStillCarriesReason is the other half:
// removing the reason from the pre-auth surfaces must not remove the operator's
// only in-product way to see WHY self-signing failed. GET /api/settings/network
// is viewer-gated, so it keeps the cause.
func TestTLSFallback_AuthenticatedSurfaceStillCarriesReason(t *testing.T) {
	withTLSFallback(t, true, tlsFallbackSentinel)

	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleViewer)
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/settings/network", http.NoBody)
	w := httptest.NewRecorder()
	apiNetworkSettings(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("apiNetworkSettings status = %d; want 200 (body: %s)", w.Code, w.Body.String())
	}
	body := decodeJSONBody(t, w)
	if got, ok := body["ui_tls_fallback"]; !ok || got != true {
		t.Errorf("ui_tls_fallback = %v (present=%v); want true", got, ok)
	}
	if got, _ := body["ui_tls_fallback_reason"].(string); got != tlsFallbackSentinel {
		t.Errorf("ui_tls_fallback_reason = %q; want the full cause %q on the authenticated surface", got, tlsFallbackSentinel)
	}
}

// TestTLSFallback_InactiveReportsFalse is the boundary case: with TLS healthy
// (or -ui-no-tls explicitly chosen) the pre-auth flag must be false, so the
// overlays show no banner. Guards against a fix that hardcodes the field.
func TestTLSFallback_InactiveReportsFalse(t *testing.T) {
	withTLSFallback(t, false, "")

	prev := cfg
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	t.Cleanup(func() { cfg = prev })

	for _, tc := range []struct {
		name    string
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"setup", "/api/setup/status", apiSetupStatus},
		{"auth", "/api/auth/status", apiAuthStatus},
	} {
		w := httptest.NewRecorder()
		tc.handler(w, httptest.NewRequest(http.MethodGet, tc.path, http.NoBody))
		body := decodeJSONBody(t, w)
		if got, ok := body["ui_tls_fallback"]; !ok || got != false {
			t.Errorf("%s: ui_tls_fallback = %v (present=%v); want false", tc.name, got, ok)
		}
		if _, ok := body["ui_tls_fallback_reason"]; ok {
			t.Errorf("%s: ui_tls_fallback_reason must never appear on a public route", tc.name)
		}
	}
}

// TestTLSFallback_MalformedAndNonGETRequestsLeakNothing covers the malformed /
// wrong-method inputs a scanner sends: the reason must not appear on any
// response either handler can produce, including the 405 branches.
func TestTLSFallback_MalformedAndNonGETRequestsLeakNothing(t *testing.T) {
	withTLSFallback(t, true, tlsFallbackSentinel)

	prev := cfg
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	t.Cleanup(func() { cfg = prev })

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, "TRACE"} {
		for _, tc := range []struct {
			name    string
			path    string
			handler func(http.ResponseWriter, *http.Request)
		}{
			{"setup", "/api/setup/status", apiSetupStatus},
			{"auth", "/api/auth/status", apiAuthStatus},
		} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(method, tc.path+"?%zz=1&cursor=%%%", strings.NewReader("{not json"))
			tc.handler(w, r)
			if strings.Contains(w.Body.String(), "internal-mgmt.corp.invalid") {
				t.Errorf("%s %s: leaked the self-sign cause: %s", method, tc.name, w.Body.String())
			}
		}
	}
}

// TestTLSFallback_ConcurrentPreAuthReadsAreClean is the concurrency case: the
// public endpoints are the ones an unauthenticated client can hammer, and the
// globals are plain (written once in startUI before any listener goroutine
// exists). Run under -race, this proves the read path adds no write and that
// the redaction holds under parallel load rather than only on the first call.
func TestTLSFallback_ConcurrentPreAuthReadsAreClean(t *testing.T) {
	withTLSFallback(t, true, tlsFallbackSentinel)

	prev := cfg
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	t.Cleanup(func() { cfg = prev })

	const workers = 32
	errs := make(chan string, workers*2)
	done := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for _, tc := range []struct {
				path    string
				handler func(http.ResponseWriter, *http.Request)
			}{
				{"/api/setup/status", apiSetupStatus},
				{"/api/auth/status", apiAuthStatus},
			} {
				w := httptest.NewRecorder()
				tc.handler(w, httptest.NewRequest(http.MethodGet, tc.path, http.NoBody))
				if strings.Contains(w.Body.String(), "internal-mgmt.corp.invalid") {
					errs <- tc.path + " leaked the self-sign cause"
				}
			}
		}()
	}
	for i := 0; i < workers; i++ {
		<-done
	}
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}
