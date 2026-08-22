package main

// ui_tls_fallback_preauth_test.go — SEC-TLSFB-1 regression wall.
//
// The admin-UI TLS-fallback signal is deliberately readable BEFORE
// authentication: a browser sitting on the login form, about to submit a
// password, must be able to learn the connection is cleartext. That is the
// boolean. The CAUSE is a different question, and it must never travel on an
// unauthenticated surface — it is a raw error string from the self-sign path,
// and Go's x509 encoder embeds the offending value in its errors, so an
// operator-configured SAN or the host's own name (uitls.collectSANs adds
// os.Hostname()) can reach any unauthenticated client on the admin port.
//
// This is the repository's existing rule for unauthenticated surfaces (the
// /ready ca / cluster_ca / frontend_v2 rows all carry FIXED detail), applied
// to the two public auth endpoints.
//
// Both halves are pinned here, in both directions:
//   - the flag still reaches the pre-auth surfaces (the warning must not be
//     silently disabled by "fixing" the disclosure), and
//   - the cause never does, while an authenticated viewer still gets it.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withTLSFallback installs a fallback state for the duration of a test.
func withTLSFallback(t *testing.T, active bool, reason string) {
	t.Helper()
	prevActive, prevReason := uiTLSFallbackActive, uiTLSFallbackReason
	uiTLSFallbackActive, uiTLSFallbackReason = active, reason
	t.Cleanup(func() { uiTLSFallbackActive, uiTLSFallbackReason = prevActive, prevReason })
}

func decodeJSONBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not JSON: %v (body %q)", err, rec.Body.String())
	}
	return got
}

// The secret-shaped cause used across these tests: the exact shape Go's x509
// encoder produces when a SAN cannot be encoded, carrying an internal name.
const tlsFallbackSecretReason = `x509: "vault-primary.corp.internal" cannot be encoded as an IA5String`

// TestSECTLSFB1_SetupStatusNeverLeaksTheCause — /api/setup/status is on the
// public allowlist (isPublicUIAuthPath: prefix /api/setup). It must carry the
// flag and an EMPTY cause.
func TestSECTLSFB1_SetupStatusNeverLeaksTheCause(t *testing.T) {
	withTLSFallback(t, true, tlsFallbackSecretReason)

	rec := httptest.NewRecorder()
	apiSetupStatus(rec, httptest.NewRequest(http.MethodGet, "/api/setup/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got := decodeJSONBody(t, rec)

	if got["ui_tls_fallback"] != true {
		t.Errorf("ui_tls_fallback = %v, want true — the pre-auth cleartext warning must still fire", got["ui_tls_fallback"])
	}
	// Present (strict client decoders require the key) but empty.
	v, ok := got["ui_tls_fallback_reason"]
	if !ok {
		t.Fatalf("ui_tls_fallback_reason key absent; strict runtime decoders require it")
	}
	if v != "" {
		t.Errorf("ui_tls_fallback_reason = %q on an UNAUTHENTICATED endpoint, want \"\"", v)
	}
	if body := rec.Body.String(); strings.Contains(body, "vault-primary.corp.internal") {
		t.Errorf("internal host name leaked in unauthenticated body: %s", body)
	}
}

// TestSECTLSFB1_AuthStatusNeverLeaksTheCause — every branch of
// /api/auth/status (also public) goes through jsonOKAuthStatus.
func TestSECTLSFB1_AuthStatusNeverLeaksTheCause(t *testing.T) {
	withTLSFallback(t, true, tlsFallbackSecretReason)

	for _, tc := range []struct {
		name   string
		fields map[string]any
	}{
		{"logged out", map[string]any{"loggedIn": false}},
		{"logged in", map[string]any{"loggedIn": true, "user": "alice", "role": RoleAdmin}},
		{"unconfigured bootstrap", map[string]any{"loggedIn": true, "user": "", "role": RoleAdmin}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			jsonOKAuthStatus(rec, tc.fields)
			got := decodeJSONBody(t, rec)

			if got["ui_tls_fallback"] != true {
				t.Errorf("ui_tls_fallback = %v, want true", got["ui_tls_fallback"])
			}
			v, ok := got["ui_tls_fallback_reason"]
			if !ok {
				t.Fatalf("ui_tls_fallback_reason key absent; strict runtime decoders require it")
			}
			if v != "" {
				t.Errorf("ui_tls_fallback_reason = %q on an UNAUTHENTICATED endpoint, want \"\"", v)
			}
		})
	}
}

// TestSECTLSFB1_FlagStillReachesPreAuthWhenClear — the negative case: with no
// fallback the flag is false and the cause stays empty. A test that only
// asserted "reason is empty" would pass against a build that also stopped
// reporting the fallback at all, which is the failure mode that matters most
// (an operator typing a password into cleartext with no warning).
func TestSECTLSFB1_FlagStillReachesPreAuthWhenClear(t *testing.T) {
	withTLSFallback(t, false, "")

	rec := httptest.NewRecorder()
	apiSetupStatus(rec, httptest.NewRequest(http.MethodGet, "/api/setup/status", nil))
	got := decodeJSONBody(t, rec)
	if got["ui_tls_fallback"] != false {
		t.Errorf("ui_tls_fallback = %v, want false", got["ui_tls_fallback"])
	}
	if got["ui_tls_fallback_reason"] != "" {
		t.Errorf("ui_tls_fallback_reason = %v, want \"\"", got["ui_tls_fallback_reason"])
	}
}

// TestSECTLSFB1_PreAuthReasonIsUnconditional — malformed/empty/huge causes all
// collapse to the same fixed value; there is no input that reopens the channel.
func TestSECTLSFB1_PreAuthReasonIsUnconditional(t *testing.T) {
	for _, reason := range []string{
		"",
		tlsFallbackSecretReason,
		"line one\nline two\r\nSet-Cookie: injected=1",
		stringOfLength(64 * 1024),
	} {
		withTLSFallback(t, true, reason)
		if got := preAuthTLSFallbackReason(); got != "" {
			t.Fatalf("preAuthTLSFallbackReason() = %q for reason %.32q…, want \"\"", got, reason)
		}
	}
}

// TestSECTLSFB1_AuthenticatedCauseStillAvailable — the fix must not destroy
// the operator's diagnostic path: GET /api/settings/network (viewer+) still
// carries the full cause.
func TestSECTLSFB1_AuthenticatedCauseStillAvailable(t *testing.T) {
	withTLSFallback(t, true, tlsFallbackSecretReason)

	req := httptest.NewRequest(http.MethodGet, "/api/settings/network", nil)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleViewer))
	rec := httptest.NewRecorder()
	apiNetworkSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	got := decodeJSONBody(t, rec)
	if got["ui_tls_fallback"] != true {
		t.Errorf("ui_tls_fallback = %v, want true", got["ui_tls_fallback"])
	}
	if got["ui_tls_fallback_reason"] != tlsFallbackSecretReason {
		t.Errorf("authenticated cause = %v, want the full reason — the diagnostic path must survive the fix", got["ui_tls_fallback_reason"])
	}
}

// TestSECTLSFB1_UnauthenticatedCallerIsRefusedTheAuthenticatedSurface — the
// other half of the boundary: the endpoint that DOES carry the cause is not
// on the public allowlist, so an anonymous caller cannot simply ask it.
func TestSECTLSFB1_UnauthenticatedCallerIsRefusedTheAuthenticatedSurface(t *testing.T) {
	if isPublicUIAuthPath("/api/settings/network") {
		t.Fatalf("/api/settings/network is on the public allowlist — the cause would be readable anonymously")
	}
	// And the two surfaces that DO carry the flag are public, by design.
	for _, p := range []string{"/api/setup/status", "/api/auth/status"} {
		if !isPublicUIAuthPath(p) {
			t.Errorf("%s is no longer public — the pre-auth cleartext warning would never render", p)
		}
	}
}

func stringOfLength(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'A'
	}
	return string(b)
}
