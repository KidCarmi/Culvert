package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ── NewOIDCAuth validation ────────────────────────────────────────────────────

func TestNewOIDCAuth_MissingURL(t *testing.T) {
	_, err := NewOIDCAuth(OIDCConfig{ClientID: "id", ClientSecret: "secret"})
	if err == nil {
		t.Error("expected error when IntrospectionURL is empty")
	}
}

func TestNewOIDCAuth_MissingClientID(t *testing.T) {
	_, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: "https://idp/introspect"})
	if err == nil {
		t.Error("expected error when ClientID is empty")
	}
}

func TestNewOIDCAuth_DefaultTTL(t *testing.T) {
	a, err := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: "https://idp/introspect",
		ClientID:         "id",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.ttl != 2*time.Minute {
		t.Errorf("expected 2m default TTL, got %v", a.ttl)
	}
}

func TestOIDCAuth_Name(t *testing.T) {
	a, _ := NewOIDCAuth(OIDCConfig{IntrospectionURL: "https://idp/introspect", ClientID: "id"})
	if a.Name() != "oidc" {
		t.Errorf("Name() = %q, want oidc", a.Name())
	}
}

// ── Mock IDP helpers ──────────────────────────────────────────────────────────

// mockIDP creates a test HTTP server that returns a fixed introspection response.
func mockIDP(t *testing.T, resp introspectionResponse) (*httptest.Server, *OIDCAuth) {
	t.Helper()
	allowLoopbackSSRF(t) // NewOIDCAuth now installs the SSRF dial guard (RISK-002); permit the loopback test IdP
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck // test response writer
	}))
	a, err := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: srv.URL,
		ClientID:         "client",
		ClientSecret:     "secret",
	})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}
	return srv, a
}

// ── Active / inactive token ───────────────────────────────────────────────────

func TestOIDCAuth_Verify_ActiveToken(t *testing.T) {
	srv, a := mockIDP(t, introspectionResponse{Active: true, Sub: "alice"})
	defer srv.Close()

	if !a.Verify("alice", "valid-token") {
		t.Error("expected Verify=true for active token")
	}
}

func TestOIDCAuth_Verify_InactiveToken(t *testing.T) {
	srv, a := mockIDP(t, introspectionResponse{Active: false})
	defer srv.Close()

	if a.Verify("alice", "expired-token") {
		t.Error("expected Verify=false for inactive token")
	}
}

func TestOIDCAuth_Verify_EmptyToken(t *testing.T) {
	a, _ := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: "http://127.0.0.1:1",
		ClientID:         "id",
	})
	// Should return false without making any HTTP call.
	if a.Verify("alice", "") {
		t.Error("expected Verify=false for empty token")
	}
}

// ── Scope check ───────────────────────────────────────────────────────────────

func TestOIDCAuth_Verify_RequiredScopePresent(t *testing.T) {
	allowLoopbackSSRF(t) // NewOIDCAuth installs the SSRF dial guard (RISK-002); permit the loopback test IdP
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(introspectionResponse{Active: true, Sub: "alice", Scope: "openid proxy:access email"}) //nolint:errcheck // test response writer
	}))
	defer srv.Close()

	a, _ := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: srv.URL,
		ClientID:         "id",
		RequiredScope:    "proxy:access",
	})
	if !a.Verify("alice", "tok") {
		t.Error("expected Verify=true when required scope is present")
	}
}

func TestOIDCAuth_Verify_RequiredScopeMissing(t *testing.T) {
	allowLoopbackSSRF(t) // NewOIDCAuth installs the SSRF dial guard (RISK-002); permit the loopback test IdP
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(introspectionResponse{Active: true, Scope: "openid email"}) //nolint:errcheck // test response writer
	}))
	defer srv.Close()

	a, _ := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: srv.URL,
		ClientID:         "id",
		RequiredScope:    "proxy:access",
	})
	if a.Verify("alice", "tok") {
		t.Error("expected Verify=false when required scope is missing")
	}
}

// ── Audience check ────────────────────────────────────────────────────────────

func TestOIDCAuth_Verify_AudienceStringMatch(t *testing.T) {
	allowLoopbackSSRF(t) // NewOIDCAuth installs the SSRF dial guard (RISK-002); permit the loopback test IdP
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return audience as a plain string.
		raw := `{"active":true,"sub":"alice","aud":"culvert"}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(raw)) //nolint:errcheck // test response writer
	}))
	defer srv.Close()

	a, _ := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: srv.URL,
		ClientID:         "id",
		RequiredAudience: "culvert",
	})
	if !a.Verify("alice", "tok") {
		t.Error("expected Verify=true when string audience matches")
	}
}

func TestOIDCAuth_Verify_AudienceArrayMatch(t *testing.T) {
	allowLoopbackSSRF(t) // NewOIDCAuth installs the SSRF dial guard (RISK-002); permit the loopback test IdP
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := `{"active":true,"sub":"alice","aud":["other","culvert"]}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(raw)) //nolint:errcheck // test response writer
	}))
	defer srv.Close()

	a, _ := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: srv.URL,
		ClientID:         "id",
		RequiredAudience: "culvert",
	})
	if !a.Verify("alice", "tok") {
		t.Error("expected Verify=true when audience array contains required value")
	}
}

func TestOIDCAuth_Verify_AudienceMismatch(t *testing.T) {
	allowLoopbackSSRF(t) // NewOIDCAuth installs the SSRF dial guard (RISK-002); permit the loopback test IdP
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := `{"active":true,"aud":"other-service"}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(raw)) //nolint:errcheck // test response writer
	}))
	defer srv.Close()

	a, _ := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: srv.URL,
		ClientID:         "id",
		RequiredAudience: "culvert",
	})
	if a.Verify("alice", "tok") {
		t.Error("expected Verify=false when audience does not match")
	}
}

// ── IDP unreachable ───────────────────────────────────────────────────────────

func TestOIDCAuth_Verify_IDPUnreachable(t *testing.T) {
	a, _ := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: "http://127.0.0.1:1/introspect",
		ClientID:         "id",
	})
	if a.Verify("alice", "tok") {
		t.Error("expected Verify=false when IDP is unreachable")
	}
}

func TestOIDCAuth_Verify_IDPReturns500(t *testing.T) {
	allowLoopbackSSRF(t) // NewOIDCAuth installs the SSRF dial guard (RISK-002); permit the loopback test IdP
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	a, _ := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "id"})
	if a.Verify("alice", "tok") {
		t.Error("expected Verify=false when IDP returns 500")
	}
}

// TestOIDCAuth_Verify_4xxDoesNotArmCooldown is the regression test for the
// CHAOS-47 review's Codex P1: a 4xx from the introspection endpoint is a
// client/token-side rejection, not a backend outage, so it must NOT arm the
// provider-wide unreachable cooldown. The gate arms after a single outage, so
// without this fix one malformed-token 400 would fail-close every OTHER user's
// authentication until a probe succeeded — an unauthenticated DoS. Each request
// must still reach the IdP (the gate never arms); contrast
// TestOIDCAuth_Verify_IDPReturns500, where one 5xx legitimately arms it.
func TestOIDCAuth_Verify_4xxDoesNotArmCooldown(t *testing.T) {
	allowLoopbackSSRF(t) // NewOIDCAuth installs the SSRF dial guard (RISK-002); permit the loopback test IdP
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "bad token", http.StatusBadRequest) // 400 — an RFC-noncompliant IdP's answer to a malformed token
	}))
	defer srv.Close()

	a, _ := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "id"})
	const n = 5
	for i := 0; i < n; i++ {
		// Distinct tokens so the (uncached) 4xx path is exercised each time and
		// this is purely a test of the provider-wide gate, not the token cache.
		if a.Verify("alice", fmt.Sprintf("malformed-%d", i)) {
			t.Fatalf("request %d: expected deny on a 400 introspection", i)
		}
	}
	if got := atomic.LoadInt32(&calls); got != n {
		t.Fatalf("IdP was called %d times, want %d — a 4xx armed the provider-wide cooldown (one malformed token gated everyone)", got, n)
	}
}

// ── Cache ─────────────────────────────────────────────────────────────────────

func TestOIDCAuth_Cache_HitAvoidsDial(t *testing.T) {
	allowLoopbackSSRF(t) // NewOIDCAuth installs the SSRF dial guard (RISK-002); permit the loopback test IdP
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(introspectionResponse{Active: true, Sub: "alice"}) //nolint:errcheck // test response writer
	}))
	defer srv.Close()

	a, _ := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "id"})

	a.Verify("alice", "tok")
	a.Verify("alice", "tok") // second call — should hit cache
	if callCount != 1 {
		t.Errorf("expected 1 IDP call (cache hit on second), got %d", callCount)
	}
}

func TestOIDCAuth_Cache_Expiry(t *testing.T) {
	allowLoopbackSSRF(t) // NewOIDCAuth installs the SSRF dial guard (RISK-002); permit the loopback test IdP
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(introspectionResponse{Active: true, Sub: "alice"}) //nolint:errcheck // test response writer
	}))
	defer srv.Close()

	a, _ := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: srv.URL,
		ClientID:         "id",
		CacheTTL:         1 * time.Millisecond,
	})

	a.Verify("alice", "tok")
	time.Sleep(5 * time.Millisecond)
	a.Verify("alice", "tok") // cache expired → second IDP call
	if callCount != 2 {
		t.Errorf("expected 2 IDP calls after TTL expiry, got %d", callCount)
	}
}

// ── audienceContains unit tests ───────────────────────────────────────────────

func TestAudienceContains(t *testing.T) {
	cases := []struct {
		aud  any
		want string
		ok   bool
	}{
		{"culvert", "culvert", true},
		{"other", "culvert", false},
		{[]any{"a", "culvert", "b"}, "culvert", true},
		{[]any{"a", "b"}, "culvert", false},
		{nil, "culvert", false},
		{42, "culvert", false},
	}
	for _, c := range cases {
		got := audienceContains(c.aud, c.want)
		if got != c.ok {
			t.Errorf("audienceContains(%v, %q) = %v, want %v", c.aud, c.want, got, c.ok)
		}
	}
}

// ── Basic Auth forwarded to IDP ───────────────────────────────────────────────

func TestOIDCAuth_Verify_SendsBasicAuth(t *testing.T) {
	allowLoopbackSSRF(t) // NewOIDCAuth installs the SSRF dial guard (RISK-002); permit the loopback test IdP
	var gotUser, gotPass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, _ = r.BasicAuth()
		json.NewEncoder(w).Encode(introspectionResponse{Active: true, Sub: "alice"}) //nolint:errcheck // test response writer
	}))
	defer srv.Close()

	a, _ := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: srv.URL,
		ClientID:         "my-client",
		ClientSecret:     "my-secret",
	})
	a.Verify("alice", "tok")

	if gotUser != "my-client" || gotPass != "my-secret" {
		t.Errorf("IDP received basic auth (%q,%q), want (my-client, my-secret)", gotUser, gotPass)
	}
}
