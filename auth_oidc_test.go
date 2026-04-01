package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(introspectionResponse{Active: true, Scope: "openid proxy:access email"}) //nolint:errcheck
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(introspectionResponse{Active: true, Scope: "openid email"}) //nolint:errcheck
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return audience as a plain string.
		raw := `{"active":true,"aud":"culvert"}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(raw)) //nolint:errcheck
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := `{"active":true,"aud":["other","culvert"]}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(raw)) //nolint:errcheck
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := `{"active":true,"aud":"other-service"}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(raw)) //nolint:errcheck
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	a, _ := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "id"})
	if a.Verify("alice", "tok") {
		t.Error("expected Verify=false when IDP returns 500")
	}
}

// ── Cache ─────────────────────────────────────────────────────────────────────

func TestOIDCAuth_Cache_HitAvoidsDial(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(introspectionResponse{Active: true}) //nolint:errcheck
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
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(introspectionResponse{Active: true}) //nolint:errcheck
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
	var gotUser, gotPass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, _ = r.BasicAuth()
		json.NewEncoder(w).Encode(introspectionResponse{Active: true}) //nolint:errcheck
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
