package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublicIdPProfile_RedactsClientSecret(t *testing.T) {
	p := &IdPProfile{
		ID:      "redact-id",
		Name:    "Redact",
		Type:    IdPTypeOIDC,
		Enabled: false,
		OIDC: &OIDCProfileConfig{
			Issuer:       "https://idp.example.com",
			ClientID:     "client",
			ClientSecret: "super-secret",
			Scopes:       []string{"openid", "groups"},
		},
	}

	got := publicIdPProfile(p)
	if got.OIDC == nil {
		t.Fatal("OIDC config missing from public profile")
	}
	if got.OIDC.ClientSecret != "" {
		t.Fatalf("public client secret = %q, want empty", got.OIDC.ClientSecret)
	}
	if p.OIDC.ClientSecret != "super-secret" {
		t.Fatalf("source profile was mutated; secret = %q", p.OIDC.ClientSecret)
	}
}

func TestAPIIdPItemGet_RedactsClientSecret(t *testing.T) {
	p := &IdPProfile{
		ID:      "redact-get-id",
		Name:    "Redact GET",
		Type:    IdPTypeOIDC,
		Enabled: false,
		OIDC: &OIDCProfileConfig{
			Issuer:       "https://idp.example.com",
			ClientID:     "client",
			ClientSecret: "super-secret",
		},
	}
	orig := idpRegistry
	idpRegistry = &IdPRegistry{profiles: []*IdPProfile{p}, live: make(map[string]IdentityProvider)}
	t.Cleanup(func() { idpRegistry = orig })

	w := httptest.NewRecorder()
	r := adminCtx(httptest.NewRequest(http.MethodGet, "/api/idp/redact-get-id", http.NoBody))
	apiIdPItem(w, r, p.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got IdPProfile
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.OIDC == nil {
		t.Fatal("OIDC config missing from response")
	}
	if got.OIDC.ClientSecret != "" {
		t.Fatalf("response leaked clientSecret %q", got.OIDC.ClientSecret)
	}
}
