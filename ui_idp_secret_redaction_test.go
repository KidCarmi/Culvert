package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestPublicIdPProfile_RedactsSAMLMetadataXML(t *testing.T) {
	p := &IdPProfile{
		ID:           "saml-redact-id",
		Name:         "SAML Redact",
		Type:         IdPTypeSAML,
		Enabled:      true,
		KnownGroups:  []string{"Engineering", "Security"},
		EmailDomains: []string{"example.com"},
		SAML: &SAMLProfileConfig{
			MetadataURL:     "https://idp.example.com/metadata",
			MetadataXML:     "<EntityDescriptor>uploaded-secret-metadata</EntityDescriptor>",
			NameIDFormat:    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
			GroupsAttribute: "memberOf",
			EmailAttribute:  "mail",
			NameAttribute:   "displayName",
		},
	}

	got := publicIdPProfile(p)
	if got.SAML == nil {
		t.Fatal("SAML config missing from public profile")
	}
	if got.SAML.MetadataXML != "" {
		t.Fatalf("public metadataXml = %q, want empty", got.SAML.MetadataXML)
	}
	if p.SAML.MetadataXML == "" {
		t.Fatal("source profile was mutated; metadataXml was cleared")
	}
	if got.SAML.MetadataURL != p.SAML.MetadataURL ||
		got.SAML.NameIDFormat != p.SAML.NameIDFormat ||
		got.SAML.GroupsAttribute != p.SAML.GroupsAttribute ||
		got.SAML.EmailAttribute != p.SAML.EmailAttribute ||
		got.SAML.NameAttribute != p.SAML.NameAttribute {
		t.Fatalf("public SAML settings = %+v, want non-secret settings preserved", got.SAML)
	}
	if len(got.KnownGroups) != 2 || got.KnownGroups[0] != "Engineering" || got.KnownGroups[1] != "Security" {
		t.Fatalf("known groups = %#v, want preserved", got.KnownGroups)
	}
}

func TestAPIIdPGetAndList_RedactSAMLMetadataXML(t *testing.T) {
	p := &IdPProfile{
		ID:           "saml-redact-get-id",
		Name:         "SAML Redact GET",
		Type:         IdPTypeSAML,
		Enabled:      false,
		KnownGroups:  []string{"Engineering"},
		EmailDomains: []string{"example.com"},
		SAML: &SAMLProfileConfig{
			MetadataURL:     "https://idp.example.com/metadata",
			MetadataXML:     "<EntityDescriptor>uploaded-secret-metadata</EntityDescriptor>",
			NameIDFormat:    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
			GroupsAttribute: "memberOf",
			EmailAttribute:  "mail",
			NameAttribute:   "displayName",
		},
	}
	orig := idpRegistry
	idpRegistry = &IdPRegistry{profiles: []*IdPProfile{p}, live: make(map[string]IdentityProvider)}
	t.Cleanup(func() { idpRegistry = orig })

	getW := httptest.NewRecorder()
	getR := adminCtx(httptest.NewRequest(http.MethodGet, "/api/idp/saml-redact-get-id", http.NoBody))
	apiIdPItem(getW, getR, p.ID)
	if getW.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200; body=%s", getW.Code, getW.Body.String())
	}
	assertNoSAMLMetadataLeak(t, getW.Body.String())
	var got IdPProfile
	if err := json.Unmarshal(getW.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	assertPublicSAMLProfile(t, got)

	listW := httptest.NewRecorder()
	listR := adminCtx(httptest.NewRequest(http.MethodGet, "/api/idp", http.NoBody))
	apiIdPList(listW, listR)
	if listW.Code != http.StatusOK {
		t.Fatalf("LIST status = %d, want 200; body=%s", listW.Code, listW.Body.String())
	}
	assertNoSAMLMetadataLeak(t, listW.Body.String())
	var list []IdPProfile
	if err := json.Unmarshal(listW.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode LIST response: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list length = %d, want 1", len(list))
	}
	assertPublicSAMLProfile(t, list[0])
}

func assertNoSAMLMetadataLeak(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, "uploaded-secret-metadata") || strings.Contains(body, "metadataXml") {
		t.Fatalf("response leaked SAML metadata XML: %s", body)
	}
}

func assertPublicSAMLProfile(t *testing.T, got IdPProfile) {
	t.Helper()
	if got.SAML == nil {
		t.Fatal("SAML config missing from response")
	}
	if got.SAML.MetadataXML != "" {
		t.Fatalf("response leaked metadataXml %q", got.SAML.MetadataXML)
	}
	if got.SAML.MetadataURL != "https://idp.example.com/metadata" {
		t.Fatalf("metadataUrl = %q, want preserved", got.SAML.MetadataURL)
	}
	if got.SAML.NameIDFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" {
		t.Fatalf("nameIdFormat = %q, want preserved", got.SAML.NameIDFormat)
	}
	if got.SAML.GroupsAttribute != "memberOf" || got.SAML.EmailAttribute != "mail" || got.SAML.NameAttribute != "displayName" {
		t.Fatalf("SAML attribute mappings = %+v, want preserved", got.SAML)
	}
	if len(got.KnownGroups) != 1 || got.KnownGroups[0] != "Engineering" {
		t.Fatalf("known groups = %#v, want preserved", got.KnownGroups)
	}
}
