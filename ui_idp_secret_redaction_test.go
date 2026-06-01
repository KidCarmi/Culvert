package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestAPIIdPItemPut_PreservesOIDCClientSecretWhenRedactedFromForm(t *testing.T) {
	p := &IdPProfile{
		ID:           "oidc-preserve-id",
		Name:         "OIDC Preserve",
		Type:         IdPTypeOIDC,
		Enabled:      false,
		KnownGroups:  []string{"Engineering"},
		EmailDomains: []string{"example.com"},
		OIDC: &OIDCProfileConfig{
			Issuer:       "https://example.com",
			ClientID:     "client",
			ClientSecret: "existing-secret",
			Scopes:       []string{"openid", "email"},
			GroupsClaim:  "groups",
		},
	}
	orig := idpRegistry
	idpRegistry = &IdPRegistry{profiles: []*IdPProfile{p}, live: make(map[string]IdentityProvider)}
	t.Cleanup(func() { idpRegistry = orig })

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPut, "/api/idp/oidc-preserve-id", map[string]any{
		"name":         "Renamed OIDC Preserve",
		"type":         "oidc",
		"enabled":      false,
		"knownGroups":  []string{"Security"},
		"emailDomains": []string{"example.org"},
		"oidc": map[string]any{
			"issuer":      "https://example.com",
			"clientId":    "client",
			"scopes":      []string{"openid", "profile"},
			"groupsClaim": "roles",
		},
	})

	apiIdPItem(w, r, p.ID)

	if w.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	assertNoOIDCSecretLeak(t, w.Body.String())
	got := idpRegistry.Get(p.ID)
	if got == nil || got.OIDC == nil {
		t.Fatal("profile missing after update")
	}
	if got.Name != "Renamed OIDC Preserve" {
		t.Fatalf("profile name = %q, want update applied", got.Name)
	}
	if got.OIDC.ClientSecret != "existing-secret" {
		t.Fatalf("stored clientSecret = %q, want preserved existing secret", got.OIDC.ClientSecret)
	}
	if got.OIDC.GroupsClaim != "roles" || len(got.OIDC.Scopes) != 2 || got.OIDC.Scopes[1] != "profile" {
		t.Fatalf("OIDC non-secret settings = %+v, want update applied", got.OIDC)
	}
	if len(got.KnownGroups) != 1 || got.KnownGroups[0] != "Security" {
		t.Fatalf("known groups = %#v, want update applied", got.KnownGroups)
	}
}

func TestAPIIdPItemPut_MutatesOIDCClientSecretWhenProvided(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		submitted  string
		wantSecret string
	}{
		{name: "clear", id: "oidc-clear-id", submitted: "", wantSecret: ""},
		{name: "replace", id: "oidc-replace-id", submitted: "new-secret", wantSecret: "new-secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &IdPProfile{
				ID:      tt.id,
				Name:    "OIDC " + tt.name,
				Type:    IdPTypeOIDC,
				Enabled: false,
				OIDC: &OIDCProfileConfig{
					Issuer:       "https://example.com",
					ClientID:     "client",
					ClientSecret: "old-secret",
				},
			}
			orig := idpRegistry
			idpRegistry = &IdPRegistry{profiles: []*IdPProfile{p}, live: make(map[string]IdentityProvider)}
			t.Cleanup(func() { idpRegistry = orig })

			w := httptest.NewRecorder()
			r := jsonReq(http.MethodPut, "/api/idp/"+tt.id, map[string]any{
				"name":    p.Name,
				"type":    "oidc",
				"enabled": false,
				"oidc": map[string]any{
					"issuer":       "https://example.com",
					"clientId":     "client",
					"clientSecret": tt.submitted,
				},
			})

			apiIdPItem(w, r, p.ID)

			if w.Code != http.StatusOK {
				t.Fatalf("PUT status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			assertNoOIDCSecretLeak(t, w.Body.String())
			got := idpRegistry.Get(p.ID)
			if got == nil || got.OIDC == nil {
				t.Fatal("profile missing after update")
			}
			if got.OIDC.ClientSecret != tt.wantSecret {
				t.Fatalf("stored clientSecret = %q, want %q", got.OIDC.ClientSecret, tt.wantSecret)
			}
		})
	}
}

func TestStaticIdPModal_ClearsWriteOnlyFieldsOnlyWhenExplicitlyChecked(t *testing.T) {
	data, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	html := string(data)
	required := []string{
		`id="idp-clear-secret"`,
		`id="idp-clear-secret-wrap"`,
		`document.getElementById('idp-clear-secret').checked = false`,
		`(p && p.type === 'oidc') ? 'flex' : 'none'`,
		`const clearClientSecret = document.getElementById('idp-clear-secret').checked`,
		`if (clearClientSecret) body.oidc.clientSecret = '';`,
		`else if (clientSecret) body.oidc.clientSecret = clientSecret;`,
		`id="idp-clear-metadata-xml"`,
		`id="idp-clear-metadata-xml-wrap"`,
		`id="idp-meta-xml-upload-label"`,
		`data-input="syncSAMLMetadataSourceChoice"`,
		`data-change="syncSAMLMetadataSourceChoice"`,
		`document.getElementById('idp-clear-metadata-xml').checked = false`,
		`(p && p.type === 'saml') ? 'flex' : 'none'`,
		`syncSAMLMetadataSourceChoice();`,
		`function syncSAMLMetadataSourceChoice()`,
		`const metadataUrl = document.getElementById('idp-meta-url').value.trim();`,
		`if (!metadataUrl) {`,
		`const clearMetadataXml = document.getElementById('idp-clear-metadata-xml').checked`,
		`if (clearMetadataXml) body.saml.metadataXml = '';`,
		`else if (metadataXml) body.saml.metadataXml = metadataXml;`,
	}
	for _, want := range required {
		if !strings.Contains(html, want) {
			t.Fatalf("static/index.html missing %q", want)
		}
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

func assertNoOIDCSecretLeak(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, "existing-secret") ||
		strings.Contains(body, "old-secret") ||
		strings.Contains(body, "new-secret") {
		t.Fatalf("response leaked OIDC client secret: %s", body)
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
