package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
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

func TestAPIIdPListGet_RedactsClientSecret(t *testing.T) {
	p := &IdPProfile{
		ID:      "redact-list-id",
		Name:    "Redact LIST",
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
	r := adminCtx(httptest.NewRequest(http.MethodGet, "/api/idp", http.NoBody))
	apiIdPList(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	assertNoOIDCSecretLeak(t, w.Body.String())
	var env struct {
		Persisted bool         `json:"persisted"`
		Profiles  []IdPProfile `json:"profiles"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if env.Persisted {
		t.Fatal("persisted = true, want false for path-less registry")
	}
	got := env.Profiles
	if len(got) != 1 {
		t.Fatalf("list length = %d, want 1", len(got))
	}
	if got[0].OIDC == nil {
		t.Fatal("OIDC config missing from response")
	}
	if got[0].OIDC.ClientSecret != "" {
		t.Fatalf("response leaked clientSecret %q", got[0].OIDC.ClientSecret)
	}
}

func TestAPIIdPListPost_StoresAndRedactsClientSecret(t *testing.T) {
	orig := idpRegistry
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}
	t.Cleanup(func() { idpRegistry = orig })

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/idp", map[string]any{
		"name":    "OIDC Create",
		"type":    "oidc",
		"enabled": false,
		"oidc": map[string]any{
			"issuer":       "https://example.com",
			"clientId":     "client",
			"clientSecret": "created-secret",
		},
	})

	apiIdPList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	assertNoOIDCSecretLeak(t, w.Body.String())
	var got IdPProfile
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.ID == "" {
		t.Fatal("response ID is empty")
	}
	if got.OIDC == nil {
		t.Fatal("OIDC config missing from response")
	}
	if got.OIDC.ClientSecret != "" {
		t.Fatalf("response clientSecret = %q, want redacted", got.OIDC.ClientSecret)
	}
	stored := idpRegistry.Get(got.ID)
	if stored == nil || stored.OIDC == nil {
		t.Fatal("stored profile missing after create")
	}
	if stored.OIDC.ClientSecret != "created-secret" {
		t.Fatalf("stored clientSecret = %q, want created secret", stored.OIDC.ClientSecret)
	}
}

func TestAPIIdPAudit_RedactsWriteOnlyFields(t *testing.T) {
	origRegistry := idpRegistry
	restoreAudit := audit.SwapRingForTest()
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}
	t.Cleanup(func() {
		idpRegistry = origRegistry
		restoreAudit()
	})

	createW := httptest.NewRecorder()
	createR := jsonReq(http.MethodPost, "/api/idp", map[string]any{
		"name":    "OIDC Audit Create",
		"type":    "oidc",
		"enabled": false,
		"oidc": map[string]any{
			"issuer":       "https://example.com",
			"clientId":     "client",
			"clientSecret": "created-secret",
		},
	})
	apiIdPList(createW, createR)
	if createW.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want 200; body=%s", createW.Code, createW.Body.String())
	}
	assertAuditNoWriteOnlyIdPFields(t, latestAuditEntry(t, "idp.create"))

	oidc := idpRegistry.Get(decodeIdPResponseID(t, createW.Body.Bytes()))
	if oidc == nil || oidc.OIDC == nil {
		t.Fatal("created OIDC profile missing")
	}
	updateW := httptest.NewRecorder()
	updateR := jsonReq(http.MethodPut, "/api/idp/"+oidc.ID, map[string]any{
		"name":    "OIDC Audit Update",
		"type":    "oidc",
		"enabled": false,
		"oidc": map[string]any{
			"issuer":       "https://example.com",
			"clientId":     "client",
			"clientSecret": "new-secret",
		},
	})
	apiIdPItem(updateW, updateR, oidc.ID)
	if updateW.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200; body=%s", updateW.Code, updateW.Body.String())
	}
	assertAuditNoWriteOnlyIdPFields(t, latestAuditEntry(t, "idp.update"))

	saml := &IdPProfile{
		ID:      "saml-audit-delete-id",
		Name:    "SAML Audit Delete",
		Type:    IdPTypeSAML,
		Enabled: false,
		SAML: &SAMLProfileConfig{
			MetadataXML:  "<EntityDescriptor>inline-metadata</EntityDescriptor>",
			NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		},
	}
	idpRegistry.profiles = append(idpRegistry.profiles, saml)
	deleteW := httptest.NewRecorder()
	deleteR := adminCtx(httptest.NewRequest(http.MethodDelete, "/api/idp/"+saml.ID, http.NoBody))
	apiIdPItem(deleteW, deleteR, saml.ID)
	if deleteW.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204; body=%s", deleteW.Code, deleteW.Body.String())
	}
	assertAuditNoWriteOnlyIdPFields(t, latestAuditEntry(t, "idp.delete"))
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

func TestAPIIdPItemPut_PreservesOIDCDiscoveryEndpointsWhenIssuerUnchanged(t *testing.T) {
	p := oidcDiscoveryCacheProfile()
	orig := idpRegistry
	idpRegistry = &IdPRegistry{profiles: []*IdPProfile{p}, live: make(map[string]IdentityProvider)}
	t.Cleanup(func() { idpRegistry = orig })

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPut, "/api/idp/"+p.ID, map[string]any{
		"name":    p.Name,
		"type":    "oidc",
		"enabled": false,
		"oidc": map[string]any{
			"issuer":   "https://example.com",
			"clientId": "client",
		},
	})

	apiIdPItem(w, r, p.ID)

	if w.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	got := idpRegistry.Get(p.ID)
	if got == nil || got.OIDC == nil {
		t.Fatal("profile missing after update")
	}
	assertOIDCDiscoveryEndpoints(t, got.OIDC)
}

func TestPreserveOIDCDiscoveryEndpoints_SkipsWhenIssuerChanges(t *testing.T) {
	before := oidcDiscoveryCacheProfile()
	next := &IdPProfile{
		Type: IdPTypeOIDC,
		OIDC: &OIDCProfileConfig{
			Issuer:   "https://other.example.com",
			ClientID: "client",
		},
	}

	preserveOIDCDiscoveryEndpoints(before, next)

	assertNoOIDCDiscoveryEndpoints(t, next.OIDC)
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

func assertOIDCDiscoveryEndpoints(t *testing.T, got *OIDCProfileConfig) {
	t.Helper()
	if got.AuthorizationEndpoint != "https://example.com/auth" ||
		got.TokenEndpoint != "https://example.com/token" ||
		got.IntrospectionEndpoint != "https://example.com/introspect" ||
		got.UserinfoEndpoint != "https://example.com/userinfo" ||
		got.JWKsURI != "https://example.com/jwks" {
		t.Fatalf("discovery endpoints = %+v, want preserved", got)
	}
}

func assertNoOIDCDiscoveryEndpoints(t *testing.T, got *OIDCProfileConfig) {
	t.Helper()
	if got.AuthorizationEndpoint != "" || got.TokenEndpoint != "" ||
		got.IntrospectionEndpoint != "" || got.UserinfoEndpoint != "" || got.JWKsURI != "" {
		t.Fatalf("discovery endpoints = %+v, want empty", got)
	}
}

func oidcDiscoveryCacheProfile() *IdPProfile {
	return &IdPProfile{
		ID:      "oidc-discovery-cache-id",
		Name:    "OIDC Discovery Cache",
		Type:    IdPTypeOIDC,
		Enabled: false,
		OIDC: &OIDCProfileConfig{
			Issuer:                "https://example.com",
			ClientID:              "client",
			AuthorizationEndpoint: "https://example.com/auth",
			TokenEndpoint:         "https://example.com/token",
			IntrospectionEndpoint: "https://example.com/introspect",
			UserinfoEndpoint:      "https://example.com/userinfo",
			JWKsURI:               "https://example.com/jwks",
		},
	}
}

func TestStaticIdPModal_ClearsWriteOnlyFieldsOnlyWhenExplicitlyChecked(t *testing.T) {
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	html := string(data)
	required := []string{
		`id="idp-clear-secret"`,
		`id="idp-clear-secret-wrap"`,
		`id="idp-oidc-required-scope"`,
		`id="idp-oidc-required-audience"`,
		`id="idp-oidc-tls-skip"`,
		`document.getElementById('idp-clear-secret').checked = false`,
		`(p && p.type === 'oidc') ? 'flex' : 'none'`,
		`const clearClientSecret = document.getElementById('idp-clear-secret').checked`,
		`if (clearClientSecret) body.oidc.clientSecret = '';`,
		`else if (clientSecret) body.oidc.clientSecret = clientSecret;`,
		`document.getElementById('idp-oidc-required-scope').value = oidc.requiredScope || '';`,
		`document.getElementById('idp-oidc-required-audience').value = oidc.requiredAudience || '';`,
		`document.getElementById('idp-oidc-tls-skip').value = oidc.tlsSkipVerify ? 'true' : '';`,
		`'idp-oidc-required-scope','idp-oidc-required-audience','idp-oidc-tls-skip'`,
		`requiredScope: document.getElementById('idp-oidc-required-scope').value.trim(),`,
		`requiredAudience: document.getElementById('idp-oidc-required-audience').value.trim(),`,
		`tlsSkipVerify: document.getElementById('idp-oidc-tls-skip').value === 'true',`,
		`id="idp-clear-metadata-xml"`,
		`id="idp-clear-metadata-xml-wrap"`,
		`id="idp-meta-xml-upload-label"`,
		`id="idp-saml-nameid-format"`,
		`id="idp-saml-name-attr"`,
		`data-input="syncSAMLMetadataSourceChoice"`,
		`data-change="syncSAMLMetadataSourceChoice"`,
		`document.getElementById('idp-clear-metadata-xml').checked = false`,
		`(p && p.type === 'saml' && p.saml && !p.saml.metadataUrl) ? 'flex' : 'none'`,
		`Saved inline XML configured`,
		`p.type === 'saml' && !saml.metadataUrl`,
		`document.getElementById('idp-saml-nameid-format').value = saml.nameIdFormat || '';`,
		`document.getElementById('idp-saml-name-attr').value = saml.nameAttribute || '';`,
		`'idp-saml-nameid-format','idp-saml-name-attr'`,
		`nameIdFormat:    document.getElementById('idp-saml-nameid-format').value.trim(),`,
		`nameAttribute:   document.getElementById('idp-saml-name-attr').value.trim(),`,
		`syncSAMLMetadataSourceChoice();`,
		`function syncSAMLMetadataSourceChoice()`,
		`const metadataUrl = document.getElementById('idp-meta-url').value.trim();`,
		`if (!metadataUrl) {`,
		`const clearMetadataXml = document.getElementById('idp-clear-metadata-xml').checked`,
		`if (metadataXml) body.saml.metadataXml = metadataXml;`,
		`else if (clearMetadataXml) {`,
		`Provide a metadata URL or upload/paste new metadata XML before clearing saved inline XML`,
	}
	for _, want := range required {
		if !strings.Contains(html, want) {
			t.Fatalf("static/index.html missing %q", want)
		}
	}
}

func TestStaticIdPList_UsesRedactedSafeSAMLInlineMetadataIndicator(t *testing.T) {
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, `p.type === 'saml' && p.saml && !p.saml.metadataUrl`) {
		t.Fatal("SAML inline metadata indicator must not depend on redacted metadataXml")
	}
	if strings.Contains(html, `p.type === 'saml' && p.saml && p.saml.metadataXml`) {
		t.Fatal("SAML inline metadata indicator still depends on redacted metadataXml")
	}
	if strings.Contains(html, `(p && p.type === 'saml') ? 'flex' : 'none'`) {
		t.Fatal("SAML metadata clear control is shown for non-inline SAML profiles")
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
	if strings.Contains(body, "super-secret") ||
		strings.Contains(body, "created-secret") ||
		strings.Contains(body, "existing-secret") ||
		strings.Contains(body, "old-secret") ||
		strings.Contains(body, "new-secret") {
		t.Fatalf("response leaked OIDC client secret: %s", body)
	}
}

func decodeIdPResponseID(t *testing.T, body []byte) string {
	t.Helper()
	var got IdPProfile
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode IdP response: %v", err)
	}
	if got.ID == "" {
		t.Fatal("IdP response ID is empty")
	}
	return got.ID
}

func latestAuditEntry(t *testing.T, action string) AuditEntry {
	t.Helper()
	for _, entry := range auditGet() {
		if entry.Action == action {
			return entry
		}
	}
	t.Fatalf("audit entry %q not found", action)
	return AuditEntry{}
}

func assertAuditNoWriteOnlyIdPFields(t *testing.T, entry AuditEntry) {
	t.Helper()
	body := entry.Before + entry.After
	if strings.Contains(body, "created-secret") ||
		strings.Contains(body, "new-secret") ||
		strings.Contains(body, "inline-metadata") ||
		strings.Contains(body, "metadataXml") {
		t.Fatalf("audit entry leaked write-only IdP field: %+v", entry)
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
	var listEnv struct {
		Profiles []IdPProfile `json:"profiles"`
	}
	if err := json.Unmarshal(listW.Body.Bytes(), &listEnv); err != nil {
		t.Fatalf("decode LIST response: %v", err)
	}
	if len(listEnv.Profiles) != 1 {
		t.Fatalf("list length = %d, want 1", len(listEnv.Profiles))
	}
	assertPublicSAMLProfile(t, listEnv.Profiles[0])
}

func assertNoSAMLMetadataLeak(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, "uploaded-secret-metadata") ||
		strings.Contains(body, "preserve-inline-metadata") ||
		strings.Contains(body, "old-inline-metadata") ||
		strings.Contains(body, "keep-inline-metadata") ||
		strings.Contains(body, "new-inline-metadata") ||
		strings.Contains(body, "inline-metadata") ||
		strings.Contains(body, "metadataXml") {
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
