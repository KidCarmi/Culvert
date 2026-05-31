package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIIdPList_PostRejectsInvalidSAMLConfig(t *testing.T) {
	withTestIdPRegistry(t)

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/idp", map[string]any{
		"name":    "bad-saml",
		"type":    "saml",
		"enabled": false,
		"saml":    map[string]any{},
	})

	apiIdPList(w, r)

	assertStatus(t, w, http.StatusBadRequest)
	if !strings.Contains(w.Body.String(), "exactly one") {
		t.Fatalf("response = %q, want exactly-one metadata validation", w.Body.String())
	}
	if got := idpRegistry.All(); len(got) != 0 {
		t.Fatalf("registry has %d profiles after rejected create, want 0", len(got))
	}
}

func TestAPIIdPItem_PutRejectsBadSAMLConfigWithoutReplacingProfile(t *testing.T) {
	withTestIdPRegistry(t)
	original := samlProfile("api-stable-id", "Working API Profile")
	if err := idpRegistry.Upsert(original); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	largeBadMetadata := "<not-saml-metadata>" + strings.Repeat("x", 4096)
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPut, "/api/idp/api-stable-id", map[string]any{
		"name":    "Broken API Profile",
		"type":    "saml",
		"enabled": true,
		"saml": map[string]any{
			"metadataXml": largeBadMetadata,
		},
	})

	apiIdPItem(w, r, "api-stable-id")

	assertStatus(t, w, http.StatusBadRequest)
	if strings.Contains(w.Body.String(), strings.Repeat("x", 256)) {
		t.Fatalf("response echoed a large metadata blob: %q", w.Body.String())
	}
	got := idpRegistry.Get("api-stable-id")
	if got == nil {
		t.Fatal("original profile disappeared after rejected update")
	}
	if got.Name != "Working API Profile" || got.Enabled {
		t.Fatalf("profile after rejected update = %+v, want original disabled profile", got)
	}
}

func TestAPIIdPItem_PutPreservesInlineSAMLMetadataWhenRedactedFromForm(t *testing.T) {
	withTestIdPRegistry(t)
	original := samlProfile("api-inline-id", "Inline Metadata Profile")
	original.SAML.MetadataXML = "<EntityDescriptor>preserve-inline-metadata</EntityDescriptor>"
	if err := idpRegistry.Upsert(original); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPut, "/api/idp/api-inline-id", map[string]any{
		"name":         "Renamed Inline Metadata Profile",
		"type":         "saml",
		"enabled":      false,
		"knownGroups":  []string{"Engineering"},
		"emailDomains": []string{"example.com"},
		"saml": map[string]any{
			"metadataUrl":     "",
			"metadataXml":     "",
			"nameIdFormat":    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
			"groupsAttribute": "memberOf",
			"emailAttribute":  "mail",
			"nameAttribute":   "displayName",
		},
	})

	apiIdPItem(w, r, "api-inline-id")

	assertStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), "preserve-inline-metadata") || strings.Contains(w.Body.String(), "metadataXml") {
		t.Fatalf("response leaked preserved metadata XML: %q", w.Body.String())
	}
	got := idpRegistry.Get("api-inline-id")
	if got == nil || got.SAML == nil {
		t.Fatal("profile missing after update")
	}
	if got.Name != "Renamed Inline Metadata Profile" {
		t.Fatalf("profile name = %q, want update applied", got.Name)
	}
	if got.SAML.MetadataXML != "<EntityDescriptor>preserve-inline-metadata</EntityDescriptor>" {
		t.Fatalf("stored metadataXml = %q, want preserved inline metadata", got.SAML.MetadataXML)
	}
	if got.SAML.MetadataURL != "" {
		t.Fatalf("stored metadataUrl = %q, want empty", got.SAML.MetadataURL)
	}
	if got.SAML.NameIDFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" {
		t.Fatalf("stored nameIdFormat = %q, want updated value", got.SAML.NameIDFormat)
	}
}

func withTestIdPRegistry(t *testing.T) {
	t.Helper()
	orig := idpRegistry
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}
	t.Cleanup(func() {
		idpRegistry = orig
	})
}
