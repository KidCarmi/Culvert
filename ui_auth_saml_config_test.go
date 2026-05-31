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

func withTestIdPRegistry(t *testing.T) {
	t.Helper()
	orig := idpRegistry
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}
	t.Cleanup(func() {
		idpRegistry = orig
	})
}
