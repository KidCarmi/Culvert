package main

import (
	"bytes"
	"encoding/xml"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"
)

func TestAuthSAMLCallbackLogsProviderRejection(t *testing.T) {
	origRegistry := idpRegistry
	origLogger := logger
	var logs bytes.Buffer
	logger = log.New(&logs, "", 0)
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{
			{ID: "corp-saml", Type: IdPTypeSAML, Enabled: true},
		},
		live: map[string]IdentityProvider{
			"corp-saml": &SAMLProvider{profile: &IdPProfile{ID: "corp-saml", Type: IdPTypeSAML}},
		},
	}
	t.Cleanup(func() {
		idpRegistry = origRegistry
		logger = origLogger
	})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/saml/callback", strings.NewReader(url.Values{
		"RelayState":   {"missing"},
		"SAMLResponse": {"not-base64"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	authSAMLCallback(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	got := logs.String()
	if !strings.Contains(got, `SAML callback rejected by provider="corp-saml"`) {
		t.Fatalf("logs missing provider rejection: %q", got)
	}
	if !strings.Contains(got, "saml callback: invalid or expired state") {
		t.Fatalf("logs missing rejection reason: %q", got)
	}
}

func TestAuthSAMLCallbackRequiresPOST(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/saml/callback", nil)
	w := httptest.NewRecorder()

	authSAMLCallback(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestAuthSAMLMetadataPublishesConfiguredSPValues(t *testing.T) {
	origBaseURL := cfg.ProxyBaseURL()
	SetProxyBaseURL("https://proxy.example/culvert")
	t.Cleanup(func() { SetProxyBaseURL(origBaseURL) })

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/saml/metadata", nil)
	w := httptest.NewRecorder()

	authSAMLMetadata(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/samlmetadata+xml") {
		t.Fatalf("Content-Type = %q, want SAML metadata XML", got)
	}
	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("metadata XML parse: %v", err)
	}
	if metadata.EntityID != "https://proxy.example/culvert" {
		t.Fatalf("EntityID = %q, want configured base URL", metadata.EntityID)
	}
	if len(metadata.SPSSODescriptors) != 1 {
		t.Fatalf("SPSSODescriptors length = %d, want 1", len(metadata.SPSSODescriptors))
	}
	acs := metadata.SPSSODescriptors[0].AssertionConsumerServices
	if len(acs) == 0 || acs[0].Location != "https://proxy.example/culvert/auth/saml/callback" {
		t.Fatalf("ACS endpoints = %+v, want path-prefixed callback", acs)
	}
	formats := metadata.SPSSODescriptors[0].NameIDFormats
	if len(formats) != 2 {
		t.Fatalf("NameIDFormats = %+v, want emailAddress and persistent", formats)
	}
	if formats[0] != saml.EmailAddressNameIDFormat || formats[1] != saml.PersistentNameIDFormat {
		t.Fatalf("NameIDFormats = %+v, want emailAddress and persistent", formats)
	}
}
