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

func TestAuthSAMLMetadataRequiresGET(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/saml/metadata", nil)
	w := httptest.NewRecorder()

	authSAMLMetadata(w, r)

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

func TestAuthSAMLMetadataRejectsUnstableNameIDFormats(t *testing.T) {
	metadata := mustBuildSAMLMetadata(t, "https://proxy.example/culvert")
	formats := metadata.SPSSODescriptors[0].NameIDFormats

	for _, format := range formats {
		if format == saml.TransientNameIDFormat || format == saml.UnspecifiedNameIDFormat {
			t.Fatalf("metadata advertised unstable NameIDFormat %q in %+v", format, formats)
		}
		if !isStableSAMLNameIDFormat(string(format)) {
			t.Fatalf("metadata advertised unsupported NameIDFormat %q in %+v", format, formats)
		}
	}
}

func TestAuthSAMLMetadataMatchesRuntimeAuthnRequestValues(t *testing.T) {
	baseURL := "https://proxy.example/culvert"
	metadata := mustBuildSAMLMetadata(t, baseURL)
	spDescriptor := metadata.SPSSODescriptors[0]
	if len(spDescriptor.AssertionConsumerServices) == 0 {
		t.Fatal("metadata missing AssertionConsumerService")
	}

	rootURL, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	runtimeSP := &saml.ServiceProvider{
		AuthnNameIDFormat: saml.PersistentNameIDFormat,
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: "https://idp.example/metadata",
			IDPSSODescriptors: []saml.IDPSSODescriptor{
				{
					SingleSignOnServices: []saml.Endpoint{
						{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example/sso"},
					},
				},
			},
		},
	}
	configureSAMLServiceProviderURLs(runtimeSP, rootURL)
	authReq, err := runtimeSP.MakeAuthenticationRequest(
		runtimeSP.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		t.Fatalf("MakeAuthenticationRequest: %v", err)
	}

	if authReq.Issuer == nil || authReq.Issuer.Value != metadata.EntityID {
		t.Fatalf("AuthnRequest issuer = %+v, want metadata EntityID %q", authReq.Issuer, metadata.EntityID)
	}
	if authReq.AssertionConsumerServiceURL != spDescriptor.AssertionConsumerServices[0].Location {
		t.Fatalf("AuthnRequest ACS = %q, want metadata ACS %q", authReq.AssertionConsumerServiceURL, spDescriptor.AssertionConsumerServices[0].Location)
	}
	if authReq.NameIDPolicy == nil || authReq.NameIDPolicy.Format == nil || *authReq.NameIDPolicy.Format != string(saml.PersistentNameIDFormat) {
		t.Fatalf("AuthnRequest NameIDPolicy = %+v, want persistent", authReq.NameIDPolicy)
	}
	if !samlMetadataFormatsContain(spDescriptor.NameIDFormats, saml.PersistentNameIDFormat) {
		t.Fatalf("metadata NameIDFormats = %+v, want persistent to match runtime profile request", spDescriptor.NameIDFormats)
	}
}

func mustBuildSAMLMetadata(t *testing.T, baseURL string) *saml.EntityDescriptor {
	t.Helper()
	origBaseURL := cfg.ProxyBaseURL()
	SetProxyBaseURL(baseURL)
	t.Cleanup(func() { SetProxyBaseURL(origBaseURL) })

	metadata, err := buildSAMLSPMetadata()
	if err != nil {
		t.Fatalf("build SAML metadata: %v", err)
	}
	if len(metadata.SPSSODescriptors) != 1 {
		t.Fatalf("SPSSODescriptors length = %d, want 1", len(metadata.SPSSODescriptors))
	}
	return metadata
}

func samlMetadataFormatsContain(formats []saml.NameIDFormat, want saml.NameIDFormat) bool {
	for _, format := range formats {
		if format == want {
			return true
		}
	}
	return false
}
