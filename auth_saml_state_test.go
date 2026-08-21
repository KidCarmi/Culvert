package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"

	"github.com/KidCarmi/Culvert/internal/authstate"
)

func resetSAMLStateStore(t *testing.T) {
	t.Helper()
	orig := globalSAMLStateStore
	globalSAMLStateStore = newSAMLStateStore()
	t.Cleanup(func() {
		globalSAMLStateStore = orig
	})
}

// resetSAMLStateStoreAt swaps in a store whose clock is pinned to `now`, so a
// test can place an entry outside the TTL without sleeping. The store owns
// entry creation time (internal/authstate), so this is how expiry is driven.
func resetSAMLStateStoreAt(t *testing.T, now func() time.Time) {
	t.Helper()
	orig := globalSAMLStateStore
	globalSAMLStateStore = authstate.NewWithClock[*samlStateEntry](samlStateTTL, samlStateStoreMax, now)
	t.Cleanup(func() {
		globalSAMLStateStore = orig
	})
}

func testSAMLRedirectProvider(t *testing.T) *SAMLProvider {
	t.Helper()
	metadataURL, err := url.Parse("https://proxy.example/saml/metadata")
	if err != nil {
		t.Fatalf("metadata URL parse: %v", err)
	}
	acsURL, err := url.Parse("https://proxy.example/auth/saml/callback")
	if err != nil {
		t.Fatalf("ACS URL parse: %v", err)
	}
	return &SAMLProvider{
		profile: &IdPProfile{ID: "corp-saml", Type: IdPTypeSAML},
		cfg:     &SAMLProfileConfig{},
		sp: &saml.ServiceProvider{
			MetadataURL:       *metadataURL,
			AcsURL:            *acsURL,
			AuthnNameIDFormat: saml.EmailAddressNameIDFormat,
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
		},
	}
}

func TestConfigureSAMLServiceProviderURLsMatchesRegisteredCallback(t *testing.T) {
	tests := []struct {
		name       string
		rootURL    string
		wantEntity string
		wantACS    string
	}{
		{
			name:       "root base URL",
			rootURL:    "https://proxy.example",
			wantEntity: "https://proxy.example",
			wantACS:    "https://proxy.example/auth/saml/callback",
		},
		{
			name:       "path prefixed base URL",
			rootURL:    "https://proxy.example/culvert",
			wantEntity: "https://proxy.example/culvert",
			wantACS:    "https://proxy.example/culvert/auth/saml/callback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootURL, err := url.Parse(tt.rootURL)
			if err != nil {
				t.Fatalf("root URL parse: %v", err)
			}
			sp := &saml.ServiceProvider{}

			configureSAMLServiceProviderURLs(sp, rootURL)

			if sp.EntityID != tt.wantEntity {
				t.Fatalf("EntityID = %q, want %q", sp.EntityID, tt.wantEntity)
			}
			if got := sp.AcsURL.String(); got != tt.wantACS {
				t.Fatalf("AcsURL = %q, want %q", got, tt.wantACS)
			}
		})
	}
}

func TestSAMLValidationErrorIncludesPrivateCause(t *testing.T) {
	err := samlValidationError(&saml.InvalidResponseError{
		PrivateErr: errors.New("audience does not match service provider"),
	})

	if !strings.Contains(err.Error(), "audience does not match service provider") {
		t.Fatalf("error %q missing private validation cause", err)
	}
	var invalid *saml.InvalidResponseError
	if !errors.As(err, &invalid) {
		t.Fatalf("error chain should preserve InvalidResponseError, got %T", err)
	}
}

func TestSAMLCaptiveLoginURLStoresRequestIDInRelayState(t *testing.T) {
	resetSAMLStateStore(t)
	prov := testSAMLRedirectProvider(t)
	relayURL := "https://app.example/protected"

	loginURL := prov.CaptiveLoginURL(relayURL, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if loginURL == "" {
		t.Fatal("CaptiveLoginURL returned empty URL")
	}
	u, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("login URL parse: %v", err)
	}
	if u.Host != "idp.example" {
		t.Fatalf("login URL host = %q, want idp.example", u.Host)
	}
	state := u.Query().Get("RelayState")
	if state == "" {
		t.Fatal("RelayState was not set")
	}
	if state == relayURL {
		t.Fatal("RelayState should be an opaque state handle, not the raw relay URL")
	}

	entry, ok := globalSAMLStateStore.Peek(state)
	if !ok {
		t.Fatal("RelayState did not map to a stored SAML request")
	}
	if entry.providerID != "corp-saml" {
		t.Fatalf("providerID = %q, want corp-saml", entry.providerID)
	}
	if entry.relayURL != relayURL {
		t.Fatalf("relayURL = %q, want %q", entry.relayURL, relayURL)
	}
	if entry.requestID == "" {
		t.Fatal("requestID was not stored")
	}
}

func TestSAMLExchangeAssertionRequiresKnownState(t *testing.T) {
	resetSAMLStateStore(t)
	prov := testSAMLRedirectProvider(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/saml/callback", strings.NewReader(url.Values{
		"RelayState":   {"missing"},
		"SAMLResponse": {"not-base64"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	id, relay, err := prov.ExchangeAssertion(r)
	if err == nil {
		t.Fatal("expected missing SAML state to fail")
	}
	if id != nil || relay != "" {
		t.Fatalf("got id=%+v relay=%q, want no identity or relay on failure", id, relay)
	}
}

func TestSAMLExchangeAssertionRejectsExpiredState(t *testing.T) {
	clock := time.Now().Add(-samlStateTTL - time.Minute)
	resetSAMLStateStoreAt(t, func() time.Time { return clock })
	globalSAMLStateStore.Set("expired-state", "203.0.113.5", &samlStateEntry{
		requestID:  "request-a",
		relayURL:   "https://app.example/",
		providerID: "corp-saml",
	})
	// Advance past the TTL: the entry above is now expired.
	clock = time.Now()
	prov := testSAMLRedirectProvider(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/saml/callback", strings.NewReader(url.Values{
		"RelayState":   {"expired-state"},
		"SAMLResponse": {"not-base64"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	id, relay, err := prov.ExchangeAssertion(r)
	if err == nil {
		t.Fatal("expected expired SAML state to fail")
	}
	if id != nil || relay != "" {
		t.Fatalf("got id=%+v relay=%q, want no identity or relay on expired state", id, relay)
	}
	if _, ok := globalSAMLStateStore.Peek("expired-state"); ok {
		t.Fatal("expired state should be removed")
	}
}

func TestSAMLExchangeAssertionProviderMismatchDoesNotConsumeState(t *testing.T) {
	resetSAMLStateStore(t)
	globalSAMLStateStore.Set("state-a", "203.0.113.5", &samlStateEntry{
		requestID:  "request-a",
		relayURL:   "https://app.example/",
		providerID: "other-saml",
	})
	prov := testSAMLRedirectProvider(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/saml/callback", strings.NewReader(url.Values{
		"RelayState":   {"state-a"},
		"SAMLResponse": {"not-base64"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, _, err := prov.ExchangeAssertion(r)
	if err == nil {
		t.Fatal("expected provider mismatch to fail")
	}
	if _, ok := globalSAMLStateStore.Peek("state-a"); !ok {
		t.Fatal("provider mismatch should not consume state before authSAMLCallback tries the owning provider")
	}
}

func TestSAMLExchangeAssertionConsumesStateBeforeValidation(t *testing.T) {
	resetSAMLStateStore(t)
	globalSAMLStateStore.Set("state-a", "203.0.113.5", &samlStateEntry{
		requestID:  "request-a",
		relayURL:   "https://app.example/",
		providerID: "corp-saml",
	})
	prov := testSAMLRedirectProvider(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/saml/callback", strings.NewReader(url.Values{
		"RelayState":   {"state-a"},
		"SAMLResponse": {"not-base64"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	id, relay, err := prov.ExchangeAssertion(r)
	if err == nil {
		t.Fatal("expected malformed SAMLResponse to fail")
	}
	if id != nil || relay != "" {
		t.Fatalf("got id=%+v relay=%q, want no identity or relay on failure", id, relay)
	}
	if _, ok := globalSAMLStateStore.Peek("state-a"); ok {
		t.Fatal("state should be consumed before SAML response validation to prevent callback replay")
	}
}
