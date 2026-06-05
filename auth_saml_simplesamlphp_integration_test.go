package main

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func TestSimpleSAMLphpInterop_CompilesProviderFromMetadataURL(t *testing.T) {
	metadataURL := strings.TrimSpace(os.Getenv("CULVERT_SIMPLESAML_METADATA_URL"))
	if metadataURL == "" {
		t.Skip("set CULVERT_SIMPLESAML_METADATA_URL to run SimpleSAMLphp interop test")
	}

	origDial := ssrfSafeDialContext
	ssrfSafeDialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	t.Cleanup(func() { ssrfSafeDialContext = origDial })

	origBaseURL := cfg.ProxyBaseURL()
	SetProxyBaseURL("https://proxy.example.test/culvert")
	t.Cleanup(func() { SetProxyBaseURL(origBaseURL) })

	prov, err := NewSAMLProvider(&IdPProfile{
		ID:      "simplesamlphp",
		Name:    "SimpleSAMLphp",
		Type:    IdPTypeSAML,
		Enabled: true,
		SAML: &SAMLProfileConfig{
			MetadataURL:     metadataURL,
			NameIDFormat:    string(saml.EmailAddressNameIDFormat),
			GroupsAttribute: "groups",
			EmailAttribute:  "email",
			NameAttribute:   "displayName",
		},
	})
	if err != nil {
		t.Fatalf("NewSAMLProvider with SimpleSAMLphp metadata: %v", err)
	}
	if prov == nil || prov.sp == nil {
		t.Fatalf("provider or service provider is nil: %+v", prov)
	}
	if prov.sp.AuthnNameIDFormat != saml.EmailAddressNameIDFormat {
		t.Fatalf("AuthnNameIDFormat = %q, want %q", prov.sp.AuthnNameIDFormat, saml.EmailAddressNameIDFormat)
	}
	if prov.sp.EntityID != "https://proxy.example.test/culvert" {
		t.Fatalf("EntityID = %q, want configured proxy base URL", prov.sp.EntityID)
	}

	loginURL := prov.CaptiveLoginURL("https://app.example.test/", nil)
	if loginURL == "" {
		t.Fatal("CaptiveLoginURL returned empty URL")
	}
	if !strings.Contains(loginURL, "SAMLRequest=") || !strings.Contains(loginURL, "RelayState=") {
		t.Fatalf("login URL does not look like an SP-initiated SAML redirect: %q", loginURL)
	}
}
