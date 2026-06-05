package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
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

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create SimpleSAMLphp cookie jar: %v", err)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Jar:     jar,
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
	if err != nil {
		t.Fatalf("build SimpleSAMLphp login request: %v", err)
	}
	// #nosec G107 -- integration test intentionally follows the IdP login URL from trusted CI fixture metadata.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET SimpleSAMLphp login URL: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read SimpleSAMLphp login response: %v", err)
	}
	bodyText := string(body)
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("SimpleSAMLphp rejected SP-initiated login URL with 404; body=%q", bodyText)
	}
	if resp.StatusCode >= 500 {
		t.Fatalf("SimpleSAMLphp login URL returned HTTP %d; body=%q", resp.StatusCode, bodyText)
	}
	if strings.Contains(bodyText, "SimpleSAML\\Error") {
		t.Fatalf("SimpleSAMLphp login URL returned an error page; status=%d body=%q", resp.StatusCode, bodyText)
	}
}
