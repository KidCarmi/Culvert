package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
)

type testSAMLServiceProviderProvider struct {
	metadata *saml.EntityDescriptor
}

func (p testSAMLServiceProviderProvider) GetServiceProvider(_ *http.Request, _ string) (*saml.EntityDescriptor, error) {
	return p.metadata, nil
}

func TestSAMLExchangeAssertionAcceptsSignedResponse(t *testing.T) {
	fixture := newSignedSAMLFixture(t, nil)

	id, relayURL, err := fixture.provider.ExchangeAssertion(fixture.callbackRequest(t))
	if err != nil {
		t.Fatalf("ExchangeAssertion failed: %v", err)
	}
	if relayURL != fixture.relayURL {
		t.Fatalf("relayURL = %q, want %q", relayURL, fixture.relayURL)
	}
	if id.Sub != "alice@example.com" {
		t.Fatalf("Sub = %q, want alice@example.com", id.Sub)
	}
	if id.Email != "alice@example.com" {
		t.Fatalf("Email = %q, want alice@example.com", id.Email)
	}
	if id.Name != "Alice Example" {
		t.Fatalf("Name = %q, want Alice Example", id.Name)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "engineering" || id.Groups[1] != "admins" {
		t.Fatalf("Groups = %v, want [engineering admins]", id.Groups)
	}
}

func TestSAMLExchangeAssertionRejectsWrongRequestID(t *testing.T) {
	fixture := newSignedSAMLFixture(t, nil)
	globalSAMLStateStore.set(fixture.state, &samlStateEntry{
		requestID:  "different-request-id",
		relayURL:   fixture.relayURL,
		providerID: fixture.provider.profile.ID,
		createdAt:  time.Now(),
	})

	id, relayURL, err := fixture.provider.ExchangeAssertion(fixture.callbackRequest(t))
	if err == nil {
		t.Fatal("expected request ID mismatch to fail")
	}
	if id != nil || relayURL != "" {
		t.Fatalf("got id=%+v relay=%q, want no identity or relay on failure", id, relayURL)
	}
	if !strings.Contains(err.Error(), "saml response validation:") {
		t.Fatalf("error %q missing validation context", err)
	}
	if !strings.Contains(err.Error(), "InResponseTo") {
		t.Fatalf("error %q missing request correlation detail", err)
	}
}

func TestSAMLExchangeAssertionRejectsAudienceMismatch(t *testing.T) {
	fixture := newSignedSAMLFixture(t, func(metadata *saml.EntityDescriptor) {
		metadata.EntityID = "https://wrong-sp.example"
	})

	id, relayURL, err := fixture.provider.ExchangeAssertion(fixture.callbackRequest(t))
	if err == nil {
		t.Fatal("expected audience mismatch to fail")
	}
	if id != nil || relayURL != "" {
		t.Fatalf("got id=%+v relay=%q, want no identity or relay on failure", id, relayURL)
	}
	if !strings.Contains(err.Error(), "saml response validation:") {
		t.Fatalf("error %q missing validation context", err)
	}
}

type signedSAMLFixture struct {
	provider     *SAMLProvider
	relayURL     string
	state        string
	samlResponse string
}

func (f signedSAMLFixture) callbackRequest(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/saml/callback", strings.NewReader(url.Values{
		"RelayState":   {f.state},
		"SAMLResponse": {f.samlResponse},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func newSignedSAMLFixture(t *testing.T, mutateSPMetadata func(*saml.EntityDescriptor)) signedSAMLFixture {
	t.Helper()
	resetSAMLStateStore(t)

	provider := testSAMLRedirectProvider(t)
	provider.sp.EntityID = "https://proxy.example"
	provider.sp.AuthnNameIDFormat = saml.EmailAddressNameIDFormat

	idpKey, idpCert := newSAMLTestKeyPair(t, "Culvert test IdP")
	idpMetadataURL := mustParseSAMLTestURL(t, "https://idp.example/metadata")
	idpSSOURL := mustParseSAMLTestURL(t, "https://idp.example/sso")
	spMetadata := provider.sp.Metadata()
	if mutateSPMetadata != nil {
		mutateSPMetadata(spMetadata)
	}
	idp := &saml.IdentityProvider{
		Key:                     idpKey,
		Certificate:             idpCert,
		MetadataURL:             *idpMetadataURL,
		SSOURL:                  *idpSSOURL,
		ServiceProviderProvider: testSAMLServiceProviderProvider{metadata: spMetadata},
	}
	provider.sp.IDPMetadata = idp.Metadata()

	relayURL := "https://app.example/protected"
	loginURL := provider.CaptiveLoginURL(relayURL, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if loginURL == "" {
		t.Fatal("CaptiveLoginURL returned empty URL")
	}
	u, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("login URL parse: %v", err)
	}
	state := u.Query().Get("RelayState")
	if state == "" {
		t.Fatal("RelayState was not set")
	}

	authnRequest, err := saml.NewIdpAuthnRequest(idp, httptest.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil))
	if err != nil {
		t.Fatalf("IdP authn request parse: %v", err)
	}
	if err := authnRequest.Validate(); err != nil {
		t.Fatalf("IdP authn request validate: %v", err)
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(authnRequest, &saml.Session{
		NameID:         "alice@example.com",
		NameIDFormat:   string(saml.EmailAddressNameIDFormat),
		UserEmail:      "alice@example.com",
		UserCommonName: "Alice Example",
		Groups:         []string{"engineering", "admins"},
	}); err != nil {
		t.Fatalf("make assertion: %v", err)
	}
	if err := authnRequest.MakeResponse(); err != nil {
		t.Fatalf("make response: %v", err)
	}

	doc := etree.NewDocument()
	doc.SetRoot(authnRequest.ResponseEl)
	responseXML, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize response: %v", err)
	}
	return signedSAMLFixture{
		provider:     provider,
		relayURL:     relayURL,
		state:        state,
		samlResponse: base64.StdEncoding.EncodeToString(responseXML),
	}
}

func mustParseSAMLTestURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return u
}

func newSAMLTestKeyPair(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("cert parse: %v", err)
	}
	return key, cert
}
