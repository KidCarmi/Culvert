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

func TestSAMLExchangeAssertionAcceptsPersistentNameIDResponse(t *testing.T) {
	fixture := newSignedSAMLFixtureWithSession(t, signedSAMLFixtureOptions{
		session: &saml.Session{
			NameID:         "persistent-user-123",
			NameIDFormat:   string(saml.PersistentNameIDFormat),
			UserEmail:      "alice@example.com",
			UserCommonName: "Alice Example",
			Groups:         []string{"engineering", "admins"},
		},
	})

	id, relayURL, err := fixture.provider.ExchangeAssertion(fixture.callbackRequest(t))
	if err != nil {
		t.Fatalf("ExchangeAssertion failed: %v", err)
	}
	if relayURL != fixture.relayURL {
		t.Fatalf("relayURL = %q, want %q", relayURL, fixture.relayURL)
	}
	if id.Sub != "persistent-user-123" {
		t.Fatalf("Sub = %q, want persistent-user-123", id.Sub)
	}
	if id.Email != "alice@example.com" {
		t.Fatalf("Email = %q, want alice@example.com", id.Email)
	}
}

func TestSAMLExchangeAssertionRejectsTransientOnlyNameIDResponse(t *testing.T) {
	fixture := newSignedSAMLFixtureWithSession(t, signedSAMLFixtureOptions{
		session: &saml.Session{
			NameID:       "session-only-id",
			NameIDFormat: string(saml.TransientNameIDFormat),
		},
	})

	id, relayURL, err := fixture.provider.ExchangeAssertion(fixture.callbackRequest(t))
	if err == nil {
		t.Fatal("expected transient-only response to fail")
	}
	if id != nil || relayURL != "" {
		t.Fatalf("got id=%+v relay=%q, want no identity or relay on failure", id, relayURL)
	}
	if !strings.Contains(err.Error(), "missing stable identity") {
		t.Fatalf("error %q missing stable identity detail", err)
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

func TestSAMLExchangeAssertionRejectsReplayedSignedResponse(t *testing.T) {
	fixture := newSignedSAMLFixture(t, nil)

	id, relayURL, err := fixture.provider.ExchangeAssertion(fixture.callbackRequest(t))
	if err != nil {
		t.Fatalf("first ExchangeAssertion failed: %v", err)
	}
	if id == nil || relayURL != fixture.relayURL {
		t.Fatalf("first ExchangeAssertion got id=%+v relay=%q, want identity and relay %q", id, relayURL, fixture.relayURL)
	}

	id, relayURL, err = fixture.provider.ExchangeAssertion(fixture.callbackRequest(t))
	if err == nil {
		t.Fatal("expected replayed signed response to fail")
	}
	if id != nil || relayURL != "" {
		t.Fatalf("got id=%+v relay=%q, want no identity or relay on replay", id, relayURL)
	}
	if !strings.Contains(err.Error(), "invalid or expired state") {
		t.Fatalf("error %q missing replay state failure detail", err)
	}
}

func TestSAMLExchangeAssertionRejectsUnsignedResponse(t *testing.T) {
	fixture := newSignedSAMLFixture(t, nil)
	fixture.samlResponse = stripSAMLResponseSignatures(t, fixture.samlResponse)

	id, relayURL, err := fixture.provider.ExchangeAssertion(fixture.callbackRequest(t))
	if err == nil {
		t.Fatal("expected unsigned response to fail")
	}
	if id != nil || relayURL != "" {
		t.Fatalf("got id=%+v relay=%q, want no identity or relay on failure", id, relayURL)
	}
	if !strings.Contains(err.Error(), "saml response validation:") {
		t.Fatalf("error %q missing validation context", err)
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

func TestSAMLExchangeAssertionRejectsExpiredSignedAssertion(t *testing.T) {
	fixture := newSignedSAMLFixtureWithSession(t, signedSAMLFixtureOptions{
		assertionMaker: expiredSAMLAssertionMaker{},
	})

	id, relayURL, err := fixture.provider.ExchangeAssertion(fixture.callbackRequest(t))
	if err == nil {
		t.Fatal("expected expired signed assertion to fail")
	}
	if id != nil || relayURL != "" {
		t.Fatalf("got id=%+v relay=%q, want no identity or relay on failure", id, relayURL)
	}
	if !strings.Contains(err.Error(), "saml response validation:") {
		t.Fatalf("error %q missing validation context", err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error %q missing expired assertion detail", err)
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

type signedSAMLFixtureOptions struct {
	mutateSPMetadata func(*saml.EntityDescriptor)
	session          *saml.Session
	assertionMaker   saml.AssertionMaker
}

func newSignedSAMLFixture(t *testing.T, mutateSPMetadata func(*saml.EntityDescriptor)) signedSAMLFixture {
	return newSignedSAMLFixtureWithSession(t, signedSAMLFixtureOptions{
		mutateSPMetadata: mutateSPMetadata,
	})
}

func newSignedSAMLFixtureWithSession(t *testing.T, opts signedSAMLFixtureOptions) signedSAMLFixture {
	t.Helper()
	resetSAMLStateStore(t)

	provider := testSAMLRedirectProvider(t)
	provider.sp.EntityID = "https://proxy.example"
	provider.sp.AuthnNameIDFormat = saml.EmailAddressNameIDFormat

	idpKey, idpCert := newSAMLTestKeyPair(t, "Culvert test IdP")
	idpMetadataURL := mustParseSAMLTestURL(t, "https://idp.example/metadata")
	idpSSOURL := mustParseSAMLTestURL(t, "https://idp.example/sso")
	spMetadata := provider.sp.Metadata()
	if opts.mutateSPMetadata != nil {
		opts.mutateSPMetadata(spMetadata)
	}
	idp := &saml.IdentityProvider{
		Key:                     idpKey,
		Certificate:             idpCert,
		MetadataURL:             *idpMetadataURL,
		SSOURL:                  *idpSSOURL,
		ServiceProviderProvider: testSAMLServiceProviderProvider{metadata: spMetadata},
		AssertionMaker:          opts.assertionMaker,
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
	session := opts.session
	if session == nil {
		session = &saml.Session{
			NameID:         "alice@example.com",
			NameIDFormat:   string(saml.EmailAddressNameIDFormat),
			UserEmail:      "alice@example.com",
			UserCommonName: "Alice Example",
			Groups:         []string{"engineering", "admins"},
		}
	}
	assertionMaker := opts.assertionMaker
	if assertionMaker == nil {
		assertionMaker = saml.DefaultAssertionMaker{}
	}
	if err := assertionMaker.MakeAssertion(authnRequest, session); err != nil {
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

type expiredSAMLAssertionMaker struct{}

func (expiredSAMLAssertionMaker) MakeAssertion(req *saml.IdpAuthnRequest, session *saml.Session) error {
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		return err
	}
	expiredAt := time.Now().Add(-2 * saml.MaxClockSkew)
	validFrom := expiredAt.Add(-time.Minute)
	req.Assertion.Conditions.NotBefore = validFrom
	req.Assertion.Conditions.NotOnOrAfter = expiredAt
	for _, confirmation := range req.Assertion.Subject.SubjectConfirmations {
		if confirmation.SubjectConfirmationData != nil {
			confirmation.SubjectConfirmationData.NotOnOrAfter = expiredAt
		}
	}
	return nil
}

func stripSAMLResponseSignatures(t *testing.T, encodedResponse string) string {
	t.Helper()
	responseXML, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		t.Fatalf("decode SAMLResponse: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(responseXML); err != nil {
		t.Fatalf("parse SAMLResponse XML: %v", err)
	}
	removed := removeElementsByLocalName(doc.Root(), "Signature")
	if removed == 0 {
		t.Fatal("test fixture did not contain a Signature element to remove")
	}
	strippedXML, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize stripped SAMLResponse: %v", err)
	}
	return base64.StdEncoding.EncodeToString(strippedXML)
}

func removeElementsByLocalName(parent *etree.Element, localName string) int {
	removed := 0
	for _, child := range parent.ChildElements() {
		if child.Tag == localName {
			parent.RemoveChild(child)
			removed++
			continue
		}
		removed += removeElementsByLocalName(child, localName)
	}
	return removed
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
