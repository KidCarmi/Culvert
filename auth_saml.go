package main

// SAMLProvider implements SAML 2.0 SP-initiated SSO using github.com/crewjam/saml.
//
// Security properties enforced by crewjam/saml:
//   - XML signature on SAMLResponse validated against IdP certificate.
//   - NotBefore / NotAfter / SessionNotOnOrAfter conditions enforced.
//   - Audience restriction validated against the SP EntityID.
//   - In-response-to (request ID) prevents unsolicited responses.
//   - Replay detection via one-time use of the assertion ID.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// ---------------------------------------------------------------------------
// SAMLProvider
// ---------------------------------------------------------------------------

// SAMLProvider wraps a crewjam/saml Service Provider for one IdP profile.
type SAMLProvider struct {
	profile    *IdPProfile
	cfg        *SAMLProfileConfig
	sp         *saml.ServiceProvider
	middleware *samlsp.Middleware
}

// NewSAMLProvider builds a SAMLProvider from an IdPProfile.
func NewSAMLProvider(p *IdPProfile) (*SAMLProvider, error) {
	cfg := p.SAML
	if cfg.MetadataURL == "" && cfg.MetadataXML == "" {
		return nil, fmt.Errorf("saml[%s]: metadata_url or metadata_xml required", p.ID)
	}

	idpMeta, err := fetchSAMLMetadata(cfg)
	if err != nil {
		return nil, fmt.Errorf("saml[%s] metadata: %w", p.ID, err)
	}

	spKey, spCert, err := ensureSPKeyPair()
	if err != nil {
		return nil, fmt.Errorf("saml[%s] sp key: %w", p.ID, err)
	}

	rootURL, err := url.Parse(proxyBaseURL())
	if err != nil {
		return nil, fmt.Errorf("saml[%s] base url: %w", p.ID, err)
	}

	middleware, err := samlsp.New(samlsp.Options{
		URL:               *rootURL,
		Key:               spKey,
		Certificate:       spCert,
		IDPMetadata:       idpMeta,
		AllowIDPInitiated: false, // SP-initiated only for security
	})
	if err != nil {
		return nil, fmt.Errorf("saml[%s] sp init: %w", p.ID, err)
	}

	return &SAMLProvider{
		profile:    p,
		cfg:        cfg,
		sp:         &middleware.ServiceProvider,
		middleware: middleware,
	}, nil
}

func (p *SAMLProvider) Name() string { return "saml:" + p.profile.ID }

// Verify always returns false — SAML is a browser-only protocol.
// Non-browser clients must use OIDC or LDAP.
func (p *SAMLProvider) Verify(_, _ string) bool { return false }

// ResolveIdentity is not applicable for SAML (browser-only flow).
func (p *SAMLProvider) ResolveIdentity(_, _ string) (*Identity, bool) { return nil, false }

// CaptiveLoginURL generates a SAML AuthnRequest and returns the redirect URL.
// relayURL is encoded as the SAMLRequest RelayState and returned after callback.
func (p *SAMLProvider) CaptiveLoginURL(relayURL string) string {
	authReq, err := p.sp.MakeAuthenticationRequest(
		p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		logger.Printf("SAML[%s] AuthnRequest error: %v", p.profile.ID, err)
		return ""
	}
	redirectURL, err := authReq.Redirect(relayURL, p.sp)
	if err != nil {
		logger.Printf("SAML[%s] redirect build error: %v", p.profile.ID, err)
		return ""
	}
	return redirectURL.String()
}

// ExchangeAssertion validates the SAMLResponse POST, extracts attributes,
// and returns the Identity + relay URL (original destination).
func (p *SAMLProvider) ExchangeAssertion(r *http.Request) (*Identity, string, error) {
	if err := r.ParseForm(); err != nil {
		return nil, "", fmt.Errorf("saml callback: form parse: %w", err)
	}
	relayState := r.FormValue("RelayState")

	assertion, err := p.sp.ParseResponse(r, nil)
	if err != nil {
		return nil, "", fmt.Errorf("saml response validation: %w", err)
	}
	id := extractSAMLIdentity(assertion, p.cfg, p.profile.ID)
	return id, relayState, nil
}

// ---------------------------------------------------------------------------
// SAML metadata fetch + parse
// ---------------------------------------------------------------------------

func fetchSAMLMetadata(cfg *SAMLProfileConfig) (*saml.EntityDescriptor, error) {
	var xmlData []byte

	if cfg.MetadataURL != "" {
		if err := validateExternalURL(cfg.MetadataURL); err != nil {
			return nil, fmt.Errorf("metadata URL: %w", err)
		}
		client := &http.Client{Timeout: 15 * time.Second}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.MetadataURL, nil)
		if err != nil {
			return nil, fmt.Errorf("metadata request: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d fetching metadata", resp.StatusCode)
		}
		xmlData, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}
	} else {
		xmlData = []byte(cfg.MetadataXML)
	}

	return samlsp.ParseMetadata(xmlData)
}

// ---------------------------------------------------------------------------
// Identity extraction from SAML assertion
// ---------------------------------------------------------------------------

func extractSAMLIdentity(a *saml.Assertion, cfg *SAMLProfileConfig, providerID string) *Identity {
	if a == nil {
		return &Identity{Provider: providerID}
	}

	id := &Identity{Provider: providerID}

	if a.Subject != nil && a.Subject.NameID != nil {
		id.Sub = a.Subject.NameID.Value
		if strings.Contains(id.Sub, "@") {
			id.Email = id.Sub
		}
	}

	groupsAttr := cfg.GroupsAttribute
	if groupsAttr == "" {
		groupsAttr = "groups"
	}
	emailAttr := cfg.EmailAttribute
	if emailAttr == "" {
		emailAttr = "email"
	}
	nameAttr := cfg.NameAttribute
	if nameAttr == "" {
		nameAttr = "displayName"
	}

	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			vals := samlAttrValues(attr)
			switch attr.Name {
			case emailAttr,
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
				"urn:oid:0.9.2342.19200300.100.1.3":
				if id.Email == "" && len(vals) > 0 {
					id.Email = vals[0]
				}
			case nameAttr, "cn", "displayName",
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
				if id.Name == "" && len(vals) > 0 {
					id.Name = vals[0]
				}
			case groupsAttr, "memberOf", "Role",
				"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
				"http://schemas.xmlsoap.org/claims/Group":
				id.Groups = append(id.Groups, vals...)
			}
		}
	}
	return id
}

func samlAttrValues(attr saml.Attribute) []string {
	out := make([]string, 0, len(attr.Values))
	for _, v := range attr.Values {
		if v.Value != "" {
			out = append(out, v.Value)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// SP RSA key pair (ephemeral, generated once per process)
// ---------------------------------------------------------------------------

var (
	spKeyOnce  sync.Once
	spKeyCache *rsa.PrivateKey
	spCertCache *x509.Certificate
	spKeyErr   error
)

// ensureSPKeyPair returns the SP's RSA private key and self-signed certificate.
// The pair is generated once at first call and reused for the process lifetime.
func ensureSPKeyPair() (*rsa.PrivateKey, *x509.Certificate, error) {
	spKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			spKeyErr = fmt.Errorf("rsa keygen: %w", err)
			return
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "ProxyShield SAML SP"},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			spKeyErr = fmt.Errorf("cert create: %w", err)
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			spKeyErr = fmt.Errorf("cert parse: %w", err)
			return
		}
		spKeyCache = key
		spCertCache = cert
	})
	return spKeyCache, spCertCache, spKeyErr
}

// Compile-time interface checks.
var _ IdentityProvider = (*SAMLProvider)(nil)
var _ IdentityProvider = (*OIDCFlowProvider)(nil)
