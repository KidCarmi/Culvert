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
	"errors"
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
	if err := validateSAMLNameIDFormat(cfg.NameIDFormat); err != nil {
		return nil, fmt.Errorf("saml[%s] name_id_format: %w", p.ID, err)
	}

	idpMeta, err := fetchSAMLMetadata(cfg)
	if err != nil {
		return nil, fmt.Errorf("saml[%s] metadata: %w", p.ID, err)
	}

	spKey, spCert, err := ensureSPKeyPair()
	if err != nil {
		return nil, fmt.Errorf("saml[%s] sp key: %w", p.ID, err)
	}

	rootURL, err := url.Parse(proxyBaseURL(nil)) // nil: called at startup, no request context
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
	configureSAMLServiceProviderURLs(&middleware.ServiceProvider, rootURL)
	middleware.ServiceProvider.AuthnNameIDFormat = saml.NameIDFormat(requestedSAMLNameIDFormat(cfg))

	return &SAMLProvider{
		profile:    p,
		cfg:        cfg,
		sp:         &middleware.ServiceProvider,
		middleware: middleware,
	}, nil
}

func configureSAMLServiceProviderURLs(sp *saml.ServiceProvider, rootURL *url.URL) {
	if sp == nil || rootURL == nil {
		return
	}
	sp.EntityID = rootURL.String()
	acsURL := *rootURL
	acsURL.Path = strings.TrimRight(acsURL.Path, "/") + "/auth/saml/callback"
	acsURL.RawPath = ""
	acsURL.RawQuery = ""
	acsURL.Fragment = ""
	sp.AcsURL = acsURL
}

func (p *SAMLProvider) Name() string { return "saml:" + p.profile.ID }

// Verify always returns false — SAML is a browser-only protocol.
// Non-browser clients must use OIDC or LDAP.
func (p *SAMLProvider) Verify(_, _ string) bool { return false }

// ResolveIdentity is not applicable for SAML (browser-only flow).
func (p *SAMLProvider) ResolveIdentity(_, _ string) (*Identity, bool) { return nil, false }

// CaptiveLoginURL generates a SAML AuthnRequest and returns the redirect URL.
// relayURL is stored server-side; RelayState carries an opaque request handle.
func (p *SAMLProvider) CaptiveLoginURL(relayURL string, _ *http.Request) string {
	authReq, err := p.sp.MakeAuthenticationRequest(
		p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		logger.Printf("SAML[%s] AuthnRequest error: %v", p.profile.ID, err)
		return ""
	}
	state := mustRandHex(16)
	globalSAMLStateStore.set(state, &samlStateEntry{
		requestID:  authReq.ID,
		relayURL:   relayURL,
		providerID: p.profile.ID,
		createdAt:  time.Now(),
	})
	redirectURL, err := authReq.Redirect(state, p.sp)
	if err != nil {
		globalSAMLStateStore.pop(state)
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
	state := r.FormValue("RelayState")
	entry, ok := globalSAMLStateStore.peek(state)
	if !ok {
		return nil, "", fmt.Errorf("saml callback: invalid or expired state")
	}
	if entry.providerID != p.profile.ID {
		return nil, "", fmt.Errorf("saml callback: state belongs to different provider")
	}
	// authSAMLCallback tries each SAML provider; consume only after the
	// state proves this provider owns the original AuthnRequest.
	entry, ok = globalSAMLStateStore.pop(state)
	if !ok {
		return nil, "", fmt.Errorf("saml callback: invalid or expired state")
	}

	assertion, err := p.sp.ParseResponse(r, []string{entry.requestID})
	if err != nil {
		return nil, "", fmt.Errorf("saml response validation: %w", samlValidationError(err))
	}
	id := extractSAMLIdentity(assertion, p.cfg, p.profile.ID)
	if err := requireStableSAMLIdentity(id); err != nil {
		return nil, "", err
	}
	return id, entry.relayURL, nil
}

func samlValidationError(err error) error {
	var invalid *saml.InvalidResponseError
	if errors.As(err, &invalid) && invalid.PrivateErr != nil {
		return fmt.Errorf("%s: %w", invalid.PrivateErr, err)
	}
	return err
}

type samlStateEntry struct {
	requestID  string
	relayURL   string
	providerID string
	createdAt  time.Time
}

type samlStateStore struct {
	mu      sync.Mutex
	entries map[string]*samlStateEntry
}

const samlStateTTL = 10 * time.Minute
const samlStateStoreMax = 1000

var globalSAMLStateStore = &samlStateStore{entries: make(map[string]*samlStateEntry)}

func (s *samlStateStore) set(state string, e *samlStateEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= samlStateStoreMax {
		now := time.Now()
		for k, v := range s.entries {
			if now.After(v.createdAt.Add(samlStateTTL)) {
				delete(s.entries, k)
			}
		}
		if len(s.entries) >= samlStateStoreMax {
			for k := range s.entries {
				delete(s.entries, k)
				break
			}
		}
	}
	s.entries[state] = e
}

func (s *samlStateStore) peek(state string) (*samlStateEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[state]
	if !ok {
		return nil, false
	}
	if time.Since(e.createdAt) > samlStateTTL {
		delete(s.entries, state)
		return nil, false
	}
	return e, true
}

func (s *samlStateStore) pop(state string) (*samlStateEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[state]
	if !ok {
		return nil, false
	}
	delete(s.entries, state)
	if time.Since(e.createdAt) > samlStateTTL {
		return nil, false
	}
	return e, true
}

// ---------------------------------------------------------------------------
// SAML metadata fetch + parse
// ---------------------------------------------------------------------------

func fetchSAMLMetadata(cfg *SAMLProfileConfig) (*saml.EntityDescriptor, error) {
	var xmlData []byte

	if cfg.MetadataURL != "" {
		// Validate scheme before making any request.
		metaURL, err := url.Parse(cfg.MetadataURL)
		if err != nil {
			return nil, fmt.Errorf("metadata URL parse: %w", err)
		}
		if metaURL.Scheme != "http" && metaURL.Scheme != "https" {
			return nil, fmt.Errorf("metadata URL must use http or https scheme")
		}

		// Use an SSRF-safe transport that rejects private/internal IPs at
		// the dial level — even if DNS changes between validation and
		// connection, the transport blocks the request.
		client := &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext: ssrfSafeDialContext,
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL.String(), nil)
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
		nameID := a.Subject.NameID
		if isStableSAMLNameIDFormat(nameID.Format) {
			id.Sub = nameID.Value
			if strings.Contains(id.Sub, "@") {
				id.Email = id.Sub
			}
		}
	}

	var groupsAttr, emailAttr, nameAttr string
	if cfg != nil {
		groupsAttr = cfg.GroupsAttribute
		emailAttr = cfg.EmailAttribute
		nameAttr = cfg.NameAttribute
	}
	if groupsAttr == "" {
		groupsAttr = "groups"
	}
	if emailAttr == "" {
		emailAttr = "email"
	}
	if nameAttr == "" {
		nameAttr = "displayName"
	}

	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			vals := samlAttrValues(attr)
			switch {
			case samlAttrMatches(attr, emailAttr,
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
				"urn:oid:0.9.2342.19200300.100.1.3"):
				if id.Email == "" && len(vals) > 0 {
					id.Email = vals[0]
				}
			case samlAttrMatches(attr, nameAttr, "cn", "displayName",
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"):
				if id.Name == "" && len(vals) > 0 {
					id.Name = vals[0]
				}
			case samlAttrMatches(attr, groupsAttr, "memberOf", "Role",
				"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
				"http://schemas.xmlsoap.org/claims/Group"):
				id.Groups = append(id.Groups, vals...)
			}
		}
	}
	if id.Sub == "" && id.Email != "" {
		id.Sub = id.Email
	}
	return id
}

func samlAttrMatches(attr saml.Attribute, names ...string) bool {
	for _, name := range names {
		switch name {
		case "":
			continue
		case attr.Name, attr.FriendlyName:
			return true
		}
	}
	return false
}

func requestedSAMLNameIDFormat(cfg *SAMLProfileConfig) string {
	if cfg != nil && cfg.NameIDFormat != "" {
		return cfg.NameIDFormat
	}
	return string(saml.EmailAddressNameIDFormat)
}

func isStableSAMLNameIDFormat(format string) bool {
	switch saml.NameIDFormat(format) {
	case saml.EmailAddressNameIDFormat, saml.PersistentNameIDFormat:
		return true
	default:
		return false
	}
}

func validateSAMLNameIDFormat(format string) error {
	if format == "" || isStableSAMLNameIDFormat(format) {
		return nil
	}
	return fmt.Errorf("must be stable (emailAddress or persistent), got %q", format)
}

func requireStableSAMLIdentity(id *Identity) error {
	if id == nil || id.Sub == "" {
		return fmt.Errorf("saml response validation: missing stable identity")
	}
	return nil
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
	spKeyOnce   sync.Once
	spKeyCache  *rsa.PrivateKey
	spCertCache *x509.Certificate
	spKeyErr    error
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
			Subject:      pkix.Name{CommonName: "Culvert SAML SP"},
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
