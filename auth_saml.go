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

	"github.com/KidCarmi/Culvert/internal/authstate"
	"github.com/KidCarmi/Culvert/internal/idpmeta"
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

	idpMeta, err := fetchSAMLMetadata(p.ID, cfg)
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

// DisplayName returns the admin-configured label shown to end users (e.g. on
// the IdP selection screen), falling back to the machine key if unset.
func (p *SAMLProvider) DisplayName() string {
	if p.profile.Name != "" {
		return p.profile.Name
	}
	return p.Name()
}

// Verify always returns false — SAML is a browser-only protocol.
// Non-browser clients must use OIDC or LDAP.
func (p *SAMLProvider) Verify(_, _ string) bool { return false }

// ResolveIdentity is not applicable for SAML (browser-only flow).
func (p *SAMLProvider) ResolveIdentity(_, _ string) (*Identity, bool) { return nil, false }

// CaptiveLoginURL generates a SAML AuthnRequest and returns the redirect URL.
// relayURL is stored server-side; RelayState carries an opaque request handle.
func (p *SAMLProvider) CaptiveLoginURL(relayURL string, r *http.Request) string {
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
	// Attributed to the requesting client so a flood from one source can only
	// evict its own in-flight state, never another user's mid-login entry.
	globalSAMLStateStore.Set(state, authStateClientKey(r), &samlStateEntry{
		requestID:  authReq.ID,
		relayURL:   relayURL,
		providerID: p.profile.ID,
	})
	redirectURL, err := authReq.Redirect(state, p.sp)
	if err != nil {
		globalSAMLStateStore.Pop(state)
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
	entry, ok := globalSAMLStateStore.Peek(state)
	if !ok {
		return nil, "", fmt.Errorf("saml callback: invalid or expired state")
	}
	if entry.providerID != p.profile.ID {
		return nil, "", fmt.Errorf("saml callback: state belongs to different provider")
	}
	// authSAMLCallback tries each SAML provider; consume only after the
	// state proves this provider owns the original AuthnRequest.
	entry, ok = globalSAMLStateStore.Pop(state)
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
}

// samlStateStore is the bounded, fair-share store for in-flight SAML
// AuthnRequests, keyed by the opaque RelayState handle.
//
// Like the OIDC PKCE store it is populated by UNAUTHENTICATED requests (the
// captive-portal path resolves a login URL before the client has any
// identity), so its eviction policy is a security control: an anonymous flood
// must not be able to destroy other users' in-flight login state. See
// internal/authstate.
type samlStateStore = authstate.Store[*samlStateEntry]

const samlStateTTL = 10 * time.Minute
const samlStateStoreMax = 1000

var globalSAMLStateStore = newSAMLStateStore()

func newSAMLStateStore() *samlStateStore {
	return authstate.New[*samlStateEntry](samlStateTTL, samlStateStoreMax)
}

// ---------------------------------------------------------------------------
// SAML metadata fetch + parse
// ---------------------------------------------------------------------------

// fetchSAMLMetadata resolves the IdP EntityDescriptor for a profile.
//
// CHAOS-71: the remote branch goes through acquireIdPDocument, so a metadata
// endpoint that is momentarily unreachable degrades to the last successfully
// fetched document (bounded by idpmeta.StaleMaxAge) instead of destroying the
// provider. The bytes it returns are parsed by the SAME samlsp.ParseMetadata
// call as network bytes — the cache is a source of bytes, never a source of
// trust.
func fetchSAMLMetadata(profileID string, cfg *SAMLProfileConfig) (*saml.EntityDescriptor, error) {
	var xmlData []byte

	if cfg.MetadataURL != "" {
		// Reject a malformed or wrong-scheme URL HERE, before the fetch, so
		// that a CONFIGURATION error can never be mistaken for an
		// AVAILABILITY error and answered from the last-known-good cache.
		// Only the parse verdict is used; the parsed value is deliberately
		// discarded and the raw configured string is what reaches the
		// fetcher, which parses and guards it once in the same function that
		// issues the request.
		if err := validateSAMLMetadataURL(cfg.MetadataURL); err != nil {
			return nil, err
		}
		fetched, fetchErr := fetchSAMLMetadataOverNetwork(cfg.MetadataURL)
		doc, err := resolveIdPDocument(profileID, idpmeta.KindSAMLMetadata, cfg.MetadataURL, fetched, fetchErr, validateSAMLMetadataDocument)
		if err != nil {
			return nil, err
		}
		xmlData = doc
	} else {
		xmlData = []byte(cfg.MetadataXML)
		noteIdPMetadataOutcome(profileID, idpMetaInline, nil)
	}

	return samlsp.ParseMetadata(xmlData)
}

// validateSAMLMetadataDocument is the document gate resolveIdPDocument applies
// before persisting a fetched document as last-known-good: the SAME parser the
// compile runs on the result, so only a document the compile would accept can
// ever replace the cached copy.
func validateSAMLMetadataDocument(doc []byte) error {
	_, err := samlsp.ParseMetadata(doc)
	return err
}

// validateSAMLMetadataURL reports whether a configured metadata URL is
// well-formed and carries a scheme this appliance will fetch. It returns no
// parsed value on purpose: nothing derived from it may reach an outbound
// request, so the raw configured string stays the single thing the fetcher
// parses (see fetchSAMLMetadataOverNetwork).
func validateSAMLMetadataURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("metadata URL parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("metadata URL must use http or https scheme")
	}
	return nil
}

// fetchSAMLMetadataOverNetwork performs exactly the request the pre-CHAOS-71
// code performed: same 15 s budget, same SSRF-safe dialer, same 1 MiB read
// limit, same HTTP-status rule. It is split out only so acquireIdPDocument can
// own the cache/fallback decision around it.
//
// THE SCHEME CHECK IS REPEATED HERE ON PURPOSE, and must not be "cleaned up"
// as redundant with the caller's. The repo convention (CLAUDE.md, SSRF guards)
// is that the guard is inlined in the same function as the outbound request so
// CodeQL can verify it — relying on a check in a calling function is exactly
// what the convention forbids. Splitting this helper out of
// fetchSAMLMetadata without carrying the guard raised a critical
// go/request-forgery alert on the first CI run of CHAOS-71.
func fetchSAMLMetadataOverNetwork(raw string) ([]byte, error) {
	metaURL, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("metadata URL parse: %w", err)
	}
	if metaURL.Scheme != "http" && metaURL.Scheme != "https" {
		return nil, fmt.Errorf("metadata URL must use http or https scheme")
	}
	// The PRE-FLIGHT half of the guard, inline per the repo's SSRF convention
	// so CodeQL can see a barrier on the host and not just on the scheme.
	//
	// It is not new enforcement: ssrfSafeDialContext below already refuses a
	// private destination at connect time, so the set of URLs this function
	// will fetch is unchanged — a private metadata host failed before and
	// fails now, just earlier and with an error that names the reason. The
	// two layers are complementary rather than redundant: this one refuses a
	// host that resolves private NOW, the dialer catches one that resolves
	// public here and private at connect time (DNS rebinding).
	if err := isPrivateHost(metaURL.Host); err != nil {
		return nil, fmt.Errorf("metadata URL host refused: %w", err)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL.String(), http.NoBody)
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
	xmlData, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return xmlData, nil
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
				"http://schemas.xmlsoap.org/claims/Group",
				"eduPersonAffiliation",
				"urn:oid:1.3.6.1.4.1.5923.1.1.1.1"):
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
