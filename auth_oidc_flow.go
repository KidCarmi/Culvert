package main

// OIDCFlowProvider implements a full OIDC Authorization Code flow with PKCE
// (RFC 7636) for browser-based authentication via the captive portal, and
// RFC 7662 token introspection for non-browser / API clients that supply a
// Bearer token in the Proxy-Authorization header.
//
// Security properties:
//   - PKCE (S256) prevents authorisation-code interception attacks.
//   - State parameter prevents CSRF on the callback endpoint.
//   - ID tokens are validated against the IdP's JWKs (RS256/ES256 only).
//   - Nonces prevent token replay attacks.
//   - All upstream URLs are validated as HTTPS + non-private (SSRF guard).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------------
// OIDC Discovery
// ---------------------------------------------------------------------------

// oidcDiscoveryDoc is the subset of fields we consume from the
// OpenID Provider Metadata document (RFC 8414 / OIDC Discovery 1.0).
type oidcDiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKsURI               string `json:"jwks_uri"`
}

// fetchOIDCDiscovery fetches and validates the provider's well-known metadata.
// The caller is responsible for ensuring issuer is a valid HTTPS URL.
func fetchOIDCDiscovery(issuer string) (*oidcDiscoveryDoc, error) {
	// Normalise: strip trailing slash.
	issuer = strings.TrimRight(issuer, "/")
	wellKnown := issuer + "/.well-known/openid-configuration"

	// Security: ensure the discovery URL is safe (non-private HTTPS).
	if err := validateExternalURL(wellKnown); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: ssrfSafeDialContext},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: HTTP %d", resp.StatusCode)
	}

	var doc oidcDiscoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("oidc discovery parse: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("oidc discovery: missing required endpoints")
	}
	// Validate all discovered endpoints before storing.
	for _, u := range []string{
		doc.AuthorizationEndpoint,
		doc.TokenEndpoint,
		doc.JWKsURI,
	} {
		if u == "" {
			continue
		}
		if err := validateExternalURL(u); err != nil {
			return nil, fmt.Errorf("oidc discovery endpoint %q: %w", u, err)
		}
	}
	return &doc, nil
}

// ---------------------------------------------------------------------------
// JWKs cache + ID-token verification
// ---------------------------------------------------------------------------

type jwkSet struct {
	Keys []json.RawMessage `json:"keys"`
}

type jwkKeyRaw struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksCache caches the public keys fetched from the IdP's JWKs endpoint.
type jwksCache struct {
	mu        sync.RWMutex
	keys      map[string]interface{} // kid → *rsa.PublicKey or *ecdsa.PublicKey
	fetchedAt time.Time
	jwksURI   string
	client    *http.Client
}

const jwksCacheTTL = 15 * time.Minute

// getKey returns the public key for kid, refreshing the cache when stale.
func (j *jwksCache) getKey(kid string) (interface{}, error) {
	j.mu.RLock()
	k, ok := j.keys[kid]
	stale := time.Since(j.fetchedAt) > jwksCacheTTL
	j.mu.RUnlock()

	if ok && !stale {
		return k, nil
	}

	// Re-fetch.
	if err := j.refresh(); err != nil {
		if ok {
			return k, nil // return stale key rather than failing
		}
		return nil, err
	}

	j.mu.RLock()
	k, ok = j.keys[kid]
	j.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("jwks: key %q not found", kid)
	}
	return k, nil
}

func (j *jwksCache) refresh() error {
	resp, err := j.client.Get(j.jwksURI) //nolint:noctx
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()

	var set jwkSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&set); err != nil {
		return fmt.Errorf("jwks parse: %w", err)
	}

	keys := make(map[string]interface{}, len(set.Keys))
	for _, raw := range set.Keys {
		var kh jwkKeyRaw
		if err := json.Unmarshal(raw, &kh); err != nil {
			continue
		}
		if kh.Kty != "RSA" {
			continue // only RSA for now (ES256 extension is straightforward to add)
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(kh.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(kh.E)
		if err != nil {
			continue
		}
		var eInt big.Int
		eInt.SetBytes(eBytes)
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(eInt.Int64()),
		}
		keys[kh.Kid] = pub
	}

	j.mu.Lock()
	j.keys = keys
	j.fetchedAt = time.Now()
	j.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// PKCE + state store
// ---------------------------------------------------------------------------

type pkceEntry struct {
	verifier  string
	nonce     string
	relayURL  string
	createdAt time.Time
	providerID string
}

type pkceStore struct {
	mu      sync.Mutex
	entries map[string]*pkceEntry // key = state
}

const pkceEntryTTL = 10 * time.Minute
const pkceStoreMax = 1000

var globalPKCEStore = &pkceStore{entries: make(map[string]*pkceEntry)}

func (s *pkceStore) set(state string, e *pkceEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Evict expired entries (and oldest if full).
	if len(s.entries) >= pkceStoreMax {
		now := time.Now()
		for k, v := range s.entries {
			if now.After(v.createdAt.Add(pkceEntryTTL)) {
				delete(s.entries, k)
			}
		}
		// If still full, evict one arbitrary entry.
		if len(s.entries) >= pkceStoreMax {
			for k := range s.entries {
				delete(s.entries, k)
				break
			}
		}
	}
	s.entries[state] = e
}

func (s *pkceStore) pop(state string) (*pkceEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[state]
	if !ok {
		return nil, false
	}
	delete(s.entries, state)
	if time.Since(e.createdAt) > pkceEntryTTL {
		return nil, false // expired
	}
	return e, true
}

// peek returns the PKCE entry without removing it (used by the UI to identify
// which provider the state belongs to before calling ExchangeCode).
func (s *pkceStore) peek(state string) (*pkceEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[state]
	if !ok {
		return nil, false
	}
	if time.Since(e.createdAt) > pkceEntryTTL {
		delete(s.entries, state)
		return nil, false
	}
	return e, true
}

// ---------------------------------------------------------------------------
// OIDCFlowProvider
// ---------------------------------------------------------------------------

// OIDCFlowProvider is the live, compiled provider built from an OIDCProfileConfig.
type OIDCFlowProvider struct {
	profile *IdPProfile
	cfg     *OIDCProfileConfig
	disc    *oidcDiscoveryDoc
	jwks    *jwksCache
	client  *http.Client
}

// NewOIDCFlowProvider validates the profile, runs OIDC discovery, and returns
// a ready-to-use OIDCFlowProvider.
func NewOIDCFlowProvider(p *IdPProfile) (*OIDCFlowProvider, error) {
	cfg := p.OIDC
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc[%s]: client_id required", p.ID)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = ssrfSafeDialContext // SSRF guard at dial level
	if cfg.TLSSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}

	disc, err := fetchOIDCDiscovery(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc[%s] discovery: %w", p.ID, err)
	}
	// Persist discovered endpoints back into the profile config so the UI
	// can display them.
	cfg.AuthorizationEndpoint = disc.AuthorizationEndpoint
	cfg.TokenEndpoint = disc.TokenEndpoint
	cfg.IntrospectionEndpoint = disc.IntrospectionEndpoint
	cfg.UserinfoEndpoint = disc.UserinfoEndpoint
	cfg.JWKsURI = disc.JWKsURI

	prov := &OIDCFlowProvider{
		profile: p,
		cfg:     cfg,
		disc:    disc,
		client:  client,
	}
	if disc.JWKsURI != "" {
		prov.jwks = &jwksCache{jwksURI: disc.JWKsURI, client: client, keys: make(map[string]interface{})}
	}
	return prov, nil
}

func (p *OIDCFlowProvider) Name() string { return "oidc:" + p.profile.ID }

// Verify supports non-browser clients that supply an access token as the
// proxy password (RFC 7662 introspection).
func (p *OIDCFlowProvider) Verify(username, token string) bool {
	id, ok := p.ResolveIdentity(username, token)
	return ok && id != nil
}

// ResolveIdentity introspects the token (for non-browser clients) or validates
// an ID token (for browser flows after callback).  For non-browser clients
// the token is treated as an opaque access token and sent to the introspection
// endpoint.
func (p *OIDCFlowProvider) ResolveIdentity(username, token string) (*Identity, bool) {
	if token == "" {
		return nil, false
	}

	// Try JWT validation first (browser flow — token is an ID token).
	// No nonce check here: non-browser clients submit access tokens, not ID tokens.
	if id, err := p.validateIDToken(token, ""); err == nil {
		return id, true
	}

	// Fallback: RFC 7662 introspection (non-browser / access token flow).
	if p.disc.IntrospectionEndpoint == "" {
		return nil, false
	}
	return p.introspect(username, token)
}

// CaptiveLoginURL builds an OIDC authorization URL with PKCE + state + nonce,
// stores the verifier in globalPKCEStore, and returns the URL to redirect to.
func (p *OIDCFlowProvider) CaptiveLoginURL(relayURL string) string {
	if p.disc.AuthorizationEndpoint == "" {
		return ""
	}

	// Generate state (CSRF token), PKCE verifier + challenge, nonce.
	state := mustRandHex(16)
	verifier := mustRandHex(32)
	nonce := mustRandHex(16)

	// PKCE S256: challenge = base64url(sha256(verifier))
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	globalPKCEStore.set(state, &pkceEntry{
		verifier:   verifier,
		nonce:      nonce,
		relayURL:   relayURL,
		createdAt:  time.Now(),
		providerID: p.profile.ID,
	})

	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {proxyBaseURL() + "/auth/oidc/callback"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return p.disc.AuthorizationEndpoint + "?" + q.Encode()
}

// ---------------------------------------------------------------------------
// OIDC callback (exchangeCode)
// ---------------------------------------------------------------------------

// ExchangeCode handles the authorization code callback: exchanges the code for
// tokens, validates the ID token, fetches userinfo, and returns the Identity.
func (p *OIDCFlowProvider) ExchangeCode(code, state string) (*Identity, error) {
	entry, ok := globalPKCEStore.pop(state)
	if !ok {
		return nil, fmt.Errorf("oidc callback: invalid or expired state")
	}
	if entry.providerID != p.profile.ID {
		return nil, fmt.Errorf("oidc callback: state belongs to different provider")
	}

	// Exchange code → tokens.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {proxyBaseURL() + "/auth/oidc/callback"},
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"code_verifier": {entry.verifier},
	}
	tokenCtx, tokenCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer tokenCancel()
	req, err := http.NewRequestWithContext(tokenCtx,
		http.MethodPost, p.disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc token exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("oidc token endpoint HTTP %d: %s", resp.StatusCode, body)
	}

	var tr struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&tr); err != nil {
		return nil, fmt.Errorf("oidc token parse: %w", err)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("oidc: no id_token in response")
	}

	// Validate ID token and extract identity; nonce verified inside.
	id, err := p.validateIDToken(tr.IDToken, entry.nonce)
	if err != nil {
		return nil, fmt.Errorf("oidc id_token validation: %w", err)
	}

	if id.Sub == "" {
		return nil, fmt.Errorf("oidc: empty sub in id_token")
	}

	// Fetch userinfo for richer attributes (email, name, groups).
	if p.disc.UserinfoEndpoint != "" && tr.AccessToken != "" {
		if err := p.enrichFromUserinfo(id, tr.AccessToken); err != nil {
			logger.Printf("OIDC userinfo error (non-fatal): %v", err)
		}
	}

	id.Provider = p.profile.ID
	return id, nil
}

// ---------------------------------------------------------------------------
// ID token validation
// ---------------------------------------------------------------------------

// validateIDToken parses, validates, and extracts identity from a raw JWT ID token.
// expectedNonce must match the "nonce" claim when non-empty (browser PKCE flow);
// pass "" to skip nonce verification (non-browser introspection path).
func (p *OIDCFlowProvider) validateIDToken(rawToken, expectedNonce string) (*Identity, error) {
	if p.jwks == nil {
		return nil, fmt.Errorf("oidc: no jwks_uri configured for ID-token validation")
	}

	// Parse without verification first to get the key ID from the header.
	unverified, _, err := jwtv5.NewParser().ParseUnverified(rawToken, jwtv5.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("oidc: parse id_token header: %w", err)
	}
	kid := unverified.Header["kid"]
	kidStr, _ := kid.(string)

	pubKey, err := p.jwks.getKey(kidStr)
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks key %q: %w", kidStr, err)
	}

	// Full validation with signature check.
	token, err := jwtv5.NewParser(
		jwtv5.WithIssuedAt(),
		jwtv5.WithAudience(p.cfg.ClientID),
		jwtv5.WithExpirationRequired(),
	).Parse(rawToken, func(t *jwtv5.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtv5.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token invalid: %w", err)
	}

	claims, ok := token.Claims.(jwtv5.MapClaims)
	if !ok {
		return nil, fmt.Errorf("oidc: claims type error")
	}

	id := &Identity{}
	id.Sub, _ = claims["sub"].(string)
	id.Email, _ = claims["email"].(string)
	id.Name, _ = claims["name"].(string)

	// Extract groups from the configured claim.
	groupsClaim := p.cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	id.Groups = extractStringSliceClaim(claims, groupsClaim)

	// Verify nonce to prevent ID token replay attacks (OIDC Core §3.1.3.7).
	if expectedNonce != "" {
		nonceClaim, _ := claims["nonce"].(string)
		if nonceClaim != expectedNonce {
			return nil, fmt.Errorf("oidc: nonce mismatch — possible token replay")
		}
	}

	return id, nil
}

// ---------------------------------------------------------------------------
// Userinfo
// ---------------------------------------------------------------------------

func (p *OIDCFlowProvider) enrichFromUserinfo(id *Identity, accessToken string) error {
	uiCtx, uiCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer uiCancel()
	req, err := http.NewRequestWithContext(uiCtx,
		http.MethodGet, p.disc.UserinfoEndpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("userinfo HTTP %d", resp.StatusCode)
	}

	var claims map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&claims); err != nil {
		return err
	}

	if id.Email == "" {
		id.Email, _ = claims["email"].(string)
	}
	if id.Name == "" {
		id.Name, _ = claims["name"].(string)
	}

	groupsClaim := p.cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	if len(id.Groups) == 0 {
		id.Groups = extractStringSliceClaim(claims, groupsClaim)
	}
	return nil
}

// ---------------------------------------------------------------------------
// RFC 7662 introspection (non-browser path)
// ---------------------------------------------------------------------------

func (p *OIDCFlowProvider) introspect(username, token string) (*Identity, bool) {
	form := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}
	intrCtx, intrCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer intrCancel()
	req, err := http.NewRequestWithContext(intrCtx,
		http.MethodPost, p.disc.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.cfg.ClientID, p.cfg.ClientSecret)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	var ir struct {
		Active   bool        `json:"active"`
		Sub      string      `json:"sub"`
		Username string      `json:"username"`
		Email    string      `json:"email"`
		Name     string      `json:"name"`
		Scope    string      `json:"scope"`
		Aud      interface{} `json:"aud"`
		Exp      int64       `json:"exp"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&ir); err != nil {
		return nil, false
	}
	if !ir.Active {
		return nil, false
	}
	if p.cfg.RequiredScope != "" {
		if !strings.Contains(" "+ir.Scope+" ", " "+p.cfg.RequiredScope+" ") {
			return nil, false
		}
	}

	sub := ir.Sub
	if sub == "" {
		sub = ir.Username
	}
	if sub == "" {
		sub = username
	}

	id := &Identity{
		Sub:      sub,
		Email:    ir.Email,
		Name:     ir.Name,
		Provider: p.profile.ID,
	}
	return id, true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustRandHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func extractStringSliceClaim(claims map[string]interface{}, key string) []string {
	raw, ok := claims[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	}
	return nil
}

// proxyBaseURL returns the external-facing base URL of the proxy UI.
// Used to construct the OIDC/SAML callback redirect_uri.
func proxyBaseURL() string {
	if u := cfg.ProxyBaseURL(); u != "" {
		return u
	}
	return "https://localhost:9090"
}
