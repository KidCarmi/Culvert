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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/KidCarmi/Culvert/internal/authstate"
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
//
// Two of its fields exist only to bound failure (CHAOS-49):
//
//   - lastAttempt bounds the refresh RATE, not its freshness. The `kid` that
//     drives a cache miss is read from an UNVERIFIED token header, so it is
//     attacker-controlled and reachable without any credential. Keying the
//     refetch decision on cache membership alone turned one unauthenticated
//     request into one outbound JWKS GET, per configured provider, forever —
//     an amplifier pointed at the customer's own IdP. lastAttempt advances on
//     every attempt (success or failure) so an unknown kid costs at most one
//     fetch per jwksMinRefreshInterval.
//
//   - refreshing/refreshDone coalesce concurrent misses. Without them a burst
//     of N simultaneous requests carrying the same unknown kid produced N
//     simultaneous fetches, which is precisely the shape of a reconnect storm.
type jwksCache struct {
	mu          sync.RWMutex
	keys        map[string]interface{} // kid → *rsa.PublicKey or *ecdsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
	jwksURI     string
	client      *http.Client

	// single-flight state, guarded by mu
	refreshing  bool
	refreshDone chan struct{}
	refreshErr  error

	logAt time.Time // rate-limits the refresh-failure log line
}

const (
	jwksCacheTTL = 15 * time.Minute

	// jwksMinRefreshInterval is the floor between two refresh ATTEMPTS. It
	// bounds both the amplification described above and the retry rate against
	// a struggling IdP. It must stay well under jwksCacheTTL so a genuine key
	// rotation is still picked up promptly.
	jwksMinRefreshInterval = time.Minute

	// jwksFetchTimeout bounds a single key-set fetch.
	jwksFetchTimeout = 10 * time.Second
)

// errJWKSThrottled is returned when a refresh was suppressed by the negative
// window. It is a deny for this lookup, never a statement about the IdP.
var errJWKSThrottled = errors.New("jwks: refresh throttled (recent attempt)")

// getKey returns the public key for kid, refreshing the cache when stale.
func (j *jwksCache) getKey(kid string) (interface{}, error) {
	j.mu.RLock()
	k, ok := j.keys[kid]
	stale := time.Since(j.fetchedAt) > jwksCacheTTL
	j.mu.RUnlock()

	if ok && !stale {
		return k, nil
	}

	// Re-fetch, rate-limited and single-flighted.
	if err := j.refreshOnce(); err != nil {
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

// refreshOnce runs at most one refresh per jwksMinRefreshInterval and lets
// concurrent callers share a single in-flight fetch.
//
// The leader publishes its error to followers rather than letting them return
// success on an empty cache, so a failed refresh produces one diagnosable
// reason for every caller instead of N "key not found"s.
func (j *jwksCache) refreshOnce() error {
	j.mu.Lock()
	if j.refreshing {
		done := j.refreshDone
		j.mu.Unlock()
		<-done
		j.mu.RLock()
		err := j.refreshErr
		j.mu.RUnlock()
		return err
	}
	if !j.lastAttempt.IsZero() && time.Since(j.lastAttempt) < jwksMinRefreshInterval {
		j.mu.Unlock()
		return errJWKSThrottled
	}
	j.refreshing = true
	j.refreshDone = make(chan struct{})
	j.lastAttempt = time.Now()
	done := j.refreshDone
	j.mu.Unlock()

	err := j.refresh()

	j.mu.Lock()
	j.refreshing = false
	j.refreshDone = nil
	j.refreshErr = err
	doLog := err != nil && (j.logAt.IsZero() || time.Since(j.logAt) >= jwksMinRefreshInterval)
	if doLog {
		j.logAt = time.Now()
	}
	j.mu.Unlock()
	close(done)

	if doLog && logger != nil {
		// Serving the previously cached keys is the correct degradation here,
		// but it is degradation: without a line, a JWKS endpoint that has been
		// broken for hours is indistinguishable from a healthy one.
		logger.Printf("OIDC: JWKS refresh FAILED for %q — serving previously cached keys: %v",
			sanitizeLog(j.jwksURI), err)
	}
	return err
}

func (j *jwksCache) refresh() error {
	ctx, cancel := context.WithTimeout(context.Background(), jwksFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.jwksURI, http.NoBody)
	if err != nil {
		return fmt.Errorf("jwks request: %w", err)
	}
	resp, err := j.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()

	// A non-200 is not a key set. Decoding one anyway is how an HTTP 503 whose
	// body happens to be JSON ("{"error":...}") became an empty key map that
	// overwrote every good key in the cache.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch: HTTP %d", resp.StatusCode)
	}

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

	// A response carrying no usable key is not evidence that the IdP has no
	// keys — it is evidence that something is wrong with the response (an edge
	// stub, a rate-limiter body, a rotation to key types this build cannot
	// parse). Installing it destroys the cache AND the stale-key fallback that
	// exists to survive exactly this, so every ID-token validation fails until
	// a good refresh lands. Keep what we have and fail the lookup closed.
	if len(keys) == 0 {
		return fmt.Errorf("jwks fetch: response carried no usable keys (keeping cached key set)")
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
	verifier   string
	nonce      string
	relayURL   string
	providerID string
}

// pkceStore is the bounded, fair-share store for in-flight OIDC authorization
// requests (verifier + nonce + return target), keyed by the `state` token.
//
// Entries are minted SPECULATIVELY for clients that have not authenticated —
// resolveCaptivePortalURL does it on the proxy's no-credentials path, and the
// public /auth/select page does it per render — so the store's eviction policy
// decides whether an anonymous flood can destroy other users' in-flight login
// state. It cannot: see internal/authstate.
type pkceStore = authstate.Store[*pkceEntry]

const pkceEntryTTL = 10 * time.Minute
const pkceStoreMax = 1000

var globalPKCEStore = newPKCEStore()

func newPKCEStore() *pkceStore {
	return authstate.New[*pkceEntry](pkceEntryTTL, pkceStoreMax)
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

	// ── Introspection result cache + availability gate (CHAOS-49) ────────────
	//
	// The registry path authenticates on EVERY proxied request, and the
	// dispatch loop in proxy.go asks every enabled provider in turn. Without a
	// cache that is one RFC 7662 round trip per request per provider; without a
	// gate, an IdP outage is one 10 s dial timeout per request per provider,
	// serialized, while the request goroutine is held. The legacy single-provider
	// backend (auth_oidc.go) has had both since CHAOS-47 — this is the same
	// contract on the newer surface, reusing the same primitives.
	mu    sync.Mutex
	cache map[string]*oidcCacheEntry // key = cacheKey("", token)
	ttl   time.Duration
	gate  authProbeGate
}

// oidcFlowCacheTTL matches the legacy backend's default: short, because a token
// can be revoked at the IdP at any moment and this cache is what delays the
// proxy noticing.
const oidcFlowCacheTTL = 2 * time.Minute

func (p *OIDCFlowProvider) cacheTTL() time.Duration {
	if p.ttl > 0 {
		return p.ttl
	}
	return oidcFlowCacheTTL
}

// introspectCacheGet returns a cached verdict, if one is live.
func (p *OIDCFlowProvider) introspectCacheGet(key string) (identity *Identity, ok, hit bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, found := p.cache[key]; found && time.Now().Before(e.expiry) {
		return cloneIdentity(e.identity), e.ok, true
	}
	return nil, false, false
}

// introspectCacheSet records an AUTHORITATIVE verdict. Infrastructure failures
// never reach here — see ResolveIdentity.
func (p *OIDCFlowProvider) introspectCacheSet(key string, identity *Identity, ok bool, tokenExp *int64) (*Identity, bool) {
	if ok && (identity == nil || strings.TrimSpace(identity.Sub) == "") {
		identity = nil
		ok = false
	}
	now := time.Now()
	ttl, stillValid := clampCacheTTLToTokenExpiry(p.cacheTTL(), tokenExp, now)
	if ok && !stillValid {
		identity = nil
		ok = false
	}
	p.mu.Lock()
	if p.cache == nil {
		p.cache = map[string]*oidcCacheEntry{}
	}
	// Evict an arbitrary entry when full — the key space is token-derived and
	// therefore caller-controlled, so the map must stay bounded.
	if len(p.cache) >= maxAuthCacheSize {
		for k := range p.cache {
			delete(p.cache, k)
			break
		}
	}
	p.cache[key] = &oidcCacheEntry{ok: ok, identity: cloneIdentity(identity), expiry: now.Add(ttl)}
	p.mu.Unlock()
	return cloneIdentity(identity), ok
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
		logWarnf("OIDC flow [%s]: TLS certificate verification DISABLED (tls_skip_verify) — credentials traverse an unverified channel vulnerable to MITM; intended for self-signed dev IdPs only", sanitizeLog(p.ID)) // RISK-009
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}                                                                                                                                              // #nosec G402 -- InsecureSkipVerify is an explicit admin opt-in via cfg.TLSSkipVerify (warned above)
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
		cache:   map[string]*oidcCacheEntry{},
		ttl:     oidcFlowCacheTTL,
	}
	if disc.JWKsURI != "" {
		prov.jwks = &jwksCache{jwksURI: disc.JWKsURI, client: client, keys: make(map[string]interface{})}
	}
	return prov, nil
}

func (p *OIDCFlowProvider) Name() string { return "oidc:" + p.profile.ID }

// DisplayName returns the admin-configured label shown to end users (e.g. on
// the IdP selection screen), falling back to the machine key if unset.
func (p *OIDCFlowProvider) DisplayName() string {
	if p.profile.Name != "" {
		return p.profile.Name
	}
	return p.Name()
}

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
		if id.Sub == "" {
			return nil, false // reject empty subject
		}
		return id, true
	}

	// Fallback: RFC 7662 introspection (non-browser / access token flow).
	if p.disc.IntrospectionEndpoint == "" {
		return nil, false
	}
	return p.resolveByIntrospection(token)
}

// resolveByIntrospection is the cached, gated, observable introspection path
// (CHAOS-49). It mirrors OIDCAuth.ResolveIdentity exactly, including the rule
// that makes the whole thing safe: only an AUTHORITATIVE answer from a reachable
// endpoint is cacheable. A failure to REACH the IdP denies this request and is
// then forgotten, so a one-second IdP blip cannot keep denying valid tokens for
// the full cache TTL after the IdP is healthy again.
func (p *OIDCFlowProvider) resolveByIntrospection(token string) (*Identity, bool) {
	backend := p.Name()

	// A bearer token has one canonical identity regardless of which Basic
	// username accompanies it, so cache by token only. cacheKey HMACs the input,
	// so no bearer token is held in the map.
	k := cacheKey("", token)
	if id, ok, hit := p.introspectCacheGet(k); hit {
		return id, ok
	}

	if !p.gate.allow() {
		// The IdP is in its unreachable cooldown — deny without another round
		// trip. This is what collapses "N providers × 10 s dial timeout on
		// every request" back to a constant during an outage.
		noteAuthBackendGatedDenial()
		return nil, false
	}

	id, ok, exp, err := p.introspect(token)
	if err != nil {
		if errors.Is(err, errIntrospectClient) {
			// A 4xx is a client/token-side rejection, not an outage. It must not
			// arm the provider-wide gate — otherwise one caller with a malformed
			// token locks out every other user. And because the endpoint
			// demonstrably answered, it must CLEAR a cooldown a previous outage
			// armed, rather than silently eating each half-open probe.
			p.gate.recordReachable()
			noteAuthBackendReachable(backend)
			logger.Printf("OIDC[%s] auth DENY (introspection 4xx) — client/token error, not a backend outage; "+
				"the endpoint answered, so any cooldown is cleared", sanitizeLog(p.profile.ID))
			return nil, false
		}
		p.gate.recordUnavailable()
		noteAuthBackendUnavailable(backend, err.Error())
		logger.Printf("OIDC[%s] auth UNAVAILABLE (introspection endpoint unreachable) — failing closed, not cached",
			sanitizeLog(p.profile.ID))
		return nil, false
	}
	p.gate.recordReachable()
	noteAuthBackendReachable(backend)

	return p.introspectCacheSet(k, id, ok, exp)
}

// CaptiveLoginURL builds an OIDC authorization URL with PKCE + state + nonce,
// stores the verifier in globalPKCEStore, and returns the URL to redirect to.
func (p *OIDCFlowProvider) CaptiveLoginURL(relayURL string, r *http.Request) string {
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

	// Attributed to the requesting client so a flood from one source can only
	// evict its own in-flight state, never another user's mid-login entry.
	globalPKCEStore.Set(state, authStateClientKey(r), &pkceEntry{
		verifier:   verifier,
		nonce:      nonce,
		relayURL:   relayURL,
		providerID: p.profile.ID,
	})

	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {proxyBaseURL(r) + "/auth/oidc/callback"},
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
func (p *OIDCFlowProvider) ExchangeCode(r *http.Request, code, state string) (*Identity, error) {
	entry, ok := globalPKCEStore.Pop(state)
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
		"redirect_uri":  {proxyBaseURL(r) + "/auth/oidc/callback"},
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

	// Full validation with signature check. The issuer claim is pinned to
	// the discovery document's issuer (OIDC Core §3.1.3.7 step 2): without
	// it, a token minted by a different issuer that shares the same JWKS —
	// e.g. another tenant of a multi-tenant IdP — would be accepted.
	opts := []jwtv5.ParserOption{
		jwtv5.WithIssuedAt(),
		jwtv5.WithAudience(p.cfg.ClientID),
		jwtv5.WithExpirationRequired(),
		jwtv5.WithLeeway(60 * time.Second), // tolerate clock skew between IdP and proxy
	}
	if p.disc.Issuer != "" {
		opts = append(opts, jwtv5.WithIssuer(p.disc.Issuer))
	}
	token, err := jwtv5.NewParser(opts...).Parse(rawToken, func(t *jwtv5.Token) (interface{}, error) {
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

// introspect returns the canonical token identity and its declared Unix expiry.
//
// The returned error is reserved for INFRASTRUCTURE failure — the endpoint could
// not be reached, or did not answer coherently. `(nil, false, nil, nil)` means
// the endpoint answered and the answer was "this token is not valid". Only the
// latter is cacheable; see resolveByIntrospection.
//
// RFC 7662 is what makes the split clean: an inactive token is reported as HTTP
// 200 with `active:false`, so ANY non-200 is a problem with the endpoint or our
// client credentials — never a verdict about the caller's token.
func (p *OIDCFlowProvider) introspect(token string) (identity *Identity, active bool, tokenExp *int64, err error) {
	form := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}
	intrCtx, intrCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer intrCancel()
	req, reqErr := http.NewRequestWithContext(intrCtx,
		http.MethodPost, p.disc.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if reqErr != nil {
		return nil, false, nil, fmt.Errorf("build request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.cfg.ClientID, p.cfg.ClientSecret)

	resp, doErr := p.client.Do(req)
	if doErr != nil {
		return nil, false, nil, fmt.Errorf("introspection request: %w", doErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if isIntrospectClientError(resp.StatusCode) {
			return nil, false, nil, fmt.Errorf("%w: HTTP %d", errIntrospectClient, resp.StatusCode)
		}
		// A 401 is a provider-wide client-credential fault, not a token verdict —
		// it arms the gate and is reported as an outage. See isIntrospectClientError.
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, false, nil, fmt.Errorf("%w", errIntrospectClientAuth)
		}
		return nil, false, nil, fmt.Errorf("introspection endpoint returned HTTP %d", resp.StatusCode)
	}

	var claims map[string]interface{}
	if decErr := decodeStrictJSON(resp.Body, 64<<10, &claims, true); decErr != nil {
		return nil, false, nil, fmt.Errorf("introspection response: %w", decErr)
	}
	// From here on the endpoint has answered coherently: every remaining branch
	// is an authoritative verdict about the token, and therefore cacheable.
	id, exp, ok := p.identityFromIntrospectionClaims(claims)
	return id, ok, exp, nil
}

func (p *OIDCFlowProvider) identityFromIntrospectionClaims(claims map[string]interface{}) (*Identity, *int64, bool) {
	active, _ := claims["active"].(bool)
	if !active {
		return nil, nil, false
	}
	var tokenExp *int64
	if rawExp, present := claims["exp"]; present {
		expNumber, numeric := rawExp.(json.Number)
		if !numeric {
			return nil, nil, false
		}
		exp, valid := parseDeclaredExpiry(json.RawMessage(expNumber.String()))
		if !valid || exp == nil || *exp <= time.Now().Unix() {
			return nil, nil, false
		}
		tokenExp = exp
	}
	scope, _ := claims["scope"].(string)
	if p.cfg.RequiredScope != "" {
		if !strings.Contains(" "+scope+" ", " "+p.cfg.RequiredScope+" ") {
			return nil, nil, false
		}
	}
	if p.cfg.RequiredAudience != "" && !audienceContains(claims["aud"], p.cfg.RequiredAudience) {
		return nil, nil, false
	}

	sub, _ := claims["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		sub, _ = claims["username"].(string)
	}
	if strings.TrimSpace(sub) == "" {
		return nil, nil, false
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	groupsClaim := p.cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	id := &Identity{
		Sub:      sub,
		Email:    email,
		Name:     name,
		Groups:   extractStringSliceClaim(claims, groupsClaim),
		Provider: p.profile.ID,
	}
	return id, tokenExp, true
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
//
// Priority: (1) explicit base_url config, (2) derive from request Host header,
// (3) fall back to https://localhost:9090.
//
// X-Forwarded-* headers are only trusted when trust_forwarded_headers is enabled
// (prevents host header injection when directly exposed to the internet).
func proxyBaseURL(r *http.Request) string {
	if u := cfg.ProxyBaseURL(); u != "" {
		return u
	}
	if r != nil {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		host := r.Host
		if trustForwardedHeaders {
			if fp := r.Header.Get("X-Forwarded-Proto"); fp == "http" || fp == "https" {
				scheme = fp
			}
			if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
				host = fh
			}
		}
		return scheme + "://" + host
	}
	return "https://localhost:9090"
}
