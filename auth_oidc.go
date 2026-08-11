package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// errIntrospectClient marks a 4xx from the introspection endpoint — a
// client/token-side rejection, NOT an endpoint outage. It must never arm the
// unreachable cooldown, or an unauthenticated caller could trip the
// provider-wide gate with a single malformed token (CHAOS-47 review). See
// isIntrospectClientError and ResolveIdentity.
var errIntrospectClient = errors.New("introspection endpoint returned a 4xx (client/token error)")

// isIntrospectClientError reports whether a non-200 introspection status is a
// caller/config-side rejection (a 4xx an unauthenticated request can provoke)
// rather than a backend reachability problem. 429 (Too Many Requests) and 408
// (Request Timeout) are 4xx but are transient "back off / retry" signals, so
// they DO count as reachability failures and are allowed to arm the cooldown.
func isIntrospectClientError(code int) bool {
	if code == http.StatusTooManyRequests || code == http.StatusRequestTimeout {
		return false
	}
	return code >= 400 && code < 500
}

// OIDCConfig holds settings for OAuth2 / OIDC token-introspection auth.
//
// How it works for proxy authentication:
//
//	The client places an access token in the proxy password field:
//	  Proxy-Authorization: Basic base64(username:access_token)
//	Culvert calls the IDP's introspection endpoint (RFC 7662) to verify
//	the token, and optionally checks that a required scope/audience is present.
//
// Compatible IDPs: Okta, Azure AD, Keycloak, Auth0, any RFC 7662 IDP.
type OIDCConfig struct {
	// IntrospectionURL is the RFC 7662 token introspection endpoint.
	// Okta:     "https://your-domain.okta.com/oauth2/default/v1/introspect"
	// Azure AD: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/introspect"
	// Keycloak: "https://keycloak.host/realms/{realm}/protocol/openid-connect/token/introspect"
	IntrospectionURL string `yaml:"introspection_url"`

	// ClientID / ClientSecret authenticate the introspection request itself.
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`

	// RequiredScope is a space-separated scope that must appear in the token.
	// Example: "proxy:access". Empty = no scope check.
	RequiredScope string `yaml:"required_scope"`

	// RequiredAudience is an optional audience ("aud") claim check.
	RequiredAudience string `yaml:"required_audience"`

	// CacheTTL is how long an introspection result is cached (default 2 min).
	// Keep short — tokens can be revoked at the IDP at any time.
	CacheTTL time.Duration `yaml:"cache_ttl"`

	// TLSSkipVerify disables certificate verification (dev/test only).
	TLSSkipVerify bool `yaml:"tls_skip_verify"`

	// LoginURL is the OIDC authorization endpoint where unauthenticated
	// browser requests are redirected (captive portal).
	// Example (Okta): "https://your-domain.okta.com/oauth2/default/v1/authorize"
	// Leave empty to disable browser redirect (return 407 instead).
	LoginURL string `yaml:"login_url"`
}

// introspectionResponse is the RFC 7662 JSON payload.
type introspectionResponse struct {
	Active   bool            `json:"active"`
	Sub      string          `json:"sub"`
	Username string          `json:"username"`
	Scope    string          `json:"scope"`
	Audience any             `json:"aud"` // string or []string per JWT spec
	Exp      json.RawMessage `json:"exp,omitempty"`
}

// parseDeclaredExpiry distinguishes an omitted RFC 7662 exp claim from every
// explicitly present representation. Present values must be numeric int64 Unix
// seconds; null, strings, fractions, and out-of-range numbers fail closed.
func parseDeclaredExpiry(raw json.RawMessage) (*int64, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, false
	}
	var exp int64
	if err := json.Unmarshal(raw, &exp); err != nil {
		return nil, false
	}
	return &exp, true
}

// decodeStrictJSON rejects oversized bodies, trailing garbage, and additional
// JSON values. useNumber preserves exact number lexemes for security-sensitive
// claims such as RFC 7662 exp.
func decodeStrictJSON(r io.Reader, limit int64, dst any, useNumber bool) error {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return fmt.Errorf("JSON body exceeds %d bytes", limit)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if useNumber {
		decoder.UseNumber()
	}
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

type oidcCacheEntry struct {
	ok       bool
	identity *Identity
	expiry   time.Time
}

// OIDCAuth verifies proxy credentials via RFC 7662 token introspection.
type OIDCAuth struct {
	cfg    OIDCConfig
	ttl    time.Duration
	client *http.Client
	mu     sync.Mutex
	cache  map[string]*oidcCacheEntry // key = cacheKey("", token)

	// gate arms when the IdP is unreachable, so an outage denies without
	// re-introspecting and recovers on one probe (CHAOS-47,
	// auth_backend_health.go).
	gate authProbeGate
}

// NewOIDCAuth validates the config and returns a ready-to-use OIDCAuth.
func NewOIDCAuth(cfg OIDCConfig) (*OIDCAuth, error) {
	if cfg.IntrospectionURL == "" {
		return nil, fmt.Errorf("oidc: introspection_url is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc: client_id is required")
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = ssrfSafeDialContext // SSRF guard at dial level (RISK-002): the admin-configured IntrospectURL is reached per-request
	if cfg.TLSSkipVerify {
		logWarnf("OIDC introspection: TLS certificate verification DISABLED (tls_skip_verify) — credentials traverse an unverified channel vulnerable to MITM; intended for self-signed dev IdPs only") // RISK-009
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}                                                                                                                               // #nosec G402 -- InsecureSkipVerify is config-guarded by cfg.TLSSkipVerify
	}
	return &OIDCAuth{
		cfg:    cfg,
		ttl:    ttl,
		client: &http.Client{Timeout: 10 * time.Second, Transport: transport},
		cache:  map[string]*oidcCacheEntry{},
	}, nil
}

func (a *OIDCAuth) Name() string { return "oidc" }

// Verify treats the password field as an OAuth2 access token and introspects it.
func (a *OIDCAuth) Verify(username, token string) bool {
	_, ok := a.ResolveIdentity(username, token)
	return ok
}

// ResolveIdentity binds authorization identity exclusively to claims returned
// by the introspection endpoint. The Basic username is an untrusted transport
// hint and is never used as the authenticated subject.
func (a *OIDCAuth) ResolveIdentity(_ string, token string) (*Identity, bool) {
	if token == "" {
		return nil, false
	}

	// A bearer token has one canonical identity regardless of which Basic
	// username accompanies it, so cache by token only.
	k := cacheKey("", token)
	if id, ok, hit := a.oidcIdentityCacheGet(k); hit {
		return id, ok
	}

	if !a.gate.allow() {
		// IdP is in its unreachable cooldown — deny without another round trip
		// (CHAOS-47). Fail-closed posture unchanged; the difference is that
		// nothing about this denial is remembered.
		noteAuthBackendGatedDenial()
		return nil, false
	}

	id, ok, exp, err := a.introspect(token)
	if err != nil {
		if errors.Is(err, errIntrospectClient) {
			// A 4xx is a client/token-side rejection, not a backend outage: deny
			// THIS request closed but do NOT record an outage or arm the cooldown,
			// so a malformed token cannot trip the provider-wide gate for everyone
			// else. Not cached — a 4xx may reflect a fixable client-credential
			// misconfiguration rather than a stable verdict about the token.
			//
			// The endpoint returned an HTTP status, so it is demonstrably up, and
			// that must CLEAR a cooldown a previous outage armed rather than merely
			// avoid arming one. Otherwise the 4xx silently eats each half-open probe
			// and the gate re-arms behind it, letting a caller with one malformed
			// token hold a recovered IdP in a permanent outage for every other user.
			// (Found by Codex review on PR #1077; same defect fixed on the LDAP leg
			// in noteVerifyError.)
			a.gate.recordReachable()
			noteAuthBackendReachable("oidc")
			logger.Printf("OIDC auth DENY (introspection 4xx) — client/token error, not a backend outage; " +
				"the endpoint answered, so any cooldown is cleared")
			return nil, false
		}
		// Could not reach the IdP, or it did not answer coherently. Deny this
		// request, but never cache it: a cached infrastructure failure keeps
		// denying a valid token for the full TTL after the IdP recovers.
		a.gate.recordUnavailable()
		noteAuthBackendUnavailable("oidc", err.Error())
		logger.Printf("OIDC auth UNAVAILABLE (introspection endpoint unreachable) — failing closed, not cached")
		return nil, false
	}
	a.gate.recordReachable()
	noteAuthBackendReachable("oidc")

	id, ok = a.oidcCacheSetIdentityWithExp(k, id, ok, exp)
	if ok {
		logger.Printf("OIDC auth OK: subject=%q", sanitizeLog(id.Sub))
	} else {
		logger.Printf("OIDC auth FAIL")
	}
	return id, ok
}

// CaptiveLoginURL implements IdentityProvider for the legacy OIDC backend.
func (a *OIDCAuth) CaptiveLoginURL(_ string, _ *http.Request) string {
	return a.cfg.LoginURL
}

// introspect returns the canonical token identity and its Unix expiry.
//
// The returned error is reserved for INFRASTRUCTURE failure — the introspection
// endpoint could not be reached, or did not answer coherently. `(nil, false,
// nil, nil)` means the endpoint answered and the answer was "this token is not
// valid". Only the latter is cacheable (CHAOS-47); see ResolveIdentity.
//
// RFC 7662 is what makes the split clean: an inactive token is reported as HTTP
// 200 with `active:false`, so ANY non-200 is a problem with the endpoint or our
// client credentials — never a verdict about the caller's token.
func (a *OIDCAuth) introspect(token string) (identity *Identity, active bool, tokenExp *int64, err error) {
	body := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}
	req, reqErr := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		a.cfg.IntrospectionURL,
		strings.NewReader(body.Encode()),
	)
	if reqErr != nil {
		logger.Printf("OIDC introspect build error: %v", reqErr)
		return nil, false, nil, fmt.Errorf("build request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.cfg.ClientID, a.cfg.ClientSecret)

	resp, doErr := a.client.Do(req)
	if doErr != nil {
		logger.Printf("OIDC introspect request error: %v", doErr)
		return nil, false, nil, fmt.Errorf("introspection request: %w", doErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Printf("OIDC introspect HTTP %d", resp.StatusCode)
		if isIntrospectClientError(resp.StatusCode) {
			// A 4xx is a client/token-side rejection, not an endpoint outage —
			// classifying it as one would let an unauthenticated caller arm the
			// provider-wide unreachable cooldown with one malformed token. Fail
			// this request closed via a distinguishable error; the caller does not
			// gate on it.
			return nil, false, nil, fmt.Errorf("%w: HTTP %d", errIntrospectClient, resp.StatusCode)
		}
		return nil, false, nil, fmt.Errorf("introspection endpoint returned HTTP %d", resp.StatusCode)
	}

	var ir introspectionResponse
	if decErr := decodeStrictJSON(resp.Body, 64<<10, &ir, false); decErr != nil {
		logger.Printf("OIDC introspect parse error: %v", decErr)
		return nil, false, nil, fmt.Errorf("introspection response: %w", decErr)
	}
	// From here on the endpoint has answered coherently: every remaining
	// branch is an authoritative verdict about the token, and therefore
	// cacheable.
	if !ir.Active {
		return nil, false, nil, nil
	}
	tokenExp, validExp := parseDeclaredExpiry(ir.Exp)
	if !validExp {
		logger.Printf("OIDC: active token has invalid declared expiry")
		return nil, false, nil, nil
	}

	// Optional scope check.
	if a.cfg.RequiredScope != "" {
		if !strings.Contains(" "+ir.Scope+" ", " "+a.cfg.RequiredScope+" ") {
			logger.Printf("OIDC: required scope %q not in %q", a.cfg.RequiredScope, ir.Scope)
			return nil, false, nil, nil
		}
	}

	// Optional audience check.
	if a.cfg.RequiredAudience != "" && !audienceContains(ir.Audience, a.cfg.RequiredAudience) {
		logger.Printf("OIDC: required audience %q not present", a.cfg.RequiredAudience)
		return nil, false, nil, nil
	}

	canonicalSub := ir.Sub
	if strings.TrimSpace(canonicalSub) == "" {
		canonicalSub = ir.Username
	}
	if strings.TrimSpace(canonicalSub) == "" {
		logger.Printf("OIDC: active token has no canonical sub or username claim")
		return nil, false, nil, nil
	}
	return &Identity{
		Sub:      canonicalSub,
		Name:     strings.TrimSpace(ir.Username),
		Provider: a.Name(),
	}, true, tokenExp, nil
}

// audienceContains handles both string and []string JWT aud claims.
func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func (a *OIDCAuth) oidcIdentityCacheGet(key string) (identity *Identity, ok, hit bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, found := a.cache[key]; found && time.Now().Before(e.expiry) {
		return cloneIdentity(e.identity), e.ok, true
	}
	return nil, false, false
}

func (a *OIDCAuth) oidcCacheSetIdentityWithExp(key string, identity *Identity, ok bool, tokenExp *int64) (*Identity, bool) {
	// A positive cache entry must always carry the canonical identity needed by
	// ResolveIdentity. Fail closed if an internal caller violates that invariant.
	if ok && (identity == nil || strings.TrimSpace(identity.Sub) == "") {
		identity = nil
		ok = false
	}
	now := time.Now()
	ttl, stillValid := clampCacheTTLToTokenExpiry(a.ttl, tokenExp, now)
	if ok && !stillValid {
		// An IdP may transiently report active=true at the expiry boundary,
		// but the declared token lifetime remains authoritative.
		identity = nil
		ok = false
	}
	a.mu.Lock()
	// Evict a random entry when the cache is full to prevent unbounded growth.
	if len(a.cache) >= maxAuthCacheSize {
		for k := range a.cache {
			delete(a.cache, k)
			break
		}
	}
	a.cache[key] = &oidcCacheEntry{ok: ok, identity: cloneIdentity(identity), expiry: now.Add(ttl)}
	a.mu.Unlock()
	return cloneIdentity(identity), ok
}

// clampCacheTTLToTokenExpiry bounds a positive cache entry by the token's own
// declared lifetime, so a cached "yes" can never outlive the credential it was
// derived from. It reports stillValid=false when the token has already expired,
// which the caller must turn into a denial.
//
// Shared by both introspection backends (auth_oidc.go and the IdP-registry
// provider in auth_oidc_flow.go) — the rule is a property of RFC 7662 tokens,
// not of either backend.
func clampCacheTTLToTokenExpiry(ttl time.Duration, tokenExp *int64, now time.Time) (bounded time.Duration, stillValid bool) {
	if tokenExp == nil {
		return ttl, true
	}
	until := time.Unix(*tokenExp, 0).Sub(now)
	if until <= 0 {
		return ttl, false
	}
	if until < ttl {
		return until, true
	}
	return ttl, true
}

func cloneIdentity(id *Identity) *Identity {
	if id == nil {
		return nil
	}
	clone := *id
	clone.Groups = append([]string(nil), id.Groups...)
	return &clone
}
