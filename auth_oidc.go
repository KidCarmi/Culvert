package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

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
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
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

	id, ok, exp := a.introspect(token)
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
func (a *OIDCAuth) introspect(token string) (identity *Identity, active bool, tokenExp *int64) {
	body := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		a.cfg.IntrospectionURL,
		strings.NewReader(body.Encode()),
	)
	if err != nil {
		logger.Printf("OIDC introspect build error: %v", err)
		return nil, false, nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.cfg.ClientID, a.cfg.ClientSecret)

	resp, err := a.client.Do(req)
	if err != nil {
		logger.Printf("OIDC introspect request error: %v", err)
		return nil, false, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Printf("OIDC introspect HTTP %d", resp.StatusCode)
		return nil, false, nil
	}

	var ir introspectionResponse
	if err := decodeStrictJSON(resp.Body, 64<<10, &ir, false); err != nil {
		logger.Printf("OIDC introspect parse error: %v", err)
		return nil, false, nil
	}
	if !ir.Active {
		return nil, false, nil
	}
	tokenExp, validExp := parseDeclaredExpiry(ir.Exp)
	if !validExp {
		logger.Printf("OIDC: active token has invalid declared expiry")
		return nil, false, nil
	}

	// Optional scope check.
	if a.cfg.RequiredScope != "" {
		if !strings.Contains(" "+ir.Scope+" ", " "+a.cfg.RequiredScope+" ") {
			logger.Printf("OIDC: required scope %q not in %q", a.cfg.RequiredScope, ir.Scope)
			return nil, false, nil
		}
	}

	// Optional audience check.
	if a.cfg.RequiredAudience != "" && !audienceContains(ir.Audience, a.cfg.RequiredAudience) {
		logger.Printf("OIDC: required audience %q not present", a.cfg.RequiredAudience)
		return nil, false, nil
	}

	canonicalSub := ir.Sub
	if strings.TrimSpace(canonicalSub) == "" {
		canonicalSub = ir.Username
	}
	if strings.TrimSpace(canonicalSub) == "" {
		logger.Printf("OIDC: active token has no canonical sub or username claim")
		return nil, false, nil
	}
	return &Identity{
		Sub:      canonicalSub,
		Name:     strings.TrimSpace(ir.Username),
		Provider: a.Name(),
	}, true, tokenExp
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
	ttl := a.ttl
	if ok && tokenExp != nil {
		until := time.Unix(*tokenExp, 0).Sub(now)
		if until <= 0 {
			// An IdP may transiently report active=true at the expiry boundary,
			// but the declared token lifetime remains authoritative.
			identity = nil
			ok = false
		} else if until < ttl {
			ttl = until
		}
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

func cloneIdentity(id *Identity) *Identity {
	if id == nil {
		return nil
	}
	clone := *id
	clone.Groups = append([]string(nil), id.Groups...)
	return &clone
}
