package main

import (
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
	Active   bool   `json:"active"`
	Sub      string `json:"sub"`
	Username string `json:"username"`
	Scope    string `json:"scope"`
	Audience any    `json:"aud"` // string or []string per JWT spec
	Exp      int64  `json:"exp"`
}

type oidcCacheEntry struct {
	ok     bool
	expiry time.Time
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
	if cfg.TLSSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &OIDCAuth{
		cfg:   cfg,
		ttl:   ttl,
		client: &http.Client{Timeout: 10 * time.Second, Transport: transport},
		cache: map[string]*oidcCacheEntry{},
	}, nil
}

func (a *OIDCAuth) Name() string { return "oidc" }

// Verify treats the password field as an OAuth2 access token and introspects it.
// The username field is used only for logging.
func (a *OIDCAuth) Verify(username, token string) bool {
	if token == "" {
		return false
	}

	k := cacheKey(username, token)
	if ok, hit := a.oidcCacheGet(k); hit {
		return ok
	}

	ok, exp := a.introspect(token)
	a.oidcCacheSetWithExp(k, ok, exp)
	if ok {
		logger.Printf("OIDC auth OK: user=%s", sanitizeLog(username))
	} else {
		logger.Printf("OIDC auth FAIL: user=%s", sanitizeLog(username))
	}
	return ok
}

// introspect returns (active, exp) where exp is the Unix timestamp from the
// token's "exp" claim (0 if absent or not active).
func (a *OIDCAuth) introspect(token string) (bool, int64) {
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
		return false, 0
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.cfg.ClientID, a.cfg.ClientSecret)

	resp, err := a.client.Do(req)
	if err != nil {
		logger.Printf("OIDC introspect request error: %v", err)
		return false, 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Printf("OIDC introspect HTTP %d", resp.StatusCode)
		return false, 0
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false, 0
	}

	var ir introspectionResponse
	if err := json.Unmarshal(raw, &ir); err != nil {
		logger.Printf("OIDC introspect parse error: %v", err)
		return false, 0
	}
	if !ir.Active {
		return false, 0
	}

	// Optional scope check.
	if a.cfg.RequiredScope != "" {
		if !strings.Contains(" "+ir.Scope+" ", " "+a.cfg.RequiredScope+" ") {
			logger.Printf("OIDC: required scope %q not in %q", a.cfg.RequiredScope, ir.Scope)
			return false, 0
		}
	}

	// Optional audience check.
	if a.cfg.RequiredAudience != "" && !audienceContains(ir.Audience, a.cfg.RequiredAudience) {
		logger.Printf("OIDC: required audience %q not present", a.cfg.RequiredAudience)
		return false, 0
	}

	return true, ir.Exp
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

func (a *OIDCAuth) oidcCacheGet(key string) (ok, hit bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, found := a.cache[key]; found && time.Now().Before(e.expiry) {
		return e.ok, true
	}
	return false, false
}

// oidcCacheSetWithExp caps the cache TTL to min(CacheTTL, time.Until(tokenExp))
// so a cached "ok" entry never outlives the actual token expiry (MED-4).
func (a *OIDCAuth) oidcCacheSetWithExp(key string, ok bool, tokenExp int64) {
	ttl := a.ttl
	if tokenExp > 0 {
		if until := time.Until(time.Unix(tokenExp, 0)); until > 0 && until < ttl {
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
	a.cache[key] = &oidcCacheEntry{ok: ok, expiry: time.Now().Add(ttl)}
	a.mu.Unlock()
}
