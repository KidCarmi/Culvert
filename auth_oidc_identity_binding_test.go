package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func installLegacyOIDCTestProvider(t *testing.T, provider *OIDCAuth) {
	t.Helper()
	cfg.mu.RLock()
	previousProvider := cfg.provider
	cfg.mu.RUnlock()
	cfg.SetProvider(provider)
	originalRegistry := idpRegistry
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}
	t.Cleanup(func() {
		cfg.SetProvider(previousProvider)
		idpRegistry = originalRegistry
	})
}

func legacyOIDCTestRequest(username, token string) *http.Request {
	credentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + token))
	r := httptest.NewRequestWithContext(context.Background(), "GET", "http://example.com/", http.NoBody)
	r.Header.Set("Proxy-Authorization", "Basic "+credentials)
	return r
}

func TestOIDCAuth_ResolveIdentityBindsCanonicalTokenSubject(t *testing.T) {
	srv, provider := mockIDP(t, introspectionResponse{
		Active:   true,
		Sub:      "canonical-subject",
		Username: "token-login",
	})
	defer srv.Close()

	id, ok := provider.ResolveIdentity("caller-controlled", "valid-token")
	if !ok || id == nil {
		t.Fatalf("ResolveIdentity failed: ok=%v id=%+v", ok, id)
	}
	if id.Sub != "canonical-subject" {
		t.Fatalf("identity subject = %q, want canonical token sub", id.Sub)
	}
	if id.Provider != "oidc" {
		t.Fatalf("identity provider = %q, want oidc", id.Provider)
	}
}

func TestOIDCAuth_ResolveIdentityFallsBackToTokenUsername(t *testing.T) {
	srv, provider := mockIDP(t, introspectionResponse{Active: true, Username: "token-login"})
	defer srv.Close()

	id, ok := provider.ResolveIdentity("caller-controlled", "valid-token")
	if !ok || id == nil || id.Sub != "token-login" {
		t.Fatalf("ResolveIdentity = (%+v, %v), want token username", id, ok)
	}
}

func TestOIDCAuth_ResolveIdentityRejectsTokenWithoutCanonicalIdentity(t *testing.T) {
	srv, provider := mockIDP(t, introspectionResponse{Active: true})
	defer srv.Close()

	if id, ok := provider.ResolveIdentity("caller-controlled", "valid-token"); ok || id != nil {
		t.Fatalf("ResolveIdentity = (%+v, %v), want rejection", id, ok)
	}
}

func TestOIDCAuth_ResolveIdentityRejectsExplicitNonFutureExpiry(t *testing.T) {
	for name, exp := range map[string]int64{
		"past":     time.Now().Add(-time.Minute).Unix(),
		"zero":     0,
		"negative": -1,
	} {
		t.Run(name, func(t *testing.T) {
			srv, provider := mockIDP(t, introspectionResponse{
				Active: true,
				Sub:    "expired-subject",
				Exp:    json.RawMessage(strconv.FormatInt(exp, 10)),
			})
			defer srv.Close()

			if id, ok := provider.ResolveIdentity("caller-controlled", "expired-token"); ok || id != nil {
				t.Fatalf("ResolveIdentity = (%+v, %v), want rejection of active token with exp=%d", id, ok, exp)
			}
		})
	}
}

func TestOIDCAuth_ResolveIdentityRejectsPresentInvalidExpiry(t *testing.T) {
	for name, rawExp := range map[string]string{
		"null":         "null",
		"string":       `"123"`,
		"fraction":     "123.5",
		"out-of-range": "9223372036854775808",
	} {
		t.Run(name, func(t *testing.T) {
			allowLoopbackSSRF(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"active":true,"sub":"invalid-exp-subject","exp":`+rawExp+`}`)
			}))
			defer srv.Close()
			provider, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "client"})
			if err != nil {
				t.Fatalf("NewOIDCAuth: %v", err)
			}
			if id, ok := provider.ResolveIdentity("caller-controlled", "invalid-exp-token"); ok || id != nil {
				t.Fatalf("ResolveIdentity = (%+v, %v), want rejection of present exp=%s", id, ok, rawExp)
			}
		})
	}
}

func TestOIDCAuth_CacheIsTokenBoundNotCallerBound(t *testing.T) {
	srv, provider := mockIDP(t, introspectionResponse{Active: true, Sub: "canonical-subject"})
	defer srv.Close()

	first, ok := provider.ResolveIdentity("first-claim", "shared-token")
	if !ok {
		t.Fatal("first ResolveIdentity failed")
	}
	second, ok := provider.ResolveIdentity("second-claim", "shared-token")
	if !ok {
		t.Fatal("second ResolveIdentity failed")
	}
	if first.Sub != "canonical-subject" || second.Sub != "canonical-subject" {
		t.Fatalf("cached identities = (%+v, %+v), want canonical subject", first, second)
	}
	if len(provider.cache) != 1 {
		t.Fatalf("cache entries = %d, want one token-bound entry", len(provider.cache))
	}
}

func TestResolveRequestAuth_LegacyOIDCBindsCanonicalIdentity(t *testing.T) {
	srv, provider := mockIDP(t, introspectionResponse{Active: true, Sub: "canonical-subject"})
	defer srv.Close()

	installLegacyOIDCTestProvider(t, provider)

	r := legacyOIDCTestRequest("caller-controlled", "valid-token")
	w := httptest.NewRecorder()

	outcome, proceed := resolveRequestAuth(w, r, "192.0.2.10", "oidc-binding-test")
	if !proceed {
		t.Fatalf("resolveRequestAuth rejected valid token: status=%d body=%q", w.Code, w.Body.String())
	}
	if outcome.identity != "canonical-subject" {
		t.Fatalf("authenticated identity = %q, want canonical token subject", outcome.identity)
	}
	if outcome.source != "oidc" {
		t.Fatalf("authenticated source = %q, want oidc", outcome.source)
	}
}

func TestResolveRequestAuthRejectsEnabledOIDCWithoutLiveBackend(t *testing.T) {
	cfg.mu.Lock()
	oldProvider, oldUser, oldHash, oldRevision := cfg.provider, cfg.user, cfg.passHash, cfg.authRevision
	cfg.provider, cfg.user, cfg.passHash = nil, "", nil
	cfg.authRevision++
	cfg.mu.Unlock()
	cfg.cache.clear()
	oldRegistry := idpRegistry
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{{ID: "uncompiled-oidc", Type: IdPTypeOIDC, Enabled: true}},
		live:     make(map[string]IdentityProvider),
	}
	t.Cleanup(func() {
		idpRegistry = oldRegistry
		cfg.mu.Lock()
		cfg.provider, cfg.user, cfg.passHash, cfg.authRevision = oldProvider, oldUser, oldHash, oldRevision
		cfg.mu.Unlock()
		cfg.cache.clear()
	})

	r := legacyOIDCTestRequest("caller-controlled", "attacker-token")
	w := httptest.NewRecorder()
	outcome, proceed := resolveRequestAuth(w, r, "192.0.2.10", "uncompiled-oidc-test")
	if proceed || outcome.identity != "" {
		t.Fatalf("resolveRequestAuth = (%+v, %v), want fail-closed rejection without a live backend", outcome, proceed)
	}
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusProxyAuthRequired)
	}
}

func TestResolveRequestAuthRejectsRegistryIdentityWithoutSubject(t *testing.T) {
	cfg.mu.Lock()
	oldProvider, oldUser, oldHash, oldRevision := cfg.provider, cfg.user, cfg.passHash, cfg.authRevision
	cfg.provider, cfg.user, cfg.passHash = nil, "", nil
	cfg.authRevision++
	cfg.mu.Unlock()
	cfg.cache.clear()
	oldRegistry := idpRegistry
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{{ID: "blank-subject", Type: IdPTypeOIDC, Enabled: true}},
		live: map[string]IdentityProvider{"blank-subject": &testProxyIdentityProvider{
			idByToken: map[string]*Identity{"valid-token": {Provider: "blank-subject"}},
		}},
	}
	t.Cleanup(func() {
		idpRegistry = oldRegistry
		cfg.mu.Lock()
		cfg.provider, cfg.user, cfg.passHash, cfg.authRevision = oldProvider, oldUser, oldHash, oldRevision
		cfg.mu.Unlock()
		cfg.cache.clear()
	})

	r := legacyOIDCTestRequest("caller-controlled", "valid-token")
	w := httptest.NewRecorder()
	outcome, proceed := resolveRequestAuth(w, r, "192.0.2.10", "blank-registry-subject-test")
	if proceed || outcome.identity != "" {
		t.Fatalf("resolveRequestAuth = (%+v, %v), want rejection of registry identity without canonical subject", outcome, proceed)
	}
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusProxyAuthRequired)
	}
}

func TestOIDCAuth_ResolveIdentityPreservesExactNonBlankSubject(t *testing.T) {
	srv, provider := mockIDP(t, introspectionResponse{Active: true, Sub: " canonical-subject "})
	defer srv.Close()

	id, ok := provider.ResolveIdentity("caller-controlled", "valid-token")
	if !ok || id == nil || id.Sub != " canonical-subject " {
		t.Fatalf("ResolveIdentity = (%+v, %v), want exact nonblank token subject", id, ok)
	}
}

func TestResolveRequestAuth_LegacyOIDCUsesTokenUsernameFallback(t *testing.T) {
	srv, provider := mockIDP(t, introspectionResponse{Active: true, Username: "token-login"})
	defer srv.Close()

	installLegacyOIDCTestProvider(t, provider)

	r := legacyOIDCTestRequest("caller-controlled", "valid-token")
	w := httptest.NewRecorder()
	outcome, proceed := resolveRequestAuth(w, r, "192.0.2.10", "oidc-fallback-test")
	if !proceed || outcome.identity != "token-login" || outcome.source != "oidc" {
		t.Fatalf("resolveRequestAuth = (%+v, %v), status=%d; want token username from oidc", outcome, proceed, w.Code)
	}
}

func TestResolveRequestAuth_LegacyOIDCRejectsTokenWithoutIdentity(t *testing.T) {
	srv, provider := mockIDP(t, introspectionResponse{Active: true})
	defer srv.Close()

	installLegacyOIDCTestProvider(t, provider)

	r := legacyOIDCTestRequest("caller-controlled", "valid-token")
	w := httptest.NewRecorder()
	outcome, proceed := resolveRequestAuth(w, r, "192.0.2.10", "oidc-no-identity-test")
	if proceed || outcome.identity != "" || w.Code != 407 {
		t.Fatalf("resolveRequestAuth = (%+v, %v), status=%d; want fail-closed 407", outcome, proceed, w.Code)
	}
}

type legacyBoolAuthProvider struct {
	calls int
	ok    bool
}

func (p *legacyBoolAuthProvider) Name() string { return "legacy-bool" }
func (p *legacyBoolAuthProvider) Verify(string, string) bool {
	p.calls++
	return p.ok
}

func TestConfigResolveAuthIdentity_GenericProviderBehaviorUnchanged(t *testing.T) {
	provider := &legacyBoolAuthProvider{ok: true}
	c := &Config{provider: provider}
	id, ok := c.resolveAuthIdentity("presented-user", "credential")
	if !ok || id == nil || id.Sub != "presented-user" || id.Provider != "local" || provider.calls != 1 {
		t.Fatalf("resolveAuthIdentity = (%+v, %v), calls=%d; want legacy caller identity and one Verify", id, ok, provider.calls)
	}
}

func TestConfigResolveAuthIdentityUsesSingleBackendSnapshot(t *testing.T) {
	rejecting := &legacyBoolAuthProvider{ok: false}
	accepting := &legacyBoolAuthProvider{ok: true}
	c := &Config{provider: rejecting, cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	snapshot := c.snapshotAuthBackend()
	c.SetProvider(accepting)

	if id, ok := c.resolveAuthIdentityWithSnapshot(snapshot, "caller-controlled", "credential"); ok || id != nil {
		t.Fatalf("snapshot resolution = (%+v, %v), want rejection by captured backend", id, ok)
	}
	if rejecting.calls != 1 || accepting.calls != 0 {
		t.Fatalf("provider calls = rejecting:%d accepting:%d, want 1 and 0", rejecting.calls, accepting.calls)
	}
}

func TestConfigResolveAuthIdentityRejectsDisabledSnapshot(t *testing.T) {
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if !c.VerifyAuth("caller-controlled", "credential") {
		t.Fatal("VerifyAuth compatibility precondition: disabled authentication should remain permissive")
	}
	if id, ok := c.resolveAuthIdentity("caller-controlled", "credential"); ok || id != nil {
		t.Fatalf("identity resolution with no backend = (%+v, %v), want fail-closed rejection", id, ok)
	}
}

func TestConfigStaleLocalSnapshotCannotRepopulateAuthCache(t *testing.T) {
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if err := c.SetAuth("alice", "old-password"); err != nil {
		t.Fatal(err)
	}
	stale := c.snapshotAuthBackend()
	if err := c.SetAuth("alice", "new-password"); err != nil {
		t.Fatal(err)
	}
	if !c.verifyAuthWithSnapshot(stale, "alice", "old-password") {
		t.Fatal("captured credential snapshot unexpectedly failed")
	}
	if c.VerifyAuth("alice", "old-password") {
		t.Fatal("stale snapshot repopulated cache after credential rotation")
	}
	if !c.VerifyAuth("alice", "new-password") {
		t.Fatal("current credential rejected after rotation")
	}
}

func TestOIDCAuth_CacheReturnsDetachedIdentity(t *testing.T) {
	srv, provider := mockIDP(t, introspectionResponse{Active: true, Sub: "unused"})
	defer srv.Close()
	key := cacheKey("", "detached-token")
	provider.oidcCacheSetIdentityWithExp(key, &Identity{Sub: "canonical", Groups: []string{"engineering"}, Provider: "oidc"}, true, nil)

	first, ok, hit := provider.oidcIdentityCacheGet(key)
	if !hit || !ok || first == nil {
		t.Fatalf("first cache get = (%+v, %v, %v)", first, ok, hit)
	}
	first.Sub = "mutated"
	first.Groups[0] = "attackers"
	second, ok, hit := provider.oidcIdentityCacheGet(key)
	if !hit || !ok || second == nil || second.Sub != "canonical" || len(second.Groups) != 1 || second.Groups[0] != "engineering" {
		t.Fatalf("cached identity was mutable through a result: %+v", second)
	}
}

func TestOIDCAuth_VerifyAndCaptiveURLCompatibility(t *testing.T) {
	srv, provider := mockIDP(t, introspectionResponse{Active: true, Sub: "canonical"})
	defer srv.Close()
	provider.cfg.LoginURL = "https://idp.example/authorize"

	if !provider.Verify("caller-controlled", "valid-token") {
		t.Fatal("Verify rejected token carrying a canonical identity")
	}
	if got := provider.CaptiveLoginURL("", nil); got != provider.cfg.LoginURL {
		t.Fatalf("CaptiveLoginURL = %q, want %q", got, provider.cfg.LoginURL)
	}
}
