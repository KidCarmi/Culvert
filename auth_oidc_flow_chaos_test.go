package main

// auth_oidc_flow_chaos_test.go — CHAOS-49 regression gates for the multi-IdP
// registry authentication path (auth_oidc_flow.go) under IdP failure.
//
// Every test in this file was run against the pre-fix engine and FAILED there.
// They cover four distinct defects:
//
//   FS-1  a 200 response carrying no usable keys WIPED the JWKS cache
//   FS-2  a non-200 response was decoded as if it were a key set
//   FS-3  an unknown `kid` re-fetched the JWKS on EVERY request (unauthenticated
//         amplification against the customer's IdP)
//   FS-4  introspection had no result cache, no probe gate, and no availability
//         reporting — an IdP outage cost a full dial timeout on every request,
//         per provider, and was invisible on the identity_backend contract row

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// jwksBodyFor renders a minimal RFC 7517 key set containing one RSA key.
func jwksBodyFor(t *testing.T, kid string, key *rsa.PublicKey) string {
	t.Helper()
	e := big.NewInt(int64(key.E)).Bytes()
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","n":%q,"e":%q}]}`,
		kid,
		base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(e),
	)
}

func jwksCacheAgainst(t *testing.T, srv *httptest.Server) *jwksCache {
	t.Helper()
	return &jwksCache{
		jwksURI: srv.URL,
		client:  &http.Client{Timeout: 5 * time.Second},
		keys:    make(map[string]interface{}),
	}
}

// ── FS-1: a 200 with no usable keys must not wipe the cache ─────────────────

// A key set that parses but yields zero usable keys is not evidence that the
// IdP has no keys — it is evidence that something is wrong with the response
// (a rate-limit JSON body, a gateway stub, an all-EC rotation this build cannot
// parse). Installing it destroys every cached key, and the "return the stale
// key rather than failing" fallback in getKey cannot help afterwards because
// there is no longer a stale key to return.
func TestJWKS_EmptyKeySetDoesNotWipeCachedKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	var degraded atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if degraded.Load() {
			// HTTP 200, valid JSON, zero usable keys — the shape an IdP
			// returns from a rate-limiter or an edge stub.
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		_, _ = w.Write([]byte(jwksBodyFor(t, "kid-1", &key.PublicKey)))
	}))
	defer srv.Close()

	j := jwksCacheAgainst(t, srv)
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("initial getKey: %v", err)
	}

	// Age the cache past its TTL and degrade the IdP.
	degraded.Store(true)
	j.mu.Lock()
	j.fetchedAt = time.Now().Add(-2 * jwksCacheTTL)
	j.lastAttempt = time.Time{}
	j.mu.Unlock()

	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("an empty key set wiped the cached key — every ID-token validation now fails: %v", err)
	}
}

// ── FS-2: a non-200 must never be parsed as a key set ───────────────────────

func TestJWKS_NonOKStatusDoesNotWipeCachedKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	var degraded atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if degraded.Load() {
			// A JSON error body behind a 5xx still decodes cleanly into
			// jwkSet{} — the pre-fix code never looked at the status.
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"upstream unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(jwksBodyFor(t, "kid-1", &key.PublicKey)))
	}))
	defer srv.Close()

	j := jwksCacheAgainst(t, srv)
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("initial getKey: %v", err)
	}

	degraded.Store(true)
	j.mu.Lock()
	j.fetchedAt = time.Now().Add(-2 * jwksCacheTTL)
	j.lastAttempt = time.Time{}
	j.mu.Unlock()

	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("an HTTP 503 body was installed as the key set: %v", err)
	}
}

// ── FS-3: an unknown kid must not re-fetch per call ─────────────────────────

// The `kid` is read from an unverified token header, so it is fully
// attacker-controlled and reachable without any credential: one
// `Proxy-Authorization: Basic base64(u:<JWT with a random kid>)` per request.
// Pre-fix, each of those forced one outbound JWKS GET, per configured provider.
func TestJWKS_UnknownKidDoesNotRefetchPerCall(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwksBodyFor(t, "kid-1", &key.PublicKey)))
	}))
	defer srv.Close()

	j := jwksCacheAgainst(t, srv)
	const attempts = 50
	for i := 0; i < attempts; i++ {
		if _, err := j.getKey(fmt.Sprintf("attacker-kid-%d", i)); err == nil {
			t.Fatal("getKey accepted an unknown kid")
		}
	}

	// One legitimate fetch is expected: the first miss may genuinely be a key
	// rotation. Everything after it must be served from the negative window.
	if got := fetches.Load(); got > 1 {
		t.Fatalf("unknown kid triggered %d JWKS fetches for %d requests — "+
			"an unauthenticated caller can amplify request rate into IdP load", got, attempts)
	}
}

func TestJWKS_ConcurrentMissesCoalesceIntoOneFetch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	var fetches atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		<-release // hold the fetch open so every caller piles up behind it
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwksBodyFor(t, "kid-1", &key.PublicKey)))
	}))
	defer srv.Close()

	j := jwksCacheAgainst(t, srv)

	const callers = 40
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			_, _ = j.getKey("kid-1")
		}()
	}
	// Give every caller time to reach the miss path before releasing.
	time.Sleep(150 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := fetches.Load(); got != 1 {
		t.Fatalf("%d concurrent cache misses produced %d JWKS fetches, want 1 (single-flight)", callers, got)
	}
}

// A refresh must still happen once the key set is genuinely stale — the
// negative window bounds the RATE, it must not freeze the cache. Without this
// gate, a rotation at the IdP would never be picked up.
func TestJWKS_StaleCacheStillRefreshesAfterNegativeWindow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	var kid atomic.Value
	kid.Store("kid-1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwksBodyFor(t, kid.Load().(string), &key.PublicKey)))
	}))
	defer srv.Close()

	j := jwksCacheAgainst(t, srv)
	if _, err := j.getKey("kid-1"); err != nil {
		t.Fatalf("initial getKey: %v", err)
	}

	// The IdP rotates to a new kid. Age past both the TTL and the negative
	// window; the next lookup must see the rotation.
	kid.Store("kid-2")
	j.mu.Lock()
	j.fetchedAt = time.Now().Add(-2 * jwksCacheTTL)
	j.lastAttempt = time.Now().Add(-2 * jwksMinRefreshInterval)
	j.mu.Unlock()

	if _, err := j.getKey("kid-2"); err != nil {
		t.Fatalf("rotated kid was not picked up after the negative window: %v", err)
	}
}

// ── FS-4: introspection cache + probe gate + availability reporting ─────────

// oidcFlowIntrospectProvider builds a registry provider whose ONLY configured
// capability is RFC 7662 introspection against srvURL (no JWKS), which is the
// non-browser proxy-auth shape.
func oidcFlowIntrospectProvider(id, srvURL string) *OIDCFlowProvider {
	return &OIDCFlowProvider{
		profile: &IdPProfile{ID: id},
		cfg:     &OIDCProfileConfig{ClientID: "culvert-client"},
		disc:    &oidcDiscoveryDoc{IntrospectionEndpoint: srvURL},
		client:  &http.Client{Timeout: 5 * time.Second},
		cache:   map[string]*oidcCacheEntry{},
	}
}

func TestOIDCFlow_IntrospectionResultIsCached(t *testing.T) {
	resetAuthBackendHealthForTest()

	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"sub":"alice"}`))
	}))
	defer srv.Close()

	p := oidcFlowIntrospectProvider("idp-a", srv.URL)
	for i := 0; i < 20; i++ {
		id, ok := p.ResolveIdentity("alice", "token-abc")
		if !ok || id == nil || id.Sub != "alice" {
			t.Fatalf("call %d: ResolveIdentity = (%v, %v), want alice/true", i, id, ok)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("20 authenticated requests produced %d introspection round trips, want 1 — "+
			"the registry path re-introspects per request", got)
	}
}

func TestOIDCFlow_UnreachableIdPIsGatedAndReported(t *testing.T) {
	resetAuthBackendHealthForTest()

	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()

	p := oidcFlowIntrospectProvider("idp-a", srv.URL)

	// First request detects the outage and fails closed.
	if _, ok := p.ResolveIdentity("alice", "token-abc"); ok {
		t.Fatal("ResolveIdentity succeeded against an unreachable IdP")
	}
	// Subsequent requests inside the cooldown must be denied WITHOUT a round
	// trip — this is what stops N providers × 10 s from landing on every
	// request during an IdP outage.
	for i := 0; i < 10; i++ {
		if _, ok := p.ResolveIdentity("bob", "token-xyz"); ok {
			t.Fatal("ResolveIdentity succeeded while the gate was armed")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("11 requests against a down IdP produced %d round trips, want 1 (probe gate)", got)
	}

	snap := authBackendHealthStatus()
	if !snap.Degraded {
		t.Fatal("identity-backend health does not report the registry IdP as degraded")
	}
	if !strings.Contains(snap.Backend, "idp-a") {
		t.Fatalf("degraded backend = %q, want it to name the IdP profile", snap.Backend)
	}
	if snap.GatedDenials == 0 {
		t.Fatal("gated denials were not counted — the outage blast radius is invisible")
	}
}

// The recovery half: an infrastructure failure must never be remembered as a
// verdict about the credential. Once the IdP answers again, the same token
// authenticates — bounded by the probe cooldown, not by a cache TTL.
func TestOIDCFlow_InfraFailureIsNotCachedAsADenial(t *testing.T) {
	resetAuthBackendHealthForTest()

	var down atomic.Bool
	down.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down.Load() {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"sub":"alice"}`))
	}))
	defer srv.Close()

	p := oidcFlowIntrospectProvider("idp-a", srv.URL)
	// Drive the cooldown from an injected clock rather than sleeping.
	var nowNS atomic.Int64
	nowNS.Store(time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC).UnixNano())
	p.gate.now = func() time.Time { return time.Unix(0, nowNS.Load()).UTC() }

	if _, ok := p.ResolveIdentity("alice", "token-abc"); ok {
		t.Fatal("authenticated against a down IdP")
	}
	down.Store(false)
	nowNS.Add(int64(authBackendProbeCooldown + time.Second)) // cooldown elapses

	id, ok := p.ResolveIdentity("alice", "token-abc")
	if !ok || id == nil || id.Sub != "alice" {
		t.Fatal("a valid token stayed denied after the IdP recovered — the infrastructure " +
			"failure was cached as a verdict about the credential")
	}
	if authBackendHealthStatus().Degraded {
		t.Fatal("identity-backend health still degraded after an observed reach")
	}
}

// A 4xx is a client/token-side rejection, not an outage: it must not arm the
// provider-wide gate (an unauthenticated caller could otherwise lock out every
// other user with one malformed token), and because the endpoint demonstrably
// answered, it must CLEAR any cooldown a previous outage armed.
func TestOIDCFlow_IntrospectionClientErrorDoesNotArmTheGate(t *testing.T) {
	resetAuthBackendHealthForTest()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	p := oidcFlowIntrospectProvider("idp-a", srv.URL)
	var nowNS atomic.Int64
	nowNS.Store(time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC).UnixNano())
	p.gate.now = func() time.Time { return time.Unix(0, nowNS.Load()).UTC() }

	// Seed a prior outage, then let the cooldown elapse so the 4xx lands on the
	// single half-open probe — the exact slot where it must not re-arm.
	p.gate.recordUnavailable()
	noteAuthBackendUnavailable("oidc:idp-a", "seeded outage")
	nowNS.Add(int64(authBackendProbeCooldown + time.Second))

	if _, ok := p.ResolveIdentity("mallory", "junk"); ok {
		t.Fatal("a 4xx introspection response authenticated the caller")
	}
	if p.gate.gated() {
		t.Fatal("a 4xx armed the provider-wide unreachable gate — one malformed token " +
			"would hold a healthy IdP in a permanent outage for every other user")
	}
	if authBackendHealthStatus().Degraded {
		t.Fatal("the endpoint answered, so the degraded state must clear")
	}
}

// An authoritative "this token is inactive" IS cacheable — that is the whole
// point of splitting infrastructure failure from a verdict.
func TestOIDCFlow_InactiveTokenVerdictIsCached(t *testing.T) {
	resetAuthBackendHealthForTest()

	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	defer srv.Close()

	p := oidcFlowIntrospectProvider("idp-a", srv.URL)
	for i := 0; i < 10; i++ {
		if _, ok := p.ResolveIdentity("mallory", "revoked"); ok {
			t.Fatal("an inactive token authenticated")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("an authoritative inactive-token verdict was re-fetched %d times, want 1", got)
	}
}

// The registry loop asks EVERY enabled provider about the same credential, so
// provider A routinely sees provider B's token. That must not become a JWKS
// fetch against A's IdP on every request.
func TestOIDCFlow_ForeignProviderTokenDoesNotStormJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwksBodyFor(t, "kid-A", &key.PublicKey)))
	}))
	defer srv.Close()

	p := &OIDCFlowProvider{
		profile: &IdPProfile{ID: "idp-a"},
		cfg:     &OIDCProfileConfig{ClientID: "culvert-client"},
		disc:    &oidcDiscoveryDoc{Issuer: "https://a.example.test"},
		jwks:    jwksCacheAgainst(t, srv),
		client:  &http.Client{Timeout: 5 * time.Second},
		cache:   map[string]*oidcCacheEntry{},
	}

	// A well-formed JWT signed by a DIFFERENT provider: parses, unknown kid.
	other := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.MapClaims{
		"iss": "https://b.example.test",
		"aud": "other-client",
		"sub": "bob",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	other.Header["kid"] = "kid-B"
	raw, err := other.SignedString(key)
	if err != nil {
		t.Fatalf("sign foreign token: %v", err)
	}

	for i := 0; i < 25; i++ {
		if _, ok := p.ResolveIdentity("bob", raw); ok {
			t.Fatal("a foreign provider's token authenticated")
		}
	}
	if got := fetches.Load(); got > 1 {
		t.Fatalf("25 requests carrying another provider's token produced %d JWKS fetches "+
			"against this provider's IdP, want ≤1", got)
	}
}
