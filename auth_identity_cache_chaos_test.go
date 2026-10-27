package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// CHAOS-76 — the identity-backend result caches as a displacement surface.
//
// All three caches on the credential path (the LDAP directory bind, the legacy
// OIDC introspection backend, and the IdP-registry introspection provider)
// evicted "one arbitrary entry" at the cap: a Go map range stopping at the
// first key, i.e. whichever entry Go's randomised map iteration yielded, live
// or already expired, on a key space derived entirely from caller-supplied
// credentials. That is register row AU-3c
// exactly — closed by CHAOS-57 in the LOCAL auth cache and never ported to
// these three siblings.
//
// Every gate below fails against the pre-fix policy.

// honestEntryTTL is comfortably longer than any gate here runs, so an entry
// that disappears was EVICTED rather than expired.
const honestEntryTTL = time.Hour

// ─────────────────────────────────────────────────────────────────────────────
// The headline property, stated once per backend: a flood from one source
// cannot displace another client's cached verdict.
// ─────────────────────────────────────────────────────────────────────────────

func TestChaos76_FloodCannotDisplaceAnHonestClientsCachedVerdict(t *testing.T) {
	// 3x the cap. Under the pre-fix policy the honest population decays
	// geometrically at (honest/cap) per insertion, so one cap-worth removes
	// ~63% of it and three remove ~95% — the honest entry is reliably gone.
	const floodSize = 3 * maxAuthCacheSize

	cases := []struct {
		name string
		// seed records one honest verdict for the honest client and returns a
		// probe reporting whether it is still cached.
		seed func(t *testing.T) (flood func(i int), honestStillCached func() bool)
	}{
		{
			name: "registry OIDC introspection (auth_oidc_flow.go)",
			seed: func(t *testing.T) (func(int), func() bool) {
				p := &OIDCFlowProvider{
					profile: &IdPProfile{ID: "idp-a"},
					cfg:     &OIDCProfileConfig{ClientID: "culvert-client"},
					disc:    &oidcDiscoveryDoc{IntrospectionEndpoint: "http://127.0.0.1:1"},
					client:  &http.Client{Timeout: time.Second},
					ttl:     honestEntryTTL,
				}
				honestKey := cacheKey("", "honest-token")
				p.introspectCacheSet(honestKey, "honest-client", &Identity{Sub: "alice"}, true, nil)
				return func(i int) {
						p.introspectCacheSet(cacheKey("", fmt.Sprintf("bogus-%d", i)), "flooding-client", nil, false, nil)
					}, func() bool {
						_, _, hit := p.introspectCacheGet(honestKey)
						return hit
					}
			},
		},
		{
			name: "legacy OIDC introspection (auth_oidc.go)",
			seed: func(t *testing.T) (func(int), func() bool) {
				a := &OIDCAuth{ttl: honestEntryTTL}
				honestKey := cacheKey("", "honest-token")
				a.oidcCacheSetIdentityWithExp(honestKey, "honest-client", &Identity{Sub: "alice"}, true, nil)
				return func(i int) {
						a.oidcCacheSetIdentityWithExp(cacheKey("", fmt.Sprintf("bogus-%d", i)), "flooding-client", nil, false, nil)
					}, func() bool {
						_, _, hit := a.oidcIdentityCacheGet(honestKey)
						return hit
					}
			},
		},
		{
			name: "LDAP directory bind (auth_ldap.go)",
			seed: func(t *testing.T) (func(int), func() bool) {
				a, err := NewLDAPAuth(LDAPConfig{
					URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com", CacheTTL: honestEntryTTL,
				})
				if err != nil {
					t.Fatalf("NewLDAPAuth: %v", err)
				}
				honestKey := cacheKey("alice", "secret")
				a.cacheSet(honestKey, "honest-client", true, nil)
				return func(i int) {
						a.cacheSet(cacheKey(fmt.Sprintf("mallory-%d", i), "nope"), "flooding-client", false, nil)
					}, func() bool {
						_, _, hit := a.cacheGet(honestKey)
						return hit
					}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flood, honestStillCached := tc.seed(t)
			if !honestStillCached() {
				t.Fatal("precondition: the honest verdict was not cached at all")
			}
			for i := 0; i < floodSize; i++ {
				flood(i)
			}
			if !honestStillCached() {
				t.Fatalf("a flood of %d distinct credentials from ONE source displaced an honest "+
					"client's cached verdict — the victim now pays a full backend round trip on every "+
					"request, or is DENIED outright while the backend sits in its unreachable cooldown "+
					"(AU-3c on this backend; CHAOS-76)", floodSize)
			}
		})
	}
}

// The sharp end of the finding: displacing a cached positive while the backend
// is in its CHAOS-47/CHAOS-49 unreachable cooldown converts a cache HIT into a
// DENIAL, because the gated path denies without a round trip. The cache exists
// so a cached verdict can ride out a short backend blip; a flood must not be
// able to invert that for the users it is there to serve.
func TestChaos76_FloodCannotTurnACachedPositiveIntoADenialDuringAnOutage(t *testing.T) {
	// Reset AND restore: this test deliberately drives the backend DOWN, and
	// noteAuthBackendUnavailable retains the down-backend entry, the counters
	// and the alert/log timestamps. Without the cleanup the simulated outage
	// outlives the test and is visible to every later health/metrics reader —
	// the global-test cleanup rule in AGENTS.md and conventions.md, and the
	// pattern the neighbouring backend-health tests already follow
	// (auth_ldap_gate_test.go, auth_oidc_test.go, diagnostics_test.go).
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	var calls atomic.Int64
	reachable := atomic.Bool{}
	reachable.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if !reachable.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"sub":"alice"}`))
	}))
	defer srv.Close()

	p := oidcFlowIntrospectProvider("idp-a", srv.URL)
	p.ttl = honestEntryTTL

	// The honest client authenticates once while the IdP is up.
	if id, ok := p.ResolveIdentityFrom("honest-client", "alice", "honest-token"); !ok || id == nil || id.Sub != "alice" {
		t.Fatalf("ResolveIdentityFrom = (%v, %v), want alice/true", id, ok)
	}

	// A flooding source fills the cache with authoritative negatives. These are
	// cacheable by design: RFC 7662 answers an unknown token with
	// 200 {"active":false}, so the flood needs no fault and no credential.
	for i := 0; i < 3*maxAuthCacheSize; i++ {
		p.introspectCacheSet(cacheKey("", fmt.Sprintf("bogus-%d", i)), "flooding-client", nil, false, nil)
	}

	// The IdP goes down and the provider-wide gate arms.
	reachable.Store(false)
	if _, ok := p.ResolveIdentityFrom("flooding-client", "mallory", "unseen-token"); ok {
		t.Fatal("an unreachable IdP authenticated a token — fail-closed posture broken")
	}

	// The honest client must still be served from its cached positive. If the
	// flood evicted it, the gate denies without a round trip and the honest
	// user is locked out for the whole cooldown.
	id, ok := p.ResolveIdentityFrom("honest-client", "alice", "honest-token")
	if !ok || id == nil || id.Sub != "alice" {
		t.Fatalf("an honest client with a live cached positive was DENIED during an IdP outage "+
			"because a flood had evicted its entry: ResolveIdentityFrom = (%v, %v) (CHAOS-76)", id, ok)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The structural half: the fairness key has to REACH the provider caches.
// ─────────────────────────────────────────────────────────────────────────────

// recordingProvider captures the client-fairness key the dispatcher hands it.
type recordingProvider struct {
	verifyClient   string
	resolveClient  string
	sawBareVerify  bool
	sawBareResolve bool
}

func (p *recordingProvider) Name() string { return "recording" }
func (p *recordingProvider) Verify(string, string) bool {
	p.sawBareVerify = true
	return true
}
func (p *recordingProvider) VerifyFrom(client, _, _ string) bool {
	p.verifyClient = client
	return true
}
func (p *recordingProvider) ResolveIdentity(user, _ string) (*Identity, bool) {
	p.sawBareResolve = true
	return &Identity{Sub: user}, true
}
func (p *recordingProvider) ResolveIdentityFrom(client, user, _ string) (*Identity, bool) {
	p.resolveClient = client
	return &Identity{Sub: user}, true
}

// proxy.go and socks5.go both compute a client-fairness key and hand it to
// store.go. Both provider dispatch points used to DROP it, so no per-client
// policy was expressible inside a provider's cache at all — authProbeGate
// governs reachability and says nothing about who may displace whose entry.
func TestChaos76_ClientFairnessKeyReachesTheIdentityProviders(t *testing.T) {
	t.Run("verifyAuthFrom", func(t *testing.T) {
		p := &recordingProvider{}
		cfg := &Config{}
		if !cfg.verifyAuthFrom(authBackendSnapshot{provider: p}, "198.51.100.7", "alice", "secret") {
			t.Fatal("verifyAuthFrom denied a provider that accepts")
		}
		if p.sawBareVerify {
			t.Error("the dispatcher used the bare Verify, discarding the fairness key (CHAOS-76)")
		}
		if p.verifyClient != "198.51.100.7" {
			t.Errorf("provider saw client key %q, want %q — the key never reaches the "+
				"provider's result cache, so its eviction policy cannot be fair (CHAOS-76)",
				p.verifyClient, "198.51.100.7")
		}
	})

	t.Run("resolveAuthIdentityFrom", func(t *testing.T) {
		p := &recordingProvider{}
		cfg := &Config{}
		id, ok := cfg.resolveAuthIdentityFromSnapshot(authBackendSnapshot{provider: p}, "203.0.113.9", "alice", "secret")
		if !ok || id == nil {
			t.Fatalf("resolveAuthIdentityFromSnapshot = (%v, %v), want an identity", id, ok)
		}
		if p.sawBareResolve {
			t.Error("the dispatcher used the bare ResolveIdentity, discarding the fairness key (CHAOS-76)")
		}
		if p.resolveClient != "203.0.113.9" {
			t.Errorf("provider saw client key %q, want %q (CHAOS-76)", p.resolveClient, "203.0.113.9")
		}
	})
}

// Every shipped identity backend that KEEPS a result cache must implement the
// client-attributed form of whichever contract the dispatcher reaches it
// through. A backend added later that forgets to inherits the defect silently,
// because the dispatcher's fallback is the historical signature — so this is an
// anti-drift wall, not a behaviour test.
//
// The resolver half is required only of backends that export ResolveIdentity:
// the LDAP engine is reached as a plain AuthProvider on the legacy path, and
// its identity twin is exposed by the registry wrapper, not by the engine.
func TestChaos76_EveryCachingIdentityBackendIsClientAttributed(t *testing.T) {
	ldapEngine, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	backends := map[string]any{
		"LDAPAuth":         ldapEngine,
		"LDAPIdPProvider":  &LDAPIdPProvider{engine: ldapEngine},
		"OIDCAuth":         &OIDCAuth{},
		"OIDCFlowProvider": &OIDCFlowProvider{},
	}
	for name, b := range backends {
		if _, ok := b.(clientAttributedVerifier); !ok {
			t.Errorf("%s keeps a result cache but does not implement clientAttributedVerifier — "+
				"the dispatcher will silently fall back to the bare Verify and the cache "+
				"reverts to arbitrary eviction (CHAOS-76)", name)
		}
		bare, exportsResolve := b.(interface {
			ResolveIdentity(username, credential string) (*Identity, bool)
		})
		_ = bare
		if !exportsResolve {
			continue
		}
		if _, ok := b.(clientAttributedResolver); !ok {
			t.Errorf("%s exports ResolveIdentity and keeps a result cache but does not implement "+
				"clientAttributedResolver — the dispatcher will silently fall back to the bare "+
				"form and discard the fairness key (CHAOS-76)", name)
		}
	}
}

// An eviction counter nobody can read is not observability. culvert_auth_cache_
// evictions_total has been on /metrics since CHAOS-57 for the local cache; the
// identity backends' displacement needs the same surface, for the same reason.
// Config.IdentityCacheEvictions keeps a NARROWER meaning than the exported
// metric: it reports only the legacy single provider on Config, and must not
// claim the local bcrypt cache's count (that reports through
// AuthCacheEvictions). After §54.9 (5) moved the metric to a process-owned
// total, this is the only gate holding that accessor's contract, so it is
// deliberately kept rather than folded into the metric gate.
//
// Renamed from ..._IdentityCacheEvictionsReachTheActiveBackend, which
// described the pre-(5) design where the metric walked the active backend.
func TestChaos76_LegacyProviderEvictionsAreReportedOnConfig(t *testing.T) {
	engine, err := NewLDAPAuth(LDAPConfig{
		URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com", CacheTTL: honestEntryTTL,
	})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	cfg := &Config{}
	cfg.provider = &LDAPIdPProvider{profile: ldapTestProfile("corp-ad", "AD"), engine: engine}

	if got := cfg.IdentityCacheEvictions(); got != 0 {
		t.Fatalf("precondition: IdentityCacheEvictions = %d, want 0", got)
	}
	for i := 0; i < maxAuthCacheSize+32; i++ {
		engine.cacheSet(cacheKey(fmt.Sprintf("mallory-%d", i), "nope"), "flooding-client", false, nil)
	}
	if got := cfg.IdentityCacheEvictions(); got < 32 {
		t.Fatalf("IdentityCacheEvictions = %d after %d insertions past the cap, want >= 32 — "+
			"the legacy provider's displacement is not reported on Config (CHAOS-76)", got, 32)
	}

	// No external backend configured: the local cache reports through
	// AuthCacheEvictions, and this accessor must not claim its count.
	if got := (&Config{}).IdentityCacheEvictions(); got != 0 {
		t.Errorf("IdentityCacheEvictions = %d with no external backend, want 0", got)
	}
}

// Codex review finding on PR #1633, confirmed: the registry dispatch loop in
// proxy.go calls prov.ResolveIdentity directly and is tried BEFORE the legacy
// fallback, so in a registry deployment — the modern path, and the one whose
// caches this sweep changed — the fairness key never reached the cache at all.
// The original gate checked store.go's two dispatch points and missed the loop
// that matters most.
//
// This pins the helper every data-plane caller must go through.
func TestChaos76_RegistryDispatchIsClientAttributed(t *testing.T) {
	t.Run("attributed provider receives the key", func(t *testing.T) {
		p := &recordingProvider{}
		id, ok := resolveIdentityAttributed(p, "198.51.100.7", "alice", "secret")
		if !ok || id == nil {
			t.Fatalf("resolveIdentityAttributed = (%v, %v), want an identity", id, ok)
		}
		if p.sawBareResolve {
			t.Error("the helper used the bare ResolveIdentity, discarding the fairness key (CHAOS-76)")
		}
		if p.resolveClient != "198.51.100.7" {
			t.Errorf("provider saw client key %q, want %q (CHAOS-76)", p.resolveClient, "198.51.100.7")
		}
	})

	t.Run("unattributed provider keeps the historical contract", func(t *testing.T) {
		// A provider with no result cache (SAML) must still resolve, through
		// the bare form, rather than being refused for lacking the interface.
		p := &bareOnlyProvider{}
		if id, ok := resolveIdentityAttributed(p, "198.51.100.7", "alice", "secret"); !ok || id == nil {
			t.Fatalf("resolveIdentityAttributed on a bare provider = (%v, %v), want an identity", id, ok)
		}
		if !p.sawBareResolve {
			t.Error("a provider implementing only ResolveIdentity was not called through it")
		}
	})

	// Every shipped registry credential provider must implement the attributed
	// form, or the helper silently falls back for it.
	t.Run("shipped registry providers are attributed", func(t *testing.T) {
		engine, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
		if err != nil {
			t.Fatalf("NewLDAPAuth: %v", err)
		}
		for name, prov := range map[string]identityResolver{
			"LDAPIdPProvider":  &LDAPIdPProvider{engine: engine},
			"OIDCFlowProvider": &OIDCFlowProvider{},
		} {
			if _, ok := prov.(clientAttributedResolver); !ok {
				t.Errorf("%s is reached by the registry dispatch but does not implement "+
					"clientAttributedResolver, so resolveIdentityAttributed falls back to the "+
					"bare form and its cache reverts to one shared bucket (CHAOS-76)", name)
			}
		}
	})
}

// bareOnlyProvider implements the historical contract and nothing more.
type bareOnlyProvider struct{ sawBareResolve bool }

func (p *bareOnlyProvider) Name() string               { return "bare-only" }
func (p *bareOnlyProvider) Verify(string, string) bool { return true }
func (p *bareOnlyProvider) ResolveIdentity(user, _ string) (*Identity, bool) {
	p.sawBareResolve = true
	return &Identity{Sub: user}, true
}

// Codex review finding on PR #1633, confirmed: the eviction counter read only
// Config.provider, but a registry deployment's caches live in idpRegistry and
// an LDAP registry cutover unwires the legacy provider — so the metric would
// report zero while the real caches evicted.
//
// Second Codex review, also confirmed: summing the LIVE instances made the
// counter FALL when a profile was edited, because Upsert and ReplaceAll
// compile a new provider with a fresh, zero cache. A Prometheus counter that
// decreases reads as a process restart. The total is now accumulated at the
// point of eviction, so both properties hold at once.
func TestChaos76_EvictionCounterCoversEveryCacheAndNeverFalls(t *testing.T) {
	newEngine := func() *LDAPAuth {
		e, err := NewLDAPAuth(LDAPConfig{
			URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com", CacheTTL: honestEntryTTL,
		})
		if err != nil {
			t.Fatalf("NewLDAPAuth: %v", err)
		}
		return e
	}
	engine := newEngine()

	// A registry-only deployment: no legacy provider on Config at all. The
	// global is restored on cleanup, per the shared-global rule in
	// docs/agent-context/conventions.md.
	profile := ldapTestProfile("corp-ad", "AD")
	prevRegistry := idpRegistry
	t.Cleanup(func() { idpRegistry = prevRegistry })
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{profile},
		live: map[string]IdentityProvider{
			profile.ID: &LDAPIdPProvider{profile: profile, engine: engine},
		},
	}

	// The counter is process-wide, so measure deltas rather than absolutes.
	before := identityCacheEvictionsTotal()
	for i := 0; i < maxAuthCacheSize+48; i++ {
		engine.cacheSet(cacheKey(fmt.Sprintf("mallory-%d", i), "nope"), "flooding-client", false, nil)
	}
	afterFlood := identityCacheEvictionsTotal()
	if afterFlood-before < 48 {
		t.Fatalf("identityCacheEvictionsTotal rose by %d after %d insertions past the cap in a "+
			"REGISTRY-only deployment, want >= 48 — the operator signal misses the caches that "+
			"actually serve the credential path (CHAOS-76)", afterFlood-before, 48)
	}

	// The operator now edits the profile: the registry compiles a NEW provider
	// with a fresh cache, so the old instance's count is gone from the live
	// set. The exported total must not fall.
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{profile},
		live: map[string]IdentityProvider{
			profile.ID: &LDAPIdPProvider{profile: profile, engine: newEngine()},
		},
	}
	if got := identityCacheEvictionsTotal(); got < afterFlood {
		t.Fatalf("identityCacheEvictionsTotal fell from %d to %d when the registry replaced the "+
			"provider — a Prometheus counter that decreases reads as a process restart, erasing "+
			"the flood evidence it exists to carry (CHAOS-76)", afterFlood, got)
	}

	// A Config with no external backend must not be credited with any of it.
	if got := (&Config{}).IdentityCacheEvictions(); got != 0 {
		t.Errorf("Config.IdentityCacheEvictions = %d with no external backend, want 0", got)
	}
}

// A positive verdict clamped to the token's own `exp` must expire WITH the
// token, not a scheduling delay later.
//
// clampCacheTTLToTokenExpiry measures the remaining lifetime against one clock
// sample; the pre-CHAOS-76 stores then wrote `expiry: now.Add(ttl)` with that
// SAME sample, so the recorded deadline was the token's exactly. Handing the
// shared store a DURATION restarts the clock inside it, and everything the
// caller spent in between — cloning the identity, contending for the store
// mutex on a busy credential path, waiting out a GC pause — is added back to
// the entry's life. Requests in that interval authenticate on a token that has
// already expired, which is the one outcome the clamp exists to prevent.
//
// The oracle is exact equality, not a tolerance: post-fix the recorded deadline
// IS time.Unix(exp, 0) by construction, so any re-derivation fails the gate
// however small the interval. Repeated across insertions so that a coarse clock
// returning two identical samples cannot hide it.
func TestChaos76_AClampedVerdictExpiresWithItsTokenNotLater(t *testing.T) {
	const inserts = 64
	exp := time.Now().Add(30 * time.Second).Unix()
	deadline := time.Unix(exp, 0)

	// Both backends get a configured TTL far longer than the token, so the
	// clamp is what bounds the entry and the defect is reachable.
	t.Run("legacy OIDC introspection (auth_oidc.go)", func(t *testing.T) {
		a := &OIDCAuth{ttl: time.Hour}
		for i := range inserts {
			k := cacheKey("", fmt.Sprintf("tok-%d", i))
			a.oidcCacheSetIdentityWithExp(k, "client", &Identity{Sub: "alice"}, true, &exp)
			assertExpiresWithToken(t, &a.cache, k, deadline, i)
		}
	})

	t.Run("registry OIDC introspection (auth_oidc_flow.go)", func(t *testing.T) {
		p := &OIDCFlowProvider{profile: &IdPProfile{ID: "idp-a"}, ttl: time.Hour}
		for i := range inserts {
			k := cacheKey("", fmt.Sprintf("tok-%d", i))
			p.introspectCacheSet(k, "client", &Identity{Sub: "alice"}, true, &exp)
			assertExpiresWithToken(t, &p.cache, k, deadline, i)
		}
	})
}

func assertExpiresWithToken(t *testing.T, c *identityResultCache[*Identity], key string, deadline time.Time, i int) {
	t.Helper()
	expiry, ok := c.expiryForTest(key)
	if !ok {
		t.Fatalf("insert %d: no entry recorded", i)
	}
	if !expiry.Equal(deadline) {
		t.Fatalf("insert %d: the cached positive expires %s AFTER the token's own exp "+
			"(recorded %s, token deadline %s) — the clamped duration was re-derived against a "+
			"later clock sample, so the verdict outlives the credential it came from and requests "+
			"in that interval authenticate on an expired token (CHAOS-76)",
			i, expiry.Sub(deadline), expiry, deadline)
	}
}

// The binding is composition only (ADR-0041), so what it must get right is
// the two dependencies it hands the engine: the application cap, shared with
// the local credential cache, and the process-wide eviction sink /metrics
// reads. The engine's own gates live in internal/identcache and build their
// caches with an explicit cap, so nothing there would notice this binding
// passing a different one.
func TestChaos76_TheBindingSuppliesTheApplicationCapAndSink(t *testing.T) {
	var c identityResultCache[*Identity]
	before := identityCacheEvictionsTotal()
	for i := 0; i < maxAuthCacheSize+7; i++ {
		c.set(fmt.Sprintf("k-%d", i), "client", nil, false, honestEntryTTL)
	}
	if got := c.len(); got != maxAuthCacheSize {
		t.Fatalf("binding holds %d entries after %d inserts, want the application cap %d",
			got, maxAuthCacheSize+7, maxAuthCacheSize)
	}
	if got := c.Evictions(); got != 7 {
		t.Fatalf("binding counted %d evictions, want 7", got)
	}
	// Other tests may evict concurrently into the same process-wide total, so
	// this is a lower bound on the delta.
	if delta := identityCacheEvictionsTotal() - before; delta < 7 {
		t.Fatalf("the process-wide total rose by %d, want at least the binding's 7 — "+
			"the eviction sink is not wired", delta)
	}
}
