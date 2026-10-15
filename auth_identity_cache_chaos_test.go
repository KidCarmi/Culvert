package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// CHAOS-76 — the identity-backend result caches as a displacement surface.
//
// All three caches on the credential path (the LDAP directory bind, the legacy
// OIDC introspection backend, and the IdP-registry introspection provider)
// evicted "one arbitrary entry" at the cap: a Go map range stopping at the
// first key, i.e. a uniformly random LIVE entry, on a key space derived
// entirely from caller-supplied credentials. That is register row AU-3c
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
	resetAuthBackendHealthForTest()

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
// The policy itself, on the shared store.
// ─────────────────────────────────────────────────────────────────────────────

// An expired entry is free to drop — it would have been a miss anyway — so
// evicting a LIVE entry while a dead one occupies capacity is pure loss. The
// pre-fix policy did exactly that, and nothing else reclaimed the dead ones.
//
// The population is inverted on purpose: ONE expired entry in a cache that is
// otherwise full of live ones. An arbitrary victim is therefore a live entry
// with probability (cap-1)/cap, which makes this a deterministic oracle rather
// than a coin flip.
func TestChaos76_ExpiredEntriesAreEvictedBeforeLiveOnes(t *testing.T) {
	var c identityResultCache[*Identity]

	// One expired entry, alone in its bucket so it is that bucket's FRONT —
	// the only positions the bounded eviction scan examines.
	c.set("dead", "dead-client", nil, false, time.Nanosecond)
	live := make([]string, 0, maxAuthCacheSize-1)
	for i := 0; i < maxAuthCacheSize-1; i++ {
		k := fmt.Sprintf("live-%d", i)
		live = append(live, k)
		c.set(k, fmt.Sprintf("live-client-%d", i%4), &Identity{Sub: "alice"}, true, honestEntryTTL)
	}
	time.Sleep(5 * time.Millisecond) // let the one short-TTL entry lapse

	c.set("newcomer", "newcomer-client", nil, false, honestEntryTTL)

	if _, _, hit := c.get("dead"); hit {
		t.Error("the expired entry survived the eviction that the newcomer forced")
	}
	survivors := 0
	for _, k := range live {
		if _, _, hit := c.get(k); hit {
			survivors++
		}
	}
	if survivors != len(live) {
		t.Fatalf("eviction took %d LIVE entr(ies) while an expired one sat in the cache "+
			"(%d of %d live entries survived) — an expired entry is free to drop, so taking a "+
			"live one in preference is pure loss (CHAOS-76)", len(live)-survivors, survivors, len(live))
	}
}

// A lookup reclaims an expired entry in place, so a dead verdict stops
// occupying capacity as soon as anybody looks at it. Pre-fix, the lookup
// reported a miss and left the entry sitting there.
func TestChaos76_LookupReclaimsAnExpiredEntry(t *testing.T) {
	var c identityResultCache[*Identity]
	c.set("k", "client", &Identity{Sub: "alice"}, true, time.Nanosecond)
	time.Sleep(5 * time.Millisecond)

	if c.len() != 1 {
		t.Fatalf("precondition: len = %d, want 1", c.len())
	}
	if _, _, hit := c.get("k"); hit {
		t.Fatal("an expired entry was reported as a hit")
	}
	if got := c.len(); got != 0 {
		t.Fatalf("a lookup left %d expired entr(ies) occupying capacity, want 0 (CHAOS-76)", got)
	}
}

// The victim must never depend on Go's map iteration order, or the policy is
// untestable and an attacker's odds change per process.
func TestChaos76_EvictionVictimIsDeterministic(t *testing.T) {
	victimOf := func() string {
		var c identityResultCache[*Identity]
		// Three clients of different sizes, all live. "big" is the largest
		// holder, so its oldest entry is the only correct victim.
		c.set("small", "small-client", nil, true, honestEntryTTL)
		c.set("medium-0", "medium-client", nil, true, honestEntryTTL)
		c.set("medium-1", "medium-client", nil, true, honestEntryTTL)
		for i := 0; i < maxAuthCacheSize-3; i++ {
			c.set(fmt.Sprintf("big-%d", i), "big-client", nil, true, honestEntryTTL)
		}
		c.set("newcomer", "newcomer-client", nil, true, honestEntryTTL)

		for _, k := range []string{"small", "medium-0", "medium-1", "big-0"} {
			if _, _, hit := c.get(k); !hit {
				return k
			}
		}
		return "<none>"
	}

	first := victimOf()
	if first != "big-0" {
		t.Fatalf("eviction victim = %q, want \"big-0\" — the oldest entry of the largest holder; "+
			"a different victim means the policy is reading Go's map order (CHAOS-76)", first)
	}
	// Repeat: map order differs per range, so a non-deterministic policy
	// diverges across runs in the same process.
	for i := 0; i < 8; i++ {
		if got := victimOf(); got != first {
			t.Fatalf("eviction victim varied across runs (%q then %q) — it depends on map order (CHAOS-76)", first, got)
		}
	}
}

// A client holding ONE entry is untouchable until every other client is down
// to one too: the property that makes an attacker buy distinct source
// addresses rather than run a for-loop.
func TestChaos76_ASingleEntryHolderOutlivesEveryLargerHolder(t *testing.T) {
	var c identityResultCache[*Identity]
	c.set("lonely", "lonely-client", &Identity{Sub: "alice"}, true, honestEntryTTL)
	// 6x the cap: under an arbitrary-victim policy the lonely entry's survival
	// probability is (1-1/cap)^(6*cap) = e^-6, about one run in four hundred.
	for i := 0; i < 6*maxAuthCacheSize; i++ {
		c.set(fmt.Sprintf("flood-%d", i), fmt.Sprintf("flood-client-%d", i%4), nil, false, honestEntryTTL)
	}
	if _, _, hit := c.get("lonely"); !hit {
		t.Fatal("a single-entry holder was displaced while four larger holders remained (CHAOS-76)")
	}
}

// The compaction trap: under a sustained flood the un-consumed window stays
// pinned at the cap while head and len advance together forever, so a
// window-based compaction test never fires and the backing array grows with
// total request count — a memory leak reachable by the same flood the
// eviction policy exists to survive.
func TestChaos76_BucketBackingSliceDoesNotGrowWithRequestCount(t *testing.T) {
	var c identityResultCache[*Identity]
	const flood = 6 * maxAuthCacheSize
	for i := 0; i < flood; i++ {
		c.set(fmt.Sprintf("k-%d", i), "one-flooding-client", nil, false, honestEntryTTL)
	}
	if got := c.len(); got > maxAuthCacheSize {
		t.Fatalf("cache holds %d entries, cap is %d", got, maxAuthCacheSize)
	}
	if got := c.keysRetainedForTest("one-flooding-client"); got > 4*maxAuthCacheSize {
		t.Fatalf("one client's bucket retains %d key slots after %d requests against a cap of %d — "+
			"the backing array is growing with request count (CHAOS-76)", got, flood, maxAuthCacheSize)
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

// Displacement must be VISIBLE: it is the operator's only signal that cached
// verdicts are being thrown away, and every eviction costs somebody a full
// backend round trip or a denial during a cooldown.
func TestChaos76_EvictionsAreCounted(t *testing.T) {
	var c identityResultCache[*Identity]
	for i := 0; i < maxAuthCacheSize+64; i++ {
		c.set(fmt.Sprintf("k-%d", i), "client", nil, false, honestEntryTTL)
	}
	if got := c.Evictions(); got < 64 {
		t.Fatalf("Evictions() = %d after %d insertions past the cap, want >= 64 — "+
			"displacement is invisible to the operator (CHAOS-76)", got, 64)
	}
}

// The store is reached concurrently from every request goroutine on the
// credential path, and it is new shared state. The bucket index, the entry map
// and the compaction window all have to stay consistent with each other under
// contention — a bucket whose live count drifts from the entry map would either
// evict the wrong victim forever or leak capacity.
func TestChaos76_ConcurrentUseKeepsTheCapAndTheBucketIndexConsistent(t *testing.T) {
	var c identityResultCache[*Identity]

	const (
		workers   = 32
		perWorker = 400
	)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			client := fmt.Sprintf("client-%d", w%6)
			for i := 0; i < perWorker; i++ {
				k := fmt.Sprintf("w%d-k%d", w, i)
				c.set(k, client, &Identity{Sub: "alice"}, true, honestEntryTTL)
				c.get(k)
				// Re-set the same key: the overwrite path has to remove the old
				// entry from its bucket before re-attributing it, or the live
				// count double-counts and the fairness ordering goes wrong.
				c.set(k, client, &Identity{Sub: "alice"}, true, honestEntryTTL)
				c.get(fmt.Sprintf("w%d-k%d", (w+1)%workers, i))
			}
		}(w)
	}
	wg.Wait()

	if got := c.len(); got > maxAuthCacheSize {
		t.Fatalf("cache holds %d entries after concurrent use, cap is %d", got, maxAuthCacheSize)
	}
	// Every bucket's live count must equal what the entry map actually
	// attributes to that client.
	if drift, client := c.bucketDriftForTest(); drift != 0 {
		t.Fatalf("bucket live count for %q drifts from the entry map by %d — the eviction "+
			"policy reads live counts, so drift corrupts the victim choice (CHAOS-76)", client, drift)
	}
}
