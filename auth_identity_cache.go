package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// identityResultCache is the bounded, client-attributed result cache shared by
// every identity backend on the credential path: the LDAP directory bind
// (auth_ldap.go), the legacy OIDC introspection backend (auth_oidc.go) and the
// IdP-registry introspection provider (auth_oidc_flow.go).
//
// # Why the eviction policy is a security control (CHAOS-76)
//
// All three caches are populated by UNAUTHENTICATED requests. The proxy
// credential path hands whatever username/password or bearer token the client
// supplied straight to the configured backend, and an AUTHORITATIVE denial is
// cached deliberately — an RFC 7662 endpoint answers an unknown or expired
// token with 200 {"active":false}, and a directory that answers "no such user"
// is an authoritative deny — because not caching those would make every wrong
// credential a fresh round trip. So the key space is derived entirely from
// caller-supplied bytes, and whoever can reach the listener decides what is in
// the map.
//
// All three previously evicted "an arbitrary entry when the cache is full": a
// Go map range that stops at the first key, i.e. a uniformly random LIVE
// entry. That is register row AU-3c exactly, which CHAOS-57 closed in the
// LOCAL auth cache (store.go) and which was never ported to these three
// siblings. Two consequences followed, both reachable by an anonymous client:
//
//   - A flood of distinct bogus credentials displaced OTHER clients' cached
//     positives at random. Each insertion past the cap evicts an honest entry
//     with probability (honest entries / cap), so the honest population decays
//     geometrically: one cap-worth of flood removes ~63% of it and three
//     cap-worths remove ~95%. The victim then pays a full directory bind or
//     introspection round trip on EVERY subsequent request, which lands the
//     attacker's amplification on legitimate traffic and on the IdP itself.
//
//   - Worse, the victim is chosen without regard to whether it is still LIVE.
//     Nothing reclaims an expired entry (the lookup path reported a miss and
//     left it in place), so the steady state under a flood is a map full of
//     DEAD attacker verdicts while eviction destroys the few live ones. An
//     expired entry is free to drop — it would have been a miss anyway — so
//     evicting a live entry in preference to one is pure loss.
//
// The sharp end is the interaction with the CHAOS-47/CHAOS-49 unreachable
// cooldown. Displacing an honest client's cached positive while the backend is
// in its cooldown turns a cache HIT into a DENIAL, because the gated path
// denies without a round trip. The cache's stated purpose is to let a cached
// verdict ride out a short backend blip; a flood inverts that for exactly the
// users it exists to serve. Failure stays CLOSED — there is no bypass — but
// the gateway's authentication becomes remotely deniable by a client holding
// no credential at all, which is the failure shape internal/authstate's
// package doc was written for.
//
// # The policy
//
// internal/authstate's, the same one CHAOS-57 ported into store.go, so there
// is ONE eviction policy in the tree rather than a fourth variant:
//
//   - Entries are attributed to a CLIENT fairness key. Eviction takes the
//     OLDEST entry of the client holding the MOST live entries, ties broken by
//     oldest entry then by client key (betterAuthCacheVictim, shared with
//     store.go), so the victim never depends on Go's map iteration order.
//     A flooding source evicts ITSELF until it is no longer the largest
//     holder, and a client holding one entry cannot be displaced until every
//     other client is down to one too.
//
//   - An EXPIRED entry is always the better victim and is taken wherever it is
//     found, because dropping it costs nobody anything. The lookup path also
//     reclaims an expired entry in place, so dead verdicts no longer occupy
//     capacity until an eviction happens to land on them.
//
//   - Work per insertion is O(active clients) — bucket FRONTS only, never a
//     scan of the whole map. The O(cache) scan under a process-wide mutex is
//     register row AU-3d, and re-introducing it here would trade one measured
//     defect for another.
//
// Entries carry a PER-ENTRY expiry rather than one store-wide TTL, because a
// positive introspection verdict is clamped to the token's own declared
// lifetime (clampCacheTTLToTokenExpiry) and may therefore be shorter-lived
// than the backend's configured TTL. A bucket front is consequently the
// client's oldest entry by INSERTION, which is not necessarily its first to
// expire; that only means a deeper expired entry waits until it reaches the
// front, and it leaves the fairness property — the one an attacker has to
// beat — untouched.
//
// The zero value is usable. All methods are safe for concurrent use.
type identityResultCache[T any] struct {
	mu      sync.Mutex
	entries map[string]*identityCacheEntry[T]
	buckets map[string]*identityCacheBucket

	// evictions counts entries displaced to stay under the cap. It is the
	// operator's only signal that cached verdicts are being thrown away —
	// every eviction costs somebody a full backend round trip on their next
	// request, or a denial if the backend is in its unreachable cooldown.
	evictions uint64
}

type identityCacheEntry[T any] struct {
	val    T
	ok     bool
	client string
	added  time.Time
	expiry time.Time

	// pos is the index, in the owning bucket's keys slice, of the slot this
	// record was written for. It is the generation marker that lets
	// frontLocked tell a STALE slot from the live one (Codex review, PR
	// #1633).
	//
	// Why it is needed: set on an existing key removes the old record and
	// appends the key again, so a bucket can read [A, B, A] while live counts
	// two. A presence test alone cannot reject the leading A, because the NEW
	// record answers "present" for every historical position of that key — so
	// frontLocked returned the FRESHLY REFRESHED entry as the client's oldest,
	// and eviction then took it in preference to the genuinely older B.
	// Compaction deduplicates, but it is skipped for buckets of eight keys or
	// fewer, so small buckets stayed wrong indefinitely.
	pos int
}

type identityCacheBucket struct {
	keys []string
	head int
	live int
}

// get returns a live cached verdict. An expired entry is removed in place and
// reported as absent, so a dead verdict stops occupying capacity as soon as
// anybody looks at it.
func (c *identityResultCache[T]) get(key string) (val T, ok, hit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var zero T
	e, found := c.entries[key]
	if !found {
		return zero, false, false
	}
	if !time.Now().Before(e.expiry) {
		c.removeLocked(key)
		return zero, false, false
	}
	return e.val, e.ok, true
}

// set records a verdict for key, attributed to client, live for ttl.
//
// client is an opaque fairness key: it is never compared against anything a
// caller supplies later and never reaches a lookup, so a wrong or empty value
// can only make eviction less fair, never admit an entry that should not be
// admitted. An empty client is legitimate — all such entries share one bucket
// and evict each other, which is the pre-CHAOS-76 behaviour for any caller
// that cannot name its peer.
func (c *identityResultCache[T]) set(key, client string, val T, ok bool, ttl time.Duration) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]*identityCacheEntry[T]{}
	}
	if c.buckets == nil {
		c.buckets = map[string]*identityCacheBucket{}
	}

	// Overwriting a live entry (the same credential re-verified after its TTL)
	// must not double-count it in its bucket, and must re-attribute it to the
	// client that refreshed it.
	if _, exists := c.entries[key]; exists {
		c.removeLocked(key)
	}
	// Loop rather than evict once: the cap is a constant today, but an
	// evictOneLocked that finds nothing to take must not spin.
	for len(c.entries) >= maxAuthCacheSize {
		if !c.evictOneLocked(now) {
			break
		}
	}

	b := c.buckets[client]
	if b == nil {
		b = &identityCacheBucket{}
		c.buckets[client] = b
	}
	b.keys = append(b.keys, key)
	c.entries[key] = &identityCacheEntry[T]{
		val: val, ok: ok, client: client, added: now, expiry: now.Add(ttl),
		pos: len(b.keys) - 1,
	}
	b.live++
	c.compactLocked(client, b)
}

// evictOneLocked drops exactly one entry: an already-expired one if a bucket
// front holds one, otherwise the oldest live entry of the client holding the
// most. It reports whether anything was dropped.
func (c *identityResultCache[T]) evictOneLocked(now time.Time) bool {
	var (
		victimKey    string
		victimClient string
		victimLive   int
		victimAdded  time.Time
		found        bool
	)
	for client, b := range c.buckets {
		k, e, okFront := c.frontLocked(client, b)
		if !okFront {
			continue
		}
		// An expired entry is free to drop and is always the better victim.
		if !now.Before(e.expiry) {
			c.removeLocked(k)
			c.countEvictionLocked()
			return true
		}
		if !found || betterAuthCacheVictim(b.live, e.added, client, victimLive, victimAdded, victimClient) {
			victimKey, victimClient, victimLive, victimAdded, found = k, client, b.live, e.added, true
		}
	}
	if !found {
		return false
	}
	c.removeLocked(victimKey)
	c.countEvictionLocked()
	return true
}

// countEvictionLocked records one displacement on this cache AND on the
// process-wide total.
//
// Both are needed. The per-cache number is what a test or a diagnostic asks an
// instance for; the process-wide one is what /metrics exports, because an
// instance does not outlive an operator editing its IdP profile. Editing,
// disabling, deleting or reloading a profile has IdPRegistry compile a NEW
// provider with a fresh, zero cache (Upsert and ReplaceAll both rebuild
// r.live), so a metric summed over the LIVE instances falls — to zero if every
// provider is replaced. A Prometheus counter that decreases reads as a process
// restart, which erases the flood evidence the counter exists to carry and
// corrupts every rate() over the window (Codex review, PR #1633).
func (c *identityResultCache[T]) countEvictionLocked() {
	c.evictions++
	identityCacheEvictions.Add(1)
}

// frontLocked returns the client's oldest still-present entry, advancing head
// past slots that have been removed, re-attributed to another client, or
// superseded by a later refresh of the same key — e.pos names the one slot a
// record is authoritative for.
func (c *identityResultCache[T]) frontLocked(client string, b *identityCacheBucket) (string, *identityCacheEntry[T], bool) {
	for b.head < len(b.keys) {
		k := b.keys[b.head]
		if e, present := c.entries[k]; present && e.client == client && e.pos == b.head {
			return k, e, true
		}
		b.head++
	}
	return "", nil, false
}

// removeLocked deletes one entry and decrements its bucket, dropping the
// bucket entirely at zero so the map's cardinality tracks ACTIVE clients
// rather than every client ever seen.
func (c *identityResultCache[T]) removeLocked(k string) {
	e, present := c.entries[k]
	if !present {
		return
	}
	delete(c.entries, k)
	b := c.buckets[e.client]
	if b == nil {
		return
	}
	b.live--
	if b.live <= 0 {
		delete(c.buckets, e.client)
	}
}

// compactLocked drops consumed and duplicated positions once a bucket's
// backing slice has grown past a small multiple of what the client actually
// holds.
//
// The condition is on len(b.keys), NOT on the un-consumed window
// len(b.keys)-b.head: under a sustained flood the window stays pinned at the
// cap while head and len advance together forever, so a window-based test
// never fires and the backing array grows with total request count — a memory
// leak reachable by the same flood the eviction policy exists to survive.
// (The identical trap is documented in store.go and internal/authstate.)
//
// Duplicates are the SECOND route to that same leak, and the one this code
// originally missed (Codex review, PR #1633). Re-verifying a credential after
// its TTL calls set for a key the bucket already lists: set removes the old
// record and appends the key, so the slice holds it twice while live counts it
// once. A presence test cannot tell the stale slot from the live one, because
// the NEW record answers "present" for every historical position of that key —
// so a plain filter kept them all and the slice grew with request count.
//
// The realistic shape is ordinary rather than adversarial: the fairness key is
// a client address, so one NAT'd office is ONE bucket holding many live
// credentials, each re-verified every TTL.
//
// Deduplication keeps each key's LAST position, which is the one whose record
// set most recently wrote, so the bucket's order still matches entry age and
// frontLocked still yields the client's oldest entry.
func (c *identityResultCache[T]) compactLocked(client string, b *identityCacheBucket) {
	if len(b.keys) <= 8 || len(b.keys) < 4*b.live {
		return
	}
	window := b.keys[b.head:]
	// Walk back to front so the first sighting of a key is its last position,
	// then reverse. A fresh slice rather than b.keys[:0]: writing forwards
	// while reading backwards would overwrite positions still to be read.
	kept := make([]string, 0, b.live)
	seen := make(map[string]struct{}, b.live)
	for i := len(window) - 1; i >= 0; i-- {
		k := window[i]
		if _, dup := seen[k]; dup {
			continue
		}
		if e, present := c.entries[k]; present && e.client == client {
			seen[k] = struct{}{}
			kept = append(kept, k)
		}
	}
	for lo, hi := 0, len(kept)-1; lo < hi; lo, hi = lo+1, hi-1 {
		kept[lo], kept[hi] = kept[hi], kept[lo]
	}
	b.keys = kept
	b.head = 0
	// Positions moved, so every surviving record's generation marker has to
	// follow, or frontLocked would reject the slots compaction just kept.
	for i, k := range b.keys {
		if e, present := c.entries[k]; present {
			e.pos = i
		}
	}
	if len(b.keys) == 0 {
		delete(c.buckets, client)
	}
}

// Evictions reports how many cached verdicts have been displaced to stay under
// the cap.
func (c *identityResultCache[T]) Evictions() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evictions
}

// len reports the number of entries currently held, live or expired.
func (c *identityResultCache[T]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// ── Test support ─────────────────────────────────────────────────────────────

// entryForTest returns the raw record under key, or nil. It does NOT apply the
// expiry check, because the tests that reach for it are asserting ON the
// recorded expiry (that a positive verdict was clamped to the token's own
// declared lifetime rather than the backend's TTL).
func (c *identityResultCache[T]) entryForTest(key string) *identityCacheEntry[T] {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries[key]
}

// identityCacheEvictions is the process-wide displacement total across every
// identityResultCache instance, live or long since replaced. It is what
// /metrics exports; see countEvictionLocked for why a sum over live instances
// is not a usable counter.
var identityCacheEvictions atomic.Uint64

// identityCacheEvictionsTotal reports displacement across every identity
// backend that keeps a result cache — the legacy provider on Config and the
// registry credential providers alike, including instances the registry has
// since retired.
//
// It deliberately does NOT walk idpRegistry. In a registry deployment those
// providers ARE the caches this sweep changed (proxy.go tries them before the
// legacy fallback) and an LDAP registry cutover unwires Config.provider
// entirely, so the counter must cover them — but reading them live made the
// total fall whenever a profile was edited. Accumulating at the point of
// eviction covers both deployments and cannot regress.
func identityCacheEvictionsTotal() uint64 { return identityCacheEvictions.Load() }

// keysRetainedForTest reports how many key slots a client's bucket still holds,
// consumed positions included. It is the only way to observe the compaction
// trap documented on compactLocked — the entry COUNT stays at the cap under a
// flood while the backing array grows with total request count.
func (c *identityResultCache[T]) keysRetainedForTest(client string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.buckets[client]
	if b == nil {
		return 0
	}
	return len(b.keys)
}

// bucketDriftForTest reports the first bucket whose live count disagrees with
// the number of entries the map actually attributes to that client, and by how
// much. The eviction policy orders victims BY those live counts, so drift does
// not merely waste memory — it corrupts the choice of victim, which is the
// security property. Returns (0, "") when every bucket agrees.
func (c *identityResultCache[T]) bucketDriftForTest() (drift int, client string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	actual := map[string]int{}
	for _, e := range c.entries {
		actual[e.client]++
	}
	for name, b := range c.buckets {
		if d := b.live - actual[name]; d != 0 {
			return d, name
		}
	}
	for name, n := range actual {
		if _, ok := c.buckets[name]; !ok {
			return -n, name
		}
	}
	return 0, ""
}
