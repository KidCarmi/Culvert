package identcache

import (
	"sync"
	"time"
)

// Options are a Cache's construction dependencies.
type Options struct {
	// MaxEntries is the hard cap on entries held, live or expired. Values
	// below 1 are treated as 1.
	MaxEntries int

	// OnEvict, when non-nil, is called once for every entry displaced to stay
	// under the cap, AFTER the cache's own per-instance count has been
	// incremented. It runs with the cache's lock held, so it must be cheap,
	// must not block and must not call back into the same Cache. Package main
	// uses it to accumulate the process-wide eviction total that /metrics
	// exports.
	OnEvict func()
}

// New returns an empty Cache configured by opts.
func New[T any](opts Options) *Cache[T] {
	if opts.MaxEntries < 1 {
		opts.MaxEntries = 1
	}
	return &Cache[T]{
		entries:    map[string]*entry[T]{},
		buckets:    map[string]*bucket{},
		maxEntries: opts.MaxEntries,
		onEvict:    opts.OnEvict,
	}
}

// Cache is one backend's result cache. Construct it with New; the policy is
// described in the package documentation. All methods are safe for concurrent
// use.
type Cache[T any] struct {
	mu         sync.Mutex
	entries    map[string]*entry[T]
	buckets    map[string]*bucket
	maxEntries int
	onEvict    func()

	// evictions counts entries displaced to stay under the cap. It is the
	// operator's only signal that cached verdicts are being thrown away —
	// every eviction costs somebody a full backend round trip on their next
	// request, or a denial if the backend is in its unreachable cooldown.
	evictions uint64
}

type entry[T any] struct {
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
	// Why it is needed: Set on an existing key removes the old record and
	// appends the key again, so a bucket can read [A, B, A] while live counts
	// two. A presence test alone cannot reject the leading A, because the NEW
	// record answers "present" for every historical position of that key — so
	// frontLocked returned the FRESHLY REFRESHED entry as the client's oldest,
	// and eviction then took it in preference to the genuinely older B.
	// Compaction deduplicates, but it is skipped for buckets of eight keys or
	// fewer, so small buckets stayed wrong indefinitely.
	pos int
}

type bucket struct {
	keys []string
	head int
	live int
}

// Get returns a live cached verdict. An expired entry is removed in place and
// reported as absent, so a dead verdict stops occupying capacity as soon as
// anybody looks at it.
func (c *Cache[T]) Get(key string) (val T, ok, hit bool) {
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

// Set records a verdict for key, attributed to client, live for ttl.
//
// client is an opaque fairness key: it is never compared against anything a
// caller supplies later and never reaches a lookup, so a wrong or empty value
// can only make eviction less fair, never admit an entry that should not be
// admitted. An empty client is legitimate — all such entries share one bucket
// and evict each other, which is the pre-CHAOS-76 behaviour for any caller
// that cannot name its peer.
func (c *Cache[T]) Set(key, client string, val T, ok bool, ttl time.Duration) {
	now := time.Now()
	c.store(key, client, val, ok, now, now.Add(ttl))
}

// SetUntil records a verdict that stops being served at an ABSOLUTE deadline
// the caller has already computed. Same fairness-key contract as Set.
//
// It exists because re-deriving that deadline from a duration here would move
// it. A caller that clamps a positive verdict to the token's own `exp`
// (clampCacheTTLToTokenExpiry) measures the remaining lifetime against its own
// clock sample, and every microsecond it then spends before reaching this
// mutex — cloning the identity, contending with another request on the
// credential path, waiting out a GC pause — would be added back to the entry's
// life. The entry would outlive the credential it was derived from by exactly
// that interval, which is the one thing the clamp exists to prevent, and the
// pre-CHAOS-76 implementations avoided by construction: they wrote
// `expiry: now.Add(ttl)` with the SAME now the clamp had used.
//
// Callers with no external deadline — an LDAP bind governed only by the
// configured TTL — use Set.
func (c *Cache[T]) SetUntil(key, client string, val T, ok bool, expiry time.Time) {
	c.store(key, client, val, ok, time.Now(), expiry)
}

// store inserts the entry under the cap and the fairness policy. now is the
// insertion instant, which orders the client's bucket and ages the entry for
// eviction; expiry is the absolute instant it stops being served.
func (c *Cache[T]) store(key, client string, val T, ok bool, now, expiry time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]*entry[T]{}
	}
	if c.buckets == nil {
		c.buckets = map[string]*bucket{}
	}

	// Overwriting a live entry (the same credential re-verified after its TTL)
	// must not double-count it in its bucket, and must re-attribute it to the
	// client that refreshed it.
	if _, exists := c.entries[key]; exists {
		c.removeLocked(key)
	}
	// Loop rather than evict once: an evictOneLocked that finds nothing to take
	// must not spin.
	maxEntries := c.maxEntries
	if maxEntries < 1 {
		maxEntries = 1 // a zero Cache, not built by New
	}
	for len(c.entries) >= maxEntries {
		if !c.evictOneLocked(now) {
			break
		}
	}

	b := c.buckets[client]
	if b == nil {
		b = &bucket{}
		c.buckets[client] = b
	}
	b.keys = append(b.keys, key)
	c.entries[key] = &entry[T]{
		val: val, ok: ok, client: client, added: now, expiry: expiry,
		pos: len(b.keys) - 1,
	}
	b.live++
	c.compactLocked(client, b)
}

// evictOneLocked drops exactly one entry: an already-expired one if a bucket
// front holds one, otherwise the oldest live entry of the client holding the
// most. It reports whether anything was dropped.
func (c *Cache[T]) evictOneLocked(now time.Time) bool {
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
		if !found || BetterVictim(b.live, e.added, client, victimLive, victimAdded, victimClient) {
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

// countEvictionLocked records one displacement on this cache and reports it to
// the owner's OnEvict sink.
//
// Both are needed. The per-cache number is what a test or a diagnostic asks an
// instance for; the owner's total is what /metrics exports, because an
// instance does not outlive an operator editing its IdP profile. Editing,
// disabling, deleting or reloading a profile has package main's IdPRegistry
// compile a NEW provider with a fresh, zero cache (Upsert and ReplaceAll both
// rebuild r.live), so a metric summed over the LIVE instances falls — to zero
// if every provider is replaced. A Prometheus counter that decreases reads as
// a process restart, which erases the flood evidence the counter exists to
// carry and corrupts every rate() over the window (Codex review, PR #1633).
func (c *Cache[T]) countEvictionLocked() {
	c.evictions++
	if c.onEvict != nil {
		c.onEvict()
	}
}

// frontLocked returns the client's oldest still-present entry, advancing head
// past slots that have been removed, re-attributed to another client, or
// superseded by a later refresh of the same key — e.pos names the one slot a
// record is authoritative for.
func (c *Cache[T]) frontLocked(client string, b *bucket) (string, *entry[T], bool) {
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
func (c *Cache[T]) removeLocked(k string) {
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
// its TTL calls Set for a key the bucket already lists: Set removes the old
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
// Set most recently wrote, so the bucket's order still matches entry age and
// frontLocked still yields the client's oldest entry.
func (c *Cache[T]) compactLocked(client string, b *bucket) {
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
func (c *Cache[T]) Evictions() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evictions
}

// Len reports the number of entries currently held, live or expired.
func (c *Cache[T]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Expiry reports the absolute instant the entry under key stops being served,
// and whether an entry is recorded. It does NOT apply the expiry check: callers
// use it to assert ON the recorded deadline (that a positive verdict was
// clamped to the token's own declared lifetime rather than the backend's TTL).
func (c *Cache[T]) Expiry(key string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return time.Time{}, false
	}
	return e.expiry, true
}

// BetterVictim reports whether candidate (live, added, client) is a better
// eviction victim than the incumbent (bestLive, bestAdded, bestClient).
// Ordering: most live entries first, then the oldest entry, then the
// lexicographically smaller client key — total and deterministic, so the
// victim never depends on Go's map iteration order. It is internal/authstate's
// ordering; package main's local credential cache (store.go) uses this
// definition too.
func BetterVictim(live int, added time.Time, client string, bestLive int, bestAdded time.Time, bestClient string) bool {
	switch {
	case live != bestLive:
		return live > bestLive
	case !added.Equal(bestAdded):
		return added.Before(bestAdded)
	default:
		return client < bestClient
	}
}
