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

	// victims and expiries are the eviction index: binary heaps over the
	// buckets that hold a live entry, ordered by victimLess and expiryLess
	// respectively. They answer the only two questions evictOneLocked asks —
	// "is any bucket front expired?" and "which front is the fairness victim?"
	// — at the root, in place of a scan over every bucket.
	//
	// Both hold the same *bucket values and are maintained together by
	// syncBucketLocked. Their length tracks the live bucket count exactly, so
	// the backing arrays peak at the cap and do not grow with request count
	// (the trap compactLocked documents for bucket.keys).
	//
	// The zero Cache is usable: both are nil slices and heapPush appends.
	victims  []*bucket
	expiries []*bucket
}

// ─── Eviction-index heaps ────────────────────────────────────────────────────
//
// A hand-rolled binary heap rather than container/heap: this package is a
// stdlib leaf whose import surface is `sync` and `time` only, pinned by
// TestIdentcacheBoundary_NoApplicationDependenciesOrSharedState (ADR-0041).
// Each bucket carries its own index per heap (bucket.pos), so a bucket whose
// front or live count changed is repositioned in place instead of being
// searched for.

// heapSwap exchanges two slots and keeps both buckets' recorded index correct.
func heapSwap(h []*bucket, slot, i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].pos[slot] = i
	h[j].pos[slot] = j
}

// heapUp sifts the bucket at i towards the root and returns where it came to
// rest.
func heapUp(h []*bucket, slot int, less func(a, b *bucket) bool, i int) int {
	for i > 0 {
		parent := (i - 1) / 2
		if !less(h[i], h[parent]) {
			break
		}
		heapSwap(h, slot, i, parent)
		i = parent
	}
	return i
}

// heapDown sifts the bucket at i away from the root.
func heapDown(h []*bucket, slot int, less func(a, b *bucket) bool, i int) {
	n := len(h)
	for {
		left := 2*i + 1
		if left >= n {
			return
		}
		best := left
		if right := left + 1; right < n && less(h[right], h[left]) {
			best = right
		}
		if !less(h[best], h[i]) {
			return
		}
		heapSwap(h, slot, i, best)
		i = best
	}
}

// heapPush inserts b, which must not already be in this heap.
func heapPush(h *[]*bucket, slot int, less func(a, b *bucket) bool, b *bucket) {
	*h = append(*h, b)
	b.pos[slot] = len(*h) - 1
	heapUp(*h, slot, less, len(*h)-1)
}

// heapRemove takes b out of this heap. It is a no-op when b is absent, so a
// bucket that never held a live entry can be removed unconditionally.
func heapRemove(h *[]*bucket, slot int, less func(a, b *bucket) bool, b *bucket) {
	i := b.pos[slot]
	if i < 0 {
		return
	}
	last := len(*h) - 1
	if i != last {
		heapSwap(*h, slot, i, last)
	}
	(*h)[last] = nil // drop the reference so an evicted bucket can be collected
	*h = (*h)[:last]
	b.pos[slot] = -1
	if i < len(*h) {
		if heapUp(*h, slot, less, i) == i {
			heapDown(*h, slot, less, i)
		}
	}
}

// heapFix repositions b after its ordering key changed. It is a no-op when b
// is absent.
func heapFix(h []*bucket, slot int, less func(a, b *bucket) bool, b *bucket) {
	i := b.pos[slot]
	if i < 0 {
		return
	}
	if heapUp(h, slot, less, i) == i {
		heapDown(h, slot, less, i)
	}
}

// heapPeek returns the root bucket, or nil when the heap is empty.
func heapPeek(h []*bucket) *bucket {
	if len(h) == 0 {
		return nil
	}
	return h[0]
}

// syncBucketLocked re-establishes b's memoised front and its place in both
// eviction heaps. It must be called after anything that can change the
// bucket's front entry, its key slice, its head or its live count, and it is
// the ONLY writer of the memo the heaps are ordered on.
//
// A bucket with no live entry left is removed from both heaps: the heaps hold
// exactly the buckets eviction may choose from, which is why evictOneLocked
// can trust its two roots without re-validating them.
func (c *Cache[T]) syncBucketLocked(client string, b *bucket) {
	k, e, ok := c.frontLocked(client, b)
	if !ok {
		heapRemove(&c.victims, slotVictim, victimLess, b)
		heapRemove(&c.expiries, slotExpiry, expiryLess, b)
		b.frontKey, b.frontAdded, b.frontExpiry = "", time.Time{}, time.Time{}
		return
	}
	b.frontKey, b.frontAdded, b.frontExpiry = k, e.added, e.expiry
	if b.pos[slotVictim] < 0 {
		heapPush(&c.victims, slotVictim, victimLess, b)
	} else {
		heapFix(c.victims, slotVictim, victimLess, b)
	}
	if b.pos[slotExpiry] < 0 {
		heapPush(&c.expiries, slotExpiry, expiryLess, b)
	} else {
		heapFix(c.expiries, slotExpiry, expiryLess, b)
	}
}

// bumpLiveLocked repositions b after ONLY its live count changed — appending a
// key to a bucket that already had a front, or removing a key that was not the
// front. The front entry is untouched, so the memo stays correct and expiryLess,
// which reads only the deadline and the client, is unaffected: just the
// fairness ordering's leading term moved.
//
// It exists to keep the map lookup inside frontLocked off the common path.
// Without it, syncBucketLocked ran twice per insertion at the cap — once for
// the bucket eviction took from, once for the bucket the new entry joined —
// and paid that lookup both times, which cost ~30% on a cache whose entries
// are concentrated in a handful of buckets.
func (c *Cache[T]) bumpLiveLocked(b *bucket) {
	heapFix(c.victims, slotVictim, victimLess, b)
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
	// client is the fairness key this bucket belongs under. It duplicates the
	// c.buckets map key because the eviction heaps hold *bucket directly and
	// their ordering reads it (victimLess), so a comparison must not need a
	// reverse lookup.
	client string

	keys []string
	head int
	live int

	// frontKey, frontAdded and frontExpiry memoise what frontLocked returns:
	// the client's oldest still-present entry. They are re-established by
	// syncBucketLocked after ANY change to keys, head, live or the entry map,
	// and they are what the two heaps below are ordered on.
	//
	// The memo exists because the eviction scan used to call frontLocked for
	// every bucket, and frontLocked's cost is a map lookup on a string key.
	// See evictOneLocked.
	frontKey    string
	frontAdded  time.Time
	frontExpiry time.Time

	// pos is this bucket's index in each eviction heap, or -1 when absent. A
	// bucket is in both heaps exactly while it holds a live entry.
	pos [2]int
}

// The two eviction heaps a bucket is tracked in. Both are ordered on the
// bucket's memoised front, so a bucket occupies one slot in each.
const (
	slotVictim = 0 // ordered by victimLess: root is the fairness victim
	slotExpiry = 1 // ordered by expiryLess: root is the earliest-expiring front
)

// victimLess reports whether a is a better eviction victim than b, under the
// exported BetterVictim ordering applied to the two buckets' memoised fronts.
// It is the heap ordering for c.victims, so that heap's root is exactly the
// entry the old full scan over c.buckets used to select.
func victimLess(a, b *bucket) bool {
	return BetterVictim(a.live, a.frontAdded, a.client, b.live, b.frontAdded, b.client)
}

// expiryLess orders c.expiries by front deadline, so its root is the front
// that expires soonest. The client key breaks exact ties, keeping the order
// total and independent of insertion history.
func expiryLess(a, b *bucket) bool {
	if !a.frontExpiry.Equal(b.frontExpiry) {
		return a.frontExpiry.Before(b.frontExpiry)
	}
	return a.client < b.client
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
//
// # A known, accepted cost on the refresh path (PERF-IDENTCACHE-1)
//
// Re-verifying a credential the cache already holds — Set on an existing key —
// removes the old record and appends the key again, so the bucket's live count
// goes down by one and straight back up. Each step repositions the bucket in
// the fairness heap, and the two moves usually cancel: measured at +362 ns
// (439 ns → 801 ns, BenchmarkRefreshAtCap/clients=1000) against the old
// implementation, which did almost nothing here because removing the existing
// key takes the entry count below the cap and the eviction loop below then
// never runs.
//
// It is deliberately NOT optimised away. Collapsing the two moves means
// deferring the first bucket's index fixup past the eviction loop on the
// strength of "removing an existing key means the loop cannot run" — a
// cross-function invariant inside an eviction policy that is a security
// control, bought for 362 ns on a path that runs once per cached credential per
// TTL (≈17/s at the 5,000 cap and a five-minute TTL) and exists to avoid a
// millisecond-scale directory bind. The insertion path it pays for is three
// orders of magnitude better off; see evictOneLocked.
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
		b = &bucket{client: client, pos: [2]int{-1, -1}}
		c.buckets[client] = b
	}
	b.keys = append(b.keys, key)
	c.entries[key] = &entry[T]{
		val: val, ok: ok, client: client, added: now, expiry: expiry,
		pos: len(b.keys) - 1,
	}
	b.live++
	// Compaction renumbers positions and resets head, but it keeps every live
	// key in age order, so the bucket's front is still the same entry and the
	// memo still describes it.
	c.compactLocked(client, b)
	if b.live > 1 && b.pos[slotVictim] >= 0 {
		// The bucket already held a live entry, so it is already in both heaps
		// with a valid memo, and the key just appended is younger than its
		// front. Only the live term moved.
		c.bumpLiveLocked(b)
		return
	}
	// A bucket that was empty — or new — takes its front from this entry and
	// enters both heaps here.
	c.syncBucketLocked(client, b)
}

// evictOneLocked drops exactly one entry: an already-expired one if a bucket
// front holds one, otherwise the oldest live entry of the client holding the
// most. It reports whether anything was dropped.
//
// # Why this is an index lookup and not a scan (PERF-IDENTCACHE-1)
//
// This runs under c.mu on the proxy CREDENTIAL path, once per insertion for as
// long as the cache is at its cap — which, at main's maxAuthCacheSize of 5,000
// and a fairness key that is the client's own address (clientFairnessKey), is
// the steady state of any deployment with a few thousand active client
// addresses. The previous implementation answered both questions below by
// iterating every bucket and calling frontLocked on each, so each insertion
// cost one map lookup per DISTINCT CLIENT:
//
//	BenchmarkStoreAtCap  clients=1      364 ns/op
//	                     clients=100   3,300 ns/op
//	                     clients=1000 49,974 ns/op
//	                     clients=5000 271,017 ns/op
//
// 271 µs of lock-held work per cached verdict is both a throughput ceiling on
// the credential path and a latency floor for every concurrent Get waiting on
// the same mutex, and the shape is linear in a number an UNAUTHENTICATED client
// contributes to: the key space is caller-supplied (see the package doc), so
// the cost of the fairness policy grew with the very flood the policy exists to
// survive.
//
// Both answers are now heap roots, maintained incrementally by
// syncBucketLocked, which makes an insertion at the cap O(log clients) instead
// of O(clients) and removes the client-count term from the measurement
// entirely. The selection is unchanged: c.victims is ordered by the same
// exported BetterVictim predicate the scan applied, so it yields the same
// entry.
//
// One deliberate refinement. The scan evicted whichever expired front Go's
// randomised map iteration reached first; this takes the EARLIEST-expiring
// one. Both satisfy "an already-expired one if a bucket front holds one" and
// the new choice is deterministic, which is the property the rest of this
// policy is built on (BetterVictim exists so the victim never depends on map
// order). TestChaos76_EvictionPrefersTheEarliestExpiredFront pins it.
func (c *Cache[T]) evictOneLocked(now time.Time) bool {
	// An expired entry is free to drop and is always the better victim.
	if b := heapPeek(c.expiries); b != nil && !now.Before(b.frontExpiry) {
		c.removeLocked(b.frontKey)
		c.countEvictionLocked()
		return true
	}
	if b := heapPeek(c.victims); b != nil {
		c.removeLocked(b.frontKey)
		c.countEvictionLocked()
		return true
	}
	return false
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
		// Leaving c.buckets must also leave the eviction index, or a root
		// would name an entry that is no longer reachable.
		heapRemove(&c.victims, slotVictim, victimLess, b)
		heapRemove(&c.expiries, slotExpiry, expiryLess, b)
		return
	}
	if k != b.frontKey {
		// The bucket survives and its front entry is untouched, so only the
		// live term of its fairness key moved.
		c.bumpLiveLocked(b)
		return
	}
	// The front itself went: recompute it and reposition in both heaps.
	c.syncBucketLocked(e.client, b)
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
		heapRemove(&c.victims, slotVictim, victimLess, b)
		heapRemove(&c.expiries, slotExpiry, expiryLess, b)
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
