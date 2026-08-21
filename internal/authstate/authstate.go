// Package authstate is the bounded store for short-lived interactive-login
// callback state: the OIDC PKCE verifier + nonce, and the SAML AuthnRequest ID.
// It is a self-contained stdlib-only leaf per ADR-0002.
//
// # Why this is its own engine
//
// The state it holds is created SPECULATIVELY, on an UNAUTHENTICATED request.
// Culvert mints an entry every time it resolves a captive-portal login URL for
// a client that has not authenticated yet — that resolution happens on the
// proxy's no-credentials path (proxy.go) and on the public /auth/select page.
// So the population of this store is driven by whoever can send the gateway a
// request, not by whoever can log in.
//
// That makes the EVICTION POLICY a security control, not a housekeeping
// detail. Both stores previously evicted "one arbitrary entry" — a Go map
// range that stops after the first key, i.e. a uniformly random live entry.
// Under a flood from a single unauthenticated source, every insertion past the
// cap destroyed a random OTHER user's in-flight login state, so real users'
// callbacks came back "invalid or expired state" and nobody could complete an
// SSO login. Failure was closed (no bypass), but the whole gateway's
// authentication was remotely deniable by an anonymous client.
//
// # The policy
//
// Entries are attributed to a CLIENT KEY, and eviction always takes the OLDEST
// entry of the client holding the MOST live entries (ties broken by the oldest
// entry, then by client key, so the choice is deterministic and testable).
//
// The property that buys: a client can only evict its own state until it is no
// longer the largest holder. One flooding source therefore evicts ITSELF, and
// a victim who holds a single entry is untouchable until every other client is
// down to one entry too — i.e. an attacker needs as many distinct client keys
// as the cap before it can displace one honest login. That is the difference
// between "one host with a for-loop" and "a thousand distinct source
// addresses", on a control whose failure mode is a fleet-wide login outage.
//
// Nothing else about the contract changes: entries still expire on a TTL, the
// store is still hard-capped, lookups are still exact-match on an unguessable
// state token, and an evicted or expired entry still fails the callback CLOSED.
package authstate

import (
	"sync"
	"time"
)

// Store holds short-lived login-callback state of type T, keyed by an
// unguessable state token, bounded by a TTL and a hard entry cap.
//
// The zero value is not usable; construct with New or NewWithClock. All
// methods are safe for concurrent use.
type Store[T any] struct {
	mu         sync.Mutex
	entries    map[string]*record[T]
	buckets    map[string]*bucket
	ttl        time.Duration
	maxEntries int
	now        func() time.Time

	evictions uint64
}

type record[T any] struct {
	val     T
	client  string
	created time.Time
}

// bucket is one client's live entries, in creation order.
//
// keys may contain STALE positions (a key that has since been popped, expired,
// evicted, or re-Set under a different client). They are skipped lazily from
// the front and compacted amortically, so a bucket never outgrows a small
// multiple of the client's live count.
type bucket struct {
	keys []string
	head int
	live int
}

// New returns a store bounded by ttl and maxEntries, using the wall clock.
// A non-positive maxEntries is treated as 1 (a store that cannot hold anything is a
// silent outage; a store of one is at least honest about the bound).
func New[T any](ttl time.Duration, maxEntries int) *Store[T] {
	return NewWithClock[T](ttl, maxEntries, time.Now)
}

// NewWithClock is New with an injected clock, so expiry and eviction ordering
// are deterministic under test.
func NewWithClock[T any](ttl time.Duration, maxEntries int, now func() time.Time) *Store[T] {
	if maxEntries < 1 {
		maxEntries = 1
	}
	if now == nil {
		now = time.Now
	}
	return &Store[T]{
		entries:    make(map[string]*record[T]),
		buckets:    make(map[string]*bucket),
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        now,
	}
}

// Set stores val under key, attributed to client.
//
// client is an opaque fairness key — it is never compared to anything a caller
// supplies later and never reaches a lookup, so a wrong or empty value can
// only make eviction less fair, never admit an entry that should not be
// admitted. An empty client is a legitimate value: all such entries share one
// bucket and evict each other.
//
// Re-Setting an existing key replaces it (and re-attributes it), matching the
// map-assignment semantics this store replaced.
func (s *Store[T]) Set(key, client string, val T) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.removeLocked(key)
	if len(s.entries) >= s.maxEntries {
		s.sweepExpiredLocked(now)
	}
	// Loop rather than evict once: maxEntries can be lowered between calls, and an
	// evictOneLocked that finds nothing to take must not spin.
	for len(s.entries) >= s.maxEntries {
		if !s.evictOneLocked() {
			break
		}
	}

	s.entries[key] = &record[T]{val: val, client: client, created: now}
	b := s.buckets[client]
	if b == nil {
		b = &bucket{}
		s.buckets[client] = b
	}
	b.keys = append(b.keys, key)
	b.live++
	s.compactLocked(client, b)
}

// Peek returns the value for key without consuming it. An expired entry is
// removed and reported as absent.
func (s *Store[T]) Peek(key string) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var zero T
	rec, ok := s.entries[key]
	if !ok {
		return zero, false
	}
	if s.expired(rec) {
		s.removeLocked(key)
		return zero, false
	}
	return rec.val, true
}

// Pop consumes the entry for key. A found-but-expired entry is consumed and
// reported as absent — single-use semantics hold either way, so a replayed
// state token can never be reused after its first callback.
func (s *Store[T]) Pop(key string) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var zero T
	rec, ok := s.entries[key]
	if !ok {
		return zero, false
	}
	s.removeLocked(key)
	if s.expired(rec) {
		return zero, false
	}
	return rec.val, true
}

// Len returns the number of entries currently held (expired-but-not-yet-swept
// entries included; they are indistinguishable from live ones for capacity).
func (s *Store[T]) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Evictions returns the number of entries dropped to make room. A rising
// counter means login state is being displaced before it could be used — the
// signal that the cap is too small for the deployment, or that something is
// flooding the login path.
func (s *Store[T]) Evictions() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evictions
}

// Clients returns the number of distinct client keys currently holding at
// least one entry. Exported for the fairness tests and for operator-facing
// occupancy reporting.
func (s *Store[T]) Clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buckets)
}

// ── internals (all callers hold s.mu) ───────────────────────────────────────

func (s *Store[T]) expired(rec *record[T]) bool {
	return s.now().Sub(rec.created) > s.ttl
}

// removeLocked deletes key and decrements its client's live count. The key is
// deliberately NOT spliced out of the bucket's slice: removal is O(1) and the
// stale position is skipped from the front (frontLocked) and compacted away
// (compactLocked).
func (s *Store[T]) removeLocked(key string) {
	rec, ok := s.entries[key]
	if !ok {
		return
	}
	delete(s.entries, key)
	b := s.buckets[rec.client]
	if b == nil {
		return
	}
	b.live--
	if b.live <= 0 {
		delete(s.buckets, rec.client)
	}
}

func (s *Store[T]) sweepExpiredLocked(now time.Time) {
	for k, rec := range s.entries {
		if now.Sub(rec.created) > s.ttl {
			s.removeLocked(k)
		}
	}
}

// frontLocked returns the oldest live key of client's bucket, advancing past
// stale positions. It reports false once the bucket holds nothing of ours.
func (s *Store[T]) frontLocked(client string, b *bucket) (string, *record[T], bool) {
	for b.head < len(b.keys) {
		k := b.keys[b.head]
		if rec, ok := s.entries[k]; ok && rec.client == client {
			return k, rec, true
		}
		b.head++
	}
	b.keys = b.keys[:0]
	b.head = 0
	return "", nil, false
}

// evictOneLocked drops the oldest entry of the client holding the most live
// entries. See the package comment for why the victim is chosen this way and
// not at random.
//
// Cost: one pass over the distinct client keys (bounded by the cap) plus an
// amortised O(1) front-pop. It runs only when the store is at capacity.
func (s *Store[T]) evictOneLocked() bool {
	var (
		victimClient string
		victimKey    string
		victimBucket *bucket
		victimOldest time.Time
		found        bool
	)
	for client, b := range s.buckets {
		k, rec, ok := s.frontLocked(client, b)
		if !ok {
			continue
		}
		if !found || better(b.live, rec.created, client, victimBucket.live, victimOldest, victimClient) {
			victimClient, victimKey, victimBucket, victimOldest, found = client, k, b, rec.created, true
		}
	}
	if !found {
		return false
	}
	s.removeLocked(victimKey)
	s.evictions++
	return true
}

// better reports whether candidate (live, created, client) is a better
// eviction victim than the incumbent. Ordering: most live entries first, then
// the oldest entry, then the lexicographically smaller client key — total and
// deterministic, so the victim never depends on Go's map iteration order.
func better(live int, created time.Time, client string, bestLive int, bestCreated time.Time, bestClient string) bool {
	switch {
	case live != bestLive:
		return live > bestLive
	case !created.Equal(bestCreated):
		return created.Before(bestCreated)
	default:
		return client < bestClient
	}
}

// compactLocked drops stale positions once a bucket's backing slice has grown
// past a small multiple of what the client actually holds.
//
// The condition is on len(b.keys), NOT on the un-consumed window
// len(b.keys)-b.head: under a sustained flood the window stays pinned at the
// cap while head and len advance together forever, so a window-based test
// never fires and the backing array grows with total request count — a memory
// leak reachable by exactly the unauthenticated flood this store exists to
// survive. Keyed on total length, a bucket is rebuilt every time it grows by
// roughly its own live size, which is amortised O(1) per Set and bounds the
// slice at ~2x live.
func (s *Store[T]) compactLocked(client string, b *bucket) {
	if len(b.keys) <= 2*b.live+8 {
		return
	}
	kept := b.keys[:0]
	for _, k := range b.keys[b.head:] {
		if rec, ok := s.entries[k]; ok && rec.client == client {
			kept = append(kept, k)
		}
	}
	b.keys = kept
	b.head = 0
}
