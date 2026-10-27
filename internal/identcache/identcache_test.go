package identcache

// The eviction policy's own gates (CHAOS-76), moved from package main's
// auth_identity_cache_chaos_test.go with the engine (ADR-0041) under unchanged
// names. They need nothing from the application: every cache here is built
// with New and the production cap. The gates that exercise backends, dispatch
// and /metrics stay in package main as integration tests.

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// testCap is the cap package main passes (maxAuthCacheSize). The gates below
// are sized against it, so they measure the production geometry rather than a
// toy one; a root test pins the binding to that same value.
const testCap = 5_000

// honestEntryTTL is comfortably longer than any gate here runs, so an entry
// that disappears was EVICTED rather than expired.
const honestEntryTTL = time.Hour

// verdict stands in for package main's *Identity: the cache is generic and
// never looks inside the value.
type verdict struct{ Sub string }

func newTestCache() *Cache[*verdict] {
	return New[*verdict](Options{MaxEntries: testCap})
}

// keysRetainedForTest reports how many key slots a client's bucket still holds,
// consumed positions included. It is the only way to observe the compaction
// trap documented on compactLocked — the entry COUNT stays at the cap under a
// flood while the backing array grows with total request count.
func (c *Cache[T]) keysRetainedForTest(client string) int {
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
func (c *Cache[T]) bucketDriftForTest() (drift int, client string) {
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

// An expired entry is free to drop — it would have been a miss anyway — so
// evicting a LIVE entry while a dead one occupies capacity is pure loss. The
// pre-fix policy did exactly that, and nothing else reclaimed the dead ones.
//
// The population is inverted on purpose: ONE expired entry in a cache that is
// otherwise full of live ones. An arbitrary victim is therefore a live entry
// with probability (cap-1)/cap, which makes this a deterministic oracle rather
// than a coin flip.
func TestChaos76_ExpiredEntriesAreEvictedBeforeLiveOnes(t *testing.T) {
	c := newTestCache()

	// One expired entry, alone in its bucket so it is that bucket's FRONT —
	// the only positions the bounded eviction scan examines.
	c.Set("dead", "dead-client", nil, false, time.Nanosecond)
	live := make([]string, 0, testCap-1)
	for i := 0; i < testCap-1; i++ {
		k := fmt.Sprintf("live-%d", i)
		live = append(live, k)
		c.Set(k, fmt.Sprintf("live-client-%d", i%4), &verdict{Sub: "alice"}, true, honestEntryTTL)
	}
	time.Sleep(5 * time.Millisecond) // let the one short-TTL entry lapse

	c.Set("newcomer", "newcomer-client", nil, false, honestEntryTTL)

	if _, _, hit := c.Get("dead"); hit {
		t.Error("the expired entry survived the eviction that the newcomer forced")
	}
	survivors := 0
	for _, k := range live {
		if _, _, hit := c.Get(k); hit {
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
	c := newTestCache()
	c.Set("k", "client", &verdict{Sub: "alice"}, true, time.Nanosecond)
	time.Sleep(5 * time.Millisecond)

	if c.Len() != 1 {
		t.Fatalf("precondition: len = %d, want 1", c.Len())
	}
	if _, _, hit := c.Get("k"); hit {
		t.Fatal("an expired entry was reported as a hit")
	}
	if got := c.Len(); got != 0 {
		t.Fatalf("a lookup left %d expired entr(ies) occupying capacity, want 0 (CHAOS-76)", got)
	}
}

// The victim must never depend on Go's map iteration order, or the policy is
// untestable and an attacker's odds change per process.
func TestChaos76_EvictionVictimIsDeterministic(t *testing.T) {
	victimOf := func() string {
		c := newTestCache()
		// Three clients of different sizes, all live. "big" is the largest
		// holder, so its oldest entry is the only correct victim.
		c.Set("small", "small-client", nil, true, honestEntryTTL)
		c.Set("medium-0", "medium-client", nil, true, honestEntryTTL)
		c.Set("medium-1", "medium-client", nil, true, honestEntryTTL)
		for i := 0; i < testCap-3; i++ {
			c.Set(fmt.Sprintf("big-%d", i), "big-client", nil, true, honestEntryTTL)
		}
		c.Set("newcomer", "newcomer-client", nil, true, honestEntryTTL)

		for _, k := range []string{"small", "medium-0", "medium-1", "big-0"} {
			if _, _, hit := c.Get(k); !hit {
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
	c := newTestCache()
	c.Set("lonely", "lonely-client", &verdict{Sub: "alice"}, true, honestEntryTTL)
	// 6x the cap: under an arbitrary-victim policy the lonely entry's survival
	// probability is (1-1/cap)^(6*cap) = e^-6, about one run in four hundred.
	for i := 0; i < 6*testCap; i++ {
		c.Set(fmt.Sprintf("flood-%d", i), fmt.Sprintf("flood-client-%d", i%4), nil, false, honestEntryTTL)
	}
	if _, _, hit := c.Get("lonely"); !hit {
		t.Fatal("a single-entry holder was displaced while four larger holders remained (CHAOS-76)")
	}
}

// The compaction trap: under a sustained flood the un-consumed window stays
// pinned at the cap while head and len advance together forever, so a
// window-based compaction test never fires and the backing array grows with
// total request count — a memory leak reachable by the same flood the
// eviction policy exists to survive.
func TestChaos76_BucketBackingSliceDoesNotGrowWithRequestCount(t *testing.T) {
	c := newTestCache()
	const flood = 6 * testCap
	for i := 0; i < flood; i++ {
		c.Set(fmt.Sprintf("k-%d", i), "one-flooding-client", nil, false, honestEntryTTL)
	}
	if got := c.Len(); got > testCap {
		t.Fatalf("cache holds %d entries, cap is %d", got, testCap)
	}
	if got := c.keysRetainedForTest("one-flooding-client"); got > 4*testCap {
		t.Fatalf("one client's bucket retains %d key slots after %d requests against a cap of %d — "+
			"the backing array is growing with request count (CHAOS-76)", got, flood, testCap)
	}
}

// Displacement must be VISIBLE: it is the operator's only signal that cached
// verdicts are being thrown away, and every eviction costs somebody a full
// backend round trip or a denial during a cooldown.
func TestChaos76_EvictionsAreCounted(t *testing.T) {
	c := newTestCache()
	for i := 0; i < testCap+64; i++ {
		c.Set(fmt.Sprintf("k-%d", i), "client", nil, false, honestEntryTTL)
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
	c := newTestCache()

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
				c.Set(k, client, &verdict{Sub: "alice"}, true, honestEntryTTL)
				c.Get(k)
				// Re-set the same key: the overwrite path has to remove the old
				// entry from its bucket before re-attributing it, or the live
				// count double-counts and the fairness ordering goes wrong.
				c.Set(k, client, &verdict{Sub: "alice"}, true, honestEntryTTL)
				c.Get(fmt.Sprintf("w%d-k%d", (w+1)%workers, i))
			}
		}(w)
	}
	wg.Wait()

	if got := c.Len(); got > testCap {
		t.Fatalf("cache holds %d entries after concurrent use, cap is %d", got, testCap)
	}
	// Every bucket's live count must equal what the entry map actually
	// attributes to that client.
	if drift, client := c.bucketDriftForTest(); drift != 0 {
		t.Fatalf("bucket live count for %q drifts from the entry map by %d — the eviction "+
			"policy reads live counts, so drift corrupts the victim choice (CHAOS-76)", client, drift)
	}
}

// Codex review finding on PR #1633, confirmed: re-verifying a credential after
// its TTL calls Set again for the SAME key. Set removes the old record and
// appends the key, so the bucket's key slice holds that key TWICE while live
// counts it once — and compactLocked kept BOTH slots, because it asks only
// whether c.entries[k] is present and the newest record answers yes for every
// historical slot. So nothing reclaimed the duplicates and b.keys grew with
// total request count behind a bounded map.
//
// This is the same trap compactLocked's own comment warns about, reached by a
// different route, and the realistic shape is ordinary: the fairness key is a
// client address, so one NAT'd office is ONE bucket holding many live
// credentials, each re-verified every TTL.
func TestChaos76_RefreshingACredentialDoesNotGrowItsBucketForever(t *testing.T) {
	c := newTestCache()
	const (
		client    = "198.51.100.7"
		creds     = 20   // distinct credentials behind one NAT'd address
		refreshes = 2000 // each re-verified after its TTL lapses
	)

	// Keep the bucket alive throughout: with more than one live entry the
	// bucket is never dropped, which is the state the duplicates accumulate in.
	for i := 0; i < creds; i++ {
		c.Set(fmt.Sprintf("cred-%d", i), client, &verdict{Sub: "alice"}, true, honestEntryTTL)
	}
	for r := 0; r < refreshes; r++ {
		c.Set(fmt.Sprintf("cred-%d", r%creds), client, &verdict{Sub: "alice"}, true, honestEntryTTL)
	}

	if got := c.Len(); got != creds {
		t.Fatalf("entry count = %d, want %d — refreshes must replace, not accumulate", got, creds)
	}
	// The bucket may carry some slack, but it must not scale with request count.
	if got := c.keysRetainedForTest(client); got > 8*creds {
		t.Fatalf("one client's bucket retains %d key slots for %d live credentials after "+
			"%d refreshes — the backing array is growing with request count, behind a "+
			"bounded map (CHAOS-76, Codex finding on #1633)", got, creds, refreshes)
	}
}

// Codex review finding on PR #1633 (second pass), confirmed by probe: set on a
// key the bucket already lists leaves the old slot in place and appends a new
// one, so a bucket reads [A, B, A] while live counts two. A presence test
// cannot reject the leading A, because the NEW record answers "present" for
// every historical position of that key — so frontLocked returned the FRESHLY
// REFRESHED entry as the client's oldest, and eviction preferred it to the
// genuinely older B. Compaction deduplicates but is skipped at eight keys or
// fewer, so small buckets stayed wrong indefinitely.
//
// Measured before the fix: keys=[A B A], front=A, with A.added NEWER than
// B.added.
func TestChaos76_RefreshDoesNotMakeAnEntryLookLikeItsClientsOldest(t *testing.T) {
	c := newTestCache()
	const client = "198.51.100.7"

	c.Set("A", client, &verdict{Sub: "a"}, true, honestEntryTTL)
	time.Sleep(2 * time.Millisecond)
	c.Set("B", client, &verdict{Sub: "b"}, true, honestEntryTTL)
	time.Sleep(2 * time.Millisecond)
	// Refresh A. B keeps the bucket alive, which is the state the stale slot
	// survives in, and the bucket is far too small for compaction to fire.
	c.Set("A", client, &verdict{Sub: "a"}, true, honestEntryTTL)

	c.mu.Lock()
	k, front, ok := c.frontLocked(client, c.buckets[client])
	addedA, addedB := c.entries["A"].added, c.entries["B"].added
	c.mu.Unlock()

	if !ok {
		t.Fatal("frontLocked found no entry for a client holding two")
	}
	if addedB.After(addedA) {
		t.Fatalf("precondition: B should be the older entry (A=%s B=%s)", addedA, addedB)
	}
	if k != "B" {
		t.Fatalf("frontLocked = %q, want \"B\" — the client's genuinely oldest entry. Returning the "+
			"just-refreshed entry makes eviction take a verdict written moments ago in preference "+
			"to an older one, and if the backend then enters its cooldown that client is denied "+
			"despite having just been verified (CHAOS-76)", k)
	}
	if !front.added.Equal(addedB) {
		t.Errorf("front entry's added = %s, want B's %s", front.added, addedB)
	}
}
