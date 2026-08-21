package authstate

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// clk is a deterministic, manually advanced clock.
type clk struct {
	mu sync.Mutex
	t  time.Time
}

func newClk() *clk {
	return &clk{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *clk) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clk) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ── Positive: the plain contract ────────────────────────────────────────────

func TestSetPeekPop(t *testing.T) {
	c := newClk()
	s := NewWithClock[string](10*time.Minute, 8, c.now)

	s.Set("state1", "client-a", "verifier-1")

	if got, ok := s.Peek("state1"); !ok || got != "verifier-1" {
		t.Fatalf("Peek = (%q, %v), want (verifier-1, true)", got, ok)
	}
	// Peek does not consume.
	if got, ok := s.Peek("state1"); !ok || got != "verifier-1" {
		t.Fatalf("second Peek = (%q, %v), want (verifier-1, true)", got, ok)
	}
	if got, ok := s.Pop("state1"); !ok || got != "verifier-1" {
		t.Fatalf("Pop = (%q, %v), want (verifier-1, true)", got, ok)
	}
	// Pop consumes: a replayed state token is dead.
	if _, ok := s.Pop("state1"); ok {
		t.Error("Pop after Pop must not find the entry (single-use state)")
	}
	if _, ok := s.Peek("state1"); ok {
		t.Error("Peek after Pop must not find the entry")
	}
	if s.Len() != 0 || s.Clients() != 0 {
		t.Errorf("after Pop: Len=%d Clients=%d, want 0/0", s.Len(), s.Clients())
	}
}

func TestSetReplacesExistingKey(t *testing.T) {
	c := newClk()
	s := NewWithClock[string](10*time.Minute, 8, c.now)
	s.Set("k", "client-a", "first")
	s.Set("k", "client-b", "second")

	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (re-Set must replace, not duplicate)", s.Len())
	}
	if s.Clients() != 1 {
		t.Fatalf("Clients = %d, want 1 (the old attribution must be released)", s.Clients())
	}
	if got, _ := s.Pop("k"); got != "second" {
		t.Errorf("Pop = %q, want second", got)
	}
}

// ── Negative: absent, expired, malformed-ish inputs ─────────────────────────

func TestMissingKey(t *testing.T) {
	s := New[string](time.Minute, 8)
	if _, ok := s.Peek("nope"); ok {
		t.Error("Peek of an unknown key must be false")
	}
	if _, ok := s.Pop("nope"); ok {
		t.Error("Pop of an unknown key must be false")
	}
	if _, ok := s.Peek(""); ok {
		t.Error("Peek of the empty key must be false")
	}
}

func TestExpiryFailsClosed(t *testing.T) {
	c := newClk()
	s := NewWithClock[string](10*time.Minute, 8, c.now)

	s.Set("peeked", "a", "v")
	s.Set("popped", "a", "v")
	c.advance(10*time.Minute + time.Nanosecond)

	if _, ok := s.Peek("peeked"); ok {
		t.Error("Peek must reject an expired entry")
	}
	if _, ok := s.Pop("popped"); ok {
		t.Error("Pop must reject an expired entry")
	}
	// Both must also be gone — an expired entry is consumed, never left to be
	// hit again by a retry.
	if s.Len() != 0 {
		t.Errorf("Len = %d, want 0 (expired entries are removed on access)", s.Len())
	}
}

func TestExpiryBoundary(t *testing.T) {
	c := newClk()
	s := NewWithClock[string](10*time.Minute, 8, c.now)
	s.Set("k", "a", "v")

	c.advance(10 * time.Minute) // exactly at the TTL — still valid
	if _, ok := s.Peek("k"); !ok {
		t.Error("an entry exactly at the TTL must still be valid")
	}
	c.advance(time.Nanosecond) // one tick past
	if _, ok := s.Peek("k"); ok {
		t.Error("an entry one tick past the TTL must be rejected")
	}
}

func TestEmptyClientKeyIsUsable(t *testing.T) {
	// An unresolvable client address must not break the store: all such
	// entries simply share one bucket.
	c := newClk()
	s := NewWithClock[string](time.Minute, 4, c.now)
	for i := range 6 {
		s.Set(fmt.Sprintf("k%d", i), "", "v")
	}
	if s.Len() != 4 {
		t.Errorf("Len = %d, want 4 (cap holds with an empty client key)", s.Len())
	}
}

// ── Boundary: the cap ───────────────────────────────────────────────────────

func TestCapIsNeverExceeded(t *testing.T) {
	c := newClk()
	const maxEntries = 16
	s := NewWithClock[int](time.Hour, maxEntries, c.now)
	for i := range 500 {
		s.Set(fmt.Sprintf("k%d", i), fmt.Sprintf("c%d", i%7), i)
		if n := s.Len(); n > maxEntries {
			t.Fatalf("after %d inserts Len = %d, want <= %d", i+1, n, maxEntries)
		}
	}
	if s.Len() != maxEntries {
		t.Errorf("Len = %d, want %d (a saturated store stays saturated)", s.Len(), maxEntries)
	}
}

func TestNonPositiveMaxIsClamped(t *testing.T) {
	s := New[string](time.Minute, 0)
	s.Set("k", "c", "v")
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (maxEntries<1 must clamp to 1, not to an unusable store)", s.Len())
	}
}

func TestExpiredEntriesAreReclaimedBeforeEviction(t *testing.T) {
	c := newClk()
	s := NewWithClock[string](time.Minute, 4, c.now)
	for i := range 4 {
		s.Set(fmt.Sprintf("old%d", i), "a", "v")
	}
	c.advance(2 * time.Minute) // everything above is now expired
	s.Set("fresh", "b", "v")

	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1 (the expiry sweep reclaims before any eviction)", s.Len())
	}
	if got := s.Evictions(); got != 0 {
		t.Errorf("Evictions = %d, want 0 (expired entries are swept, not counted as evictions)", got)
	}
	if _, ok := s.Peek("fresh"); !ok {
		t.Error("the new entry must be present")
	}
}

// ── Regression: the security property this store exists for ─────────────────

// TestFloodingClientEvictsOnlyItself is THE gate. One unauthenticated source
// hammering the login path must not be able to destroy another client's
// in-flight state. Under the previous "delete one arbitrary map key" policy
// the victim was chosen at random, so a flood of this size evicted the honest
// entry with overwhelming probability.
func TestFloodingClientEvictsOnlyItself(t *testing.T) {
	c := newClk()
	const maxEntries = 64
	s := NewWithClock[string](10*time.Minute, maxEntries, c.now)

	// An honest browser starts one login.
	s.Set("victim-state", "10.0.0.9", "victim-verifier")

	// A single unauthenticated source floods far past the cap.
	for i := range 100 * maxEntries {
		c.advance(time.Millisecond)
		s.Set(fmt.Sprintf("flood-%d", i), "198.51.100.7", "x")
	}

	if _, ok := s.Peek("victim-state"); !ok {
		t.Fatal("a single flooding client evicted an unrelated client's in-flight login state")
	}
	if s.Clients() != 2 {
		t.Errorf("Clients = %d, want 2 (victim + flooder)", s.Clients())
	}
}

// TestFloodingClientCannotStarveManyVictims is the same property at scale: the
// flooder must not be able to displace ANY of a population of honest clients
// that each hold a single entry.
func TestFloodingClientCannotStarveManyVictims(t *testing.T) {
	c := newClk()
	const maxEntries = 64
	s := NewWithClock[string](10*time.Minute, maxEntries, c.now)

	victims := make([]string, 0, 32)
	for i := range 32 {
		k := fmt.Sprintf("victim-%d", i)
		victims = append(victims, k)
		c.advance(time.Millisecond)
		s.Set(k, fmt.Sprintf("10.0.0.%d", i), "v")
	}
	for i := range 50 * maxEntries {
		c.advance(time.Millisecond)
		s.Set(fmt.Sprintf("flood-%d", i), "198.51.100.7", "x")
	}
	for _, k := range victims {
		if _, ok := s.Peek(k); !ok {
			t.Fatalf("victim %q was evicted by a single-source flood", k)
		}
	}
}

// TestEvictionTakesTheLargestHolderOldestEntry pins the policy itself, so a
// future "simplification" back to arbitrary eviction fails here.
func TestEvictionTakesTheLargestHolderOldestEntry(t *testing.T) {
	c := newClk()
	s := NewWithClock[string](time.Hour, 4, c.now)

	c.advance(time.Second)
	s.Set("big-oldest", "big", "v")
	c.advance(time.Second)
	s.Set("big-newer", "big", "v")
	c.advance(time.Second)
	s.Set("big-newest", "big", "v")
	c.advance(time.Second)
	s.Set("small", "small", "v") // store is now full: big=3, small=1

	c.advance(time.Second)
	s.Set("incoming", "other", "v")

	if _, ok := s.Peek("big-oldest"); ok {
		t.Error("eviction must take the largest holder's OLDEST entry")
	}
	for _, k := range []string{"big-newer", "big-newest", "small", "incoming"} {
		if _, ok := s.Peek(k); !ok {
			t.Errorf("%q must have survived", k)
		}
	}
	if got := s.Evictions(); got != 1 {
		t.Errorf("Evictions = %d, want 1", got)
	}
}

// TestEvictionIsDeterministic proves the victim never depends on Go's map
// iteration order: the same insertion sequence must evict the same key every
// time, across independent stores.
func TestEvictionIsDeterministic(t *testing.T) {
	build := func() *Store[string] {
		c := newClk()
		s := NewWithClock[string](time.Hour, 6, c.now)
		for i := range 6 {
			c.advance(time.Second)
			s.Set(fmt.Sprintf("k%d", i), fmt.Sprintf("c%d", i%3), "v")
		}
		c.advance(time.Second)
		s.Set("incoming", "c9", "v")
		return s
	}
	first := ""
	for range 40 {
		s := build()
		gone := ""
		for i := range 6 {
			k := fmt.Sprintf("k%d", i)
			if _, ok := s.Peek(k); !ok {
				gone = k
				break
			}
		}
		if gone == "" {
			t.Fatal("expected exactly one eviction")
		}
		if first == "" {
			first = gone
		} else if gone != first {
			t.Fatalf("eviction victim varied across runs: %q then %q", first, gone)
		}
	}
}

// TestTiedClientsEvictTheOldestEntry covers the tie-break: when every client
// holds the same number of entries, the globally oldest entry goes first
// (classic FIFO), never a freshly created one.
func TestTiedClientsEvictTheOldestEntry(t *testing.T) {
	c := newClk()
	s := NewWithClock[string](time.Hour, 3, c.now)
	c.advance(time.Second)
	s.Set("first", "a", "v")
	c.advance(time.Second)
	s.Set("second", "b", "v")
	c.advance(time.Second)
	s.Set("third", "c", "v")
	c.advance(time.Second)
	s.Set("fourth", "d", "v")

	if _, ok := s.Peek("first"); ok {
		t.Error("with all clients tied, the oldest entry must be the victim")
	}
	for _, k := range []string{"second", "third", "fourth"} {
		if _, ok := s.Peek(k); !ok {
			t.Errorf("%q must have survived", k)
		}
	}
}

// ── Bookkeeping the eviction policy depends on ──────────────────────────────

func TestBucketMemoryDoesNotGrowWithChurn(t *testing.T) {
	c := newClk()
	s := NewWithClock[string](time.Hour, 32, c.now)
	// One client that starts and completes 20k logins must not accumulate
	// per-client bookkeeping proportional to the total, only to what it holds.
	for i := range 20000 {
		k := fmt.Sprintf("k%d", i)
		s.Set(k, "steady", "v")
		s.Pop(k)
	}
	s.Set("held", "steady", "v")

	s.mu.Lock()
	b := s.buckets["steady"]
	n := 0
	if b != nil {
		n = len(b.keys)
	}
	s.mu.Unlock()
	if n > 64 {
		t.Errorf("bucket slice grew to %d entries for 1 live key — compaction is not running", n)
	}
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1", s.Len())
	}
}

// TestBucketMemoryDoesNotGrowUnderSustainedFlood is the other half, and the
// one a window-based compaction test misses: while a flooder is pinned at the
// cap, its bucket's un-consumed window never shrinks, so compaction has to key
// on the backing slice's total length or the array grows with total request
// count — a memory-exhaustion path reachable by the very flood this store is
// meant to survive.
func TestBucketMemoryDoesNotGrowUnderSustainedFlood(t *testing.T) {
	c := newClk()
	const maxEntries = 64
	s := NewWithClock[string](time.Hour, maxEntries, c.now)
	for i := range 200 * maxEntries {
		c.advance(time.Millisecond)
		s.Set(fmt.Sprintf("k%d", i), "flooder", "v")
	}

	s.mu.Lock()
	n := 0
	if b := s.buckets["flooder"]; b != nil {
		n = len(b.keys)
	}
	s.mu.Unlock()
	if n > 4*maxEntries {
		t.Errorf("bucket slice grew to %d for a store capped at %d — compaction does not fire while a client sits at the cap", n, maxEntries)
	}
	if s.Len() != maxEntries {
		t.Errorf("Len = %d, want %d", s.Len(), maxEntries)
	}
}

func TestClientAccountingSurvivesEviction(t *testing.T) {
	c := newClk()
	s := NewWithClock[string](time.Hour, 4, c.now)
	for i := range 200 {
		c.advance(time.Millisecond)
		s.Set(fmt.Sprintf("k%d", i), fmt.Sprintf("c%d", i%3), "v")
	}
	if s.Len() != 4 {
		t.Fatalf("Len = %d, want 4", s.Len())
	}
	// Drain everything and confirm the client index empties with it — a leak
	// here would let a long-dead client keep winning the eviction ballot.
	for i := range 200 {
		s.Pop(fmt.Sprintf("k%d", i))
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d, want 0", s.Len())
	}
	if s.Clients() != 0 {
		t.Errorf("Clients = %d, want 0 (client index leaked)", s.Clients())
	}
}

// ── Concurrency ─────────────────────────────────────────────────────────────

func TestConcurrentUseIsRaceFreeAndBounded(t *testing.T) {
	const maxEntries = 128
	s := New[int](time.Minute, maxEntries)

	var wg sync.WaitGroup
	for w := range 16 {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range 500 {
				k := fmt.Sprintf("w%d-k%d", w, i)
				s.Set(k, fmt.Sprintf("client-%d", w), i)
				s.Peek(k)
				s.Pop(k)
				s.Len()
				s.Evictions()
				s.Clients()
			}
		}(w)
	}
	wg.Wait()

	if n := s.Len(); n > maxEntries {
		t.Errorf("Len = %d, want <= %d", n, maxEntries)
	}
}

// TestConcurrentPopIsSingleUse proves the store hands one state token to
// exactly one caller — the property the OIDC/SAML callbacks rely on so a
// racing replay of a captured state cannot be redeemed twice.
func TestConcurrentPopIsSingleUse(t *testing.T) {
	s := New[string](time.Minute, 64)
	for round := range 200 {
		k := fmt.Sprintf("k%d", round)
		s.Set(k, "c", "v")

		var wins int64
		var mu sync.Mutex
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, ok := s.Pop(k); ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("round %d: %d concurrent Pops succeeded, want exactly 1", round, wins)
		}
	}
}
