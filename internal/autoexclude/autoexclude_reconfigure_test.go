package autoexclude

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"
)

// autoexclude_reconfigure_test.go — F10 PR1: the runtime-tunable seam. These tests
// pin Reconfigure's contract in isolation; the method is DARK (no caller outside
// these tests) until the F10 persistence/API slices land. Everything here is
// white-box (package autoexclude) so it can assert on the unexported cache state
// (c.active/c.pend/c.confirmN/…) that the public surface only summarizes via Stats.

// promoteAt promotes (scope=sc, host) to an active exclusion at the clock's current
// time, using ConfirmN=1 semantics (one distinct token promotes). Returns the key.
func promoteAt(t *testing.T, c *Cache, host string) {
	t.Helper()
	if !obs(c, host, ReasonUnsupportedParams, "id:evidence") {
		t.Fatalf("expected %q to promote (ConfirmN must be 1 for this helper)", host)
	}
}

// TestReconfigure_AllTunablesApplied — every tunable takes effect and the
// maxPending==maxEntries invariant is re-established.
func TestReconfigure_AllTunablesApplied(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{}, clk)

	c.Reconfigure(Config{
		TTL:        6 * time.Hour,
		PinnedTTL:  30 * time.Minute,
		ConfirmN:   3,
		Window:     5 * time.Minute,
		MaxEntries: 1000,
	})

	s := c.Stats()
	if s.ConfirmN != 3 || s.TTLSecs != int(6*time.Hour/time.Second) || s.PinnedSecs != int(30*time.Minute/time.Second) ||
		s.WindowSecs != int(5*time.Minute/time.Second) || s.MaxEntries != 1000 {
		t.Fatalf("tunables not applied: %+v", s)
	}
	if c.maxPending != 1000 {
		t.Fatalf("maxPending=%d, want == maxEntries 1000 (New invariant not re-established)", c.maxPending)
	}
}

// TestReconfigure_ZeroResolvesToDefault — a zeroed field means "reset to default"
// (full zero Config restores all Default*; a partial Config defaults the rest).
func TestReconfigure_ZeroResolvesToDefault(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 5, TTL: time.Hour, MaxEntries: 99}, clk)

	c.Reconfigure(Config{}) // all zero ⇒ all defaults

	s := c.Stats()
	if s.ConfirmN != DefaultConfirmN || s.TTLSecs != int(DefaultTTL/time.Second) ||
		s.PinnedSecs != int(DefaultPinnedTTL/time.Second) || s.WindowSecs != int(DefaultWindow/time.Second) ||
		s.MaxEntries != DefaultMaxEntries {
		t.Fatalf("zero Config did not reset to defaults: %+v", s)
	}

	// Partial: only ConfirmN set ⇒ everything else defaults.
	c.Reconfigure(Config{ConfirmN: 4})
	s = c.Stats()
	if s.ConfirmN != 4 || s.TTLSecs != int(DefaultTTL/time.Second) || s.MaxEntries != DefaultMaxEntries {
		t.Fatalf("partial Config did not default the unset fields: %+v", s)
	}
}

// TestReconfigure_PreservesActiveWithinLimits — Reconfigure must NOT drop learned
// entries that still fit under the new cap (only the tunables change).
func TestReconfigure_PreservesActiveWithinLimits(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1, MaxEntries: 100}, clk)
	for i := 0; i < 10; i++ {
		promoteAt(t, c, fmt.Sprintf("h%02d.example", i))
		clk.add(time.Second)
	}
	if c.Len() != 10 {
		t.Fatalf("precondition: want 10 active, got %d", c.Len())
	}
	c.Reconfigure(Config{ConfirmN: 4, MaxEntries: 100, Window: time.Minute}) // still fits
	if c.Len() != 10 {
		t.Fatalf("Reconfigure dropped entries within the cap: got %d, want 10", c.Len())
	}
	for i := 0; i < 10; i++ {
		if _, ok := c.Contains(sc, fmt.Sprintf("h%02d.example", i)); !ok {
			t.Fatalf("h%02d.example should still be excluded after in-limits Reconfigure", i)
		}
	}
}

// TestReconfigure_PreservesPendingWithinLimits — in-progress observations below the
// confirm-count survive an in-limits Reconfigure and can still promote afterward.
func TestReconfigure_PreservesPendingWithinLimits(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 2, MaxEntries: 100, Window: time.Hour}, clk)
	// One token each on 5 hosts ⇒ 5 pending, none promoted (ConfirmN=2).
	for i := 0; i < 5; i++ {
		obs(c, fmt.Sprintf("p%02d.example", i), ReasonUnsupportedParams, "id:first")
	}
	if c.PendingLen() != 5 || c.Len() != 0 {
		t.Fatalf("precondition: want 5 pending / 0 active, got %d / %d", c.PendingLen(), c.Len())
	}
	c.Reconfigure(Config{ConfirmN: 2, MaxEntries: 100, Window: time.Hour}) // in-limits
	if c.PendingLen() != 5 {
		t.Fatalf("Reconfigure dropped in-limits pending observations: got %d, want 5", c.PendingLen())
	}
	// A second distinct token now promotes — proving pending survived intact.
	if !obs(c, "p00.example", ReasonUnsupportedParams, "id:second") {
		t.Fatal("second token should promote a surviving pending observation")
	}
}

// TestReconfigure_LoweredActiveCapEvictsExactly — lowering maxEntries evicts down to
// EXACTLY the new cap, oldest-first (the newest survive).
func TestReconfigure_LoweredActiveCapEvictsExactly(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1, MaxEntries: 100, TTL: 12 * time.Hour}, clk)
	const n = 20
	for i := 0; i < n; i++ {
		promoteAt(t, c, fmt.Sprintf("h%02d.example", i)) // h00 oldest … h19 newest
		clk.add(time.Second)
	}
	c.Reconfigure(Config{ConfirmN: 1, MaxEntries: 8, TTL: 12 * time.Hour})
	if c.Len() != 8 {
		t.Fatalf("lowered cap did not evict to EXACTLY the cap: got %d, want 8", c.Len())
	}
	// The 8 NEWEST (h12..h19) survive; the 12 oldest are gone.
	for i := 0; i < n; i++ {
		_, ok := c.Contains(sc, fmt.Sprintf("h%02d.example", i))
		wantKept := i >= n-8
		if ok != wantKept {
			t.Fatalf("h%02d.example kept=%v, want kept=%v (oldest must be evicted first)", i, ok, wantKept)
		}
	}
}

// TestReconfigure_LoweredPendingCapEvictsExactly — lowering maxEntries also bounds
// the pending map (maxPending == maxEntries) to EXACTLY the new cap.
func TestReconfigure_LoweredPendingCapEvictsExactly(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 2, MaxEntries: 100, Window: time.Hour}, clk)
	const n = 20
	for i := 0; i < n; i++ {
		obs(c, fmt.Sprintf("p%02d.example", i), ReasonUnsupportedParams, "id:first") // pending, distinct firstSeen
		clk.add(time.Second)
	}
	if c.PendingLen() != n {
		t.Fatalf("precondition: want %d pending, got %d", n, c.PendingLen())
	}
	c.Reconfigure(Config{ConfirmN: 2, MaxEntries: 6, Window: time.Hour})
	if c.PendingLen() != 6 {
		t.Fatalf("lowered cap did not bound pending to EXACTLY maxPending: got %d, want 6", c.PendingLen())
	}
}

// TestReconfigure_DeterministicEviction — across repeated identical runs, the SAME
// entries survive a lowered-cap eviction, including when entries share a timestamp
// (the evictLess key tiebreaker must remove the map-iteration-order dependence).
func TestReconfigure_DeterministicEviction(t *testing.T) {
	survivorsOf := func() []string {
		clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
		c := newTestCache(Config{ConfirmN: 1, MaxEntries: 100, TTL: 12 * time.Hour}, clk)
		// 10 entries ALL AT THE SAME TICK ⇒ identical learnedAt ⇒ ties resolved only
		// by the key. Without the tiebreaker this would be map-order (random).
		for i := 0; i < 10; i++ {
			promoteAt(t, c, fmt.Sprintf("h%02d.example", i))
		}
		c.Reconfigure(Config{ConfirmN: 1, MaxEntries: 4, TTL: 12 * time.Hour})
		out := make([]string, 0, 4)
		for i := 0; i < 10; i++ {
			host := fmt.Sprintf("h%02d.example", i)
			if _, ok := c.Contains(sc, host); ok {
				out = append(out, host)
			}
		}
		return out
	}
	first := survivorsOf()
	if len(first) != 4 {
		t.Fatalf("want exactly 4 survivors, got %d (%v)", len(first), first)
	}
	for run := 0; run < 25; run++ {
		got := survivorsOf()
		if fmt.Sprint(got) != fmt.Sprint(first) {
			t.Fatalf("non-deterministic eviction: run %d survivors %v != %v", run, got, first)
		}
	}
}

// TestReconfigure_PinnedTTLClampedToTTL — the engine defensively clamps
// pinnedTTL <= ttl even when a caller bypasses outer validation.
func TestReconfigure_PinnedTTLClampedToTTL(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{}, clk)
	c.Reconfigure(Config{TTL: time.Hour, PinnedTTL: 10 * time.Hour}) // pinned > ttl
	s := c.Stats()
	if s.PinnedSecs != int(time.Hour/time.Second) {
		t.Fatalf("pinnedTTL not clamped to ttl: pinned=%ds ttl=%ds", s.PinnedSecs, s.TTLSecs)
	}
	// And a subsequent client_pinned promotion uses the clamped (not the requested) TTL.
	c.Reconfigure(Config{ConfirmN: 1, TTL: time.Hour, PinnedTTL: 10 * time.Hour})
	obs(c, "pinned.example", ReasonClientPinned, "id:x")
	list := c.List()
	if len(list) != 1 {
		t.Fatalf("want 1 active, got %d", len(list))
	}
	if got := list[0].ExpiresAt.Sub(list[0].LearnedAt); got != time.Hour {
		t.Fatalf("client_pinned entry TTL=%v, want clamped 1h", got)
	}
}

// TestReconfigure_NoPartialStateOnClamp — even an input that forces BOTH a
// cross-field clamp and a cap-lowering leaves a fully self-consistent cache: all
// fields resolved, maxPending==maxEntries, active within the cap, pinned<=ttl.
func TestReconfigure_NoPartialStateOnClamp(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1, MaxEntries: 100, TTL: 12 * time.Hour}, clk)
	for i := 0; i < 12; i++ {
		promoteAt(t, c, fmt.Sprintf("h%02d.example", i))
		clk.add(time.Second)
	}
	// pinnedTTL>ttl (clamp), maxEntries lowered below active (evict), confirmN 0 (default).
	c.Reconfigure(Config{TTL: 2 * time.Hour, PinnedTTL: 9 * time.Hour, MaxEntries: 5})
	s := c.Stats()
	switch {
	case s.PinnedSecs > s.TTLSecs:
		t.Fatalf("partial state: pinned %ds > ttl %ds", s.PinnedSecs, s.TTLSecs)
	case s.ConfirmN != DefaultConfirmN:
		t.Fatalf("partial state: confirmN=%d, want default %d", s.ConfirmN, DefaultConfirmN)
	case c.maxPending != s.MaxEntries:
		t.Fatalf("partial state: maxPending=%d != maxEntries=%d", c.maxPending, s.MaxEntries)
	case c.Len() != 5:
		t.Fatalf("partial state: active=%d, want == cap 5", c.Len())
	}
}

// TestReconfigure_TTLChangeIsForwardOnly — pins ADR-0010 Model A: an existing
// active entry KEEPS its original ExpiresAt across a TTL change; only entries
// promoted AFTER the change use the new TTL.
func TestReconfigure_TTLChangeIsForwardOnly(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1, TTL: 12 * time.Hour}, clk)
	promoteAt(t, c, "old.example")
	before := c.List()
	if len(before) != 1 {
		t.Fatalf("want 1 active, got %d", len(before))
	}
	origExpiry := before[0].ExpiresAt // = now + 12h

	// Shorten TTL drastically.
	c.Reconfigure(Config{ConfirmN: 1, TTL: time.Minute})

	// The EXISTING entry's expiry is unchanged (forward-only) …
	after := c.List()
	if len(after) != 1 || !after[0].ExpiresAt.Equal(origExpiry) {
		t.Fatalf("existing entry expiry changed: got %v want %v (Model A: forward-only)", after[0].ExpiresAt, origExpiry)
	}
	// … and it is still active well past the NEW (1m) TTL.
	clk.add(10 * time.Minute)
	if _, ok := c.Contains(sc, "old.example"); !ok {
		t.Fatal("existing entry must live to its ORIGINAL expiry, not the shortened TTL")
	}
	// A NEWLY promoted entry uses the new 1m TTL.
	promoteAt(t, c, "new.example")
	nl := c.List()
	var newEntry *Entry
	for i := range nl {
		if nl[i].Host == "new.example" {
			newEntry = &nl[i]
		}
	}
	if newEntry == nil {
		t.Fatal("new.example not promoted")
	}
	if got := newEntry.ExpiresAt.Sub(newEntry.LearnedAt); got != time.Minute {
		t.Fatalf("newly promoted entry TTL=%v, want new 1m", got)
	}
}

// TestReconfigure_Concurrent drives Reconfigure concurrently with every mutating and
// reading entry point under -race. The detector is the real assertion; we also check
// no panic and that the final active count honors the last-applied cap bound.
func TestReconfigure_Concurrent(t *testing.T) {
	c := New(Config{ConfirmN: 1, MaxEntries: 128}) // real clock; contention, not timing
	const goroutines = 400
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			host := "h" + strconv.Itoa(g%256) + ".example"
			switch g % 5 {
			case 0:
				c.Observe("s", "s", host, ReasonUnsupportedParams, "id:"+strconv.Itoa(g))
			case 1:
				_, _ = c.Contains("s", host)
			case 2:
				c.Remove("s", host)
			case 3:
				c.Clear()
			case 4:
				// Vary the cap to force concurrent evict-to-cap under readers/writers.
				c.Reconfigure(Config{ConfirmN: 1, MaxEntries: 16 + g%64})
			}
		}(g)
	}
	wg.Wait()
	if c.Len() > c.Stats().MaxEntries {
		t.Fatalf("active %d exceeds the last-applied cap %d", c.Len(), c.Stats().MaxEntries)
	}
}

// TestReconfigure_NoReadPathAllocRegression — PR1 must not add allocations to the
// hot read path. Contains' per-call allocation count is identical before and after a
// Reconfigure (Reconfigure only mutates config scalars + trims maps; it touches
// nothing Contains allocates).
func TestReconfigure_NoReadPathAllocRegression(t *testing.T) {
	c := New(Config{ConfirmN: 1, MaxEntries: 100})
	c.Observe("s", "s", "host.example", ReasonUnsupportedParams, "id:x") // active hit target
	read := func() { _, _ = c.Contains("s", "host.example") }

	before := testing.AllocsPerRun(200, read)
	c.Reconfigure(Config{ConfirmN: 1, MaxEntries: 50, TTL: 6 * time.Hour})
	after := testing.AllocsPerRun(200, read)

	if after > before {
		t.Fatalf("Reconfigure regressed read-path allocations: before=%.0f after=%.0f", before, after)
	}
}
