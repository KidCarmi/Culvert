package autoexclude

import (
	"testing"
	"time"
)

// fakeClock is an injectable monotonic clock so expiry/window tests never sleep
// (the determinism gate re-runs -shuffle; time.Sleep would be flaky and slow).
type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time      { return f.t }
func (f *fakeClock) add(d time.Duration) { f.t = f.t.Add(d) }

func newTestCache(cfg Config, clk *fakeClock) *Cache {
	cfg.Now = clk.now
	return New(cfg)
}

const sc = "scope-a" // default test scope id

// obs is a terse Observe helper for the default scope.
func obs(c *Cache, host string, r Reason, client string) bool {
	return c.Observe(sc, "Scope A", host, r, client)
}

// TestConfirmCount_DistinctTokens pins the core anti-poison invariant: one
// evidence token can never promote a host on its own; confirmN DISTINCT tokens
// are required (the engine treats the token opaquely — subnet/identity policy
// lives in the caller).
func TestConfirmCount_DistinctTokens(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 2}, clk)
	for i := 0; i < 5; i++ {
		if obs(c, "evil.example", ReasonClientPinned, "ip:10.0.0.1") {
			t.Fatalf("single token promoted on attempt %d — self-poison not blocked", i)
		}
	}
	if _, ok := c.Contains(sc, "evil.example"); ok {
		t.Fatal("host excluded from a single token — confirm-count bypassed")
	}
	if !obs(c, "evil.example", ReasonClientPinned, "ip:10.1.0.2") {
		t.Fatal("second distinct token did not promote")
	}
	if r, ok := c.Contains(sc, "evil.example"); !ok || r != ReasonClientPinned {
		t.Fatalf("post-promotion Contains = (%q,%v), want (client_pinned,true)", r, ok)
	}
}

// TestScopeIsolation pins B1: a host learned under one scope is NOT excluded for a
// different scope — one fail-open profile cannot create a bypass consumed by
// another profile targeting the same host.
func TestScopeIsolation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1}, clk)
	c.Observe("prof-A", "A", "shared.example", ReasonClientCertRequired, "ip:1.1.1.1")
	if _, ok := c.Contains("prof-A", "shared.example"); !ok {
		t.Fatal("scope A should have the exclusion")
	}
	if _, ok := c.Contains("prof-B", "shared.example"); ok {
		t.Fatal("scope B must NOT see scope A's exclusion (cross-scope contamination)")
	}
	// Removing from B is a no-op; A stays.
	if c.Remove("prof-B", "shared.example") {
		t.Fatal("Remove on wrong scope should report not-present")
	}
	if _, ok := c.Contains("prof-A", "shared.example"); !ok {
		t.Fatal("scope A entry must survive a wrong-scope remove")
	}
}

// TestObserve_PromotesOncePerHost confirms promotion fires exactly once.
func TestObserve_PromotesOncePerHost(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1}, clk)
	if !obs(c, "h.example", ReasonUnsupportedParams, "ip:1.1.1.1") {
		t.Fatal("first observation with confirmN=1 should promote")
	}
	if obs(c, "h.example", ReasonUnsupportedParams, "ip:2.2.2.2") {
		t.Fatal("already-excluded host must not re-promote")
	}
}

// TestExpiry_ReasonTTL pins that client_pinned uses the shorter pinnedTTL and
// server-observed reasons use the full TTL, and that an expired entry reads as
// absent (fail-closed — inspection resumes).
func TestExpiry_ReasonTTL(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1, TTL: 12 * time.Hour, PinnedTTL: 1 * time.Hour}, clk)
	obs(c, "pinned.example", ReasonClientPinned, "ip:1.1.1.1")
	obs(c, "unsup.example", ReasonUnsupportedParams, "ip:1.1.1.1")
	clk.add(90 * time.Minute)
	if _, ok := c.Contains(sc, "pinned.example"); ok {
		t.Fatal("client_pinned entry should have expired after pinnedTTL")
	}
	if _, ok := c.Contains(sc, "unsup.example"); !ok {
		t.Fatal("unsupported entry should still be active within TTL")
	}
	clk.add(12 * time.Hour)
	if _, ok := c.Contains(sc, "unsup.example"); ok {
		t.Fatal("unsupported entry should have expired after TTL")
	}
	if n := c.Len(); n != 0 {
		t.Fatalf("Len after all expired = %d, want 0", n)
	}
}

// TestWindow_ResetsPartialObservation pins that observations older than the
// window do not accumulate.
func TestWindow_ResetsPartialObservation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 2, Window: 10 * time.Minute}, clk)
	obs(c, "drip.example", ReasonClientPinned, "ip:1.1.1.1")
	clk.add(11 * time.Minute)
	if obs(c, "drip.example", ReasonClientPinned, "ip:2.2.2.2") {
		t.Fatal("observations across a lapsed window must not combine to promote")
	}
	if _, ok := c.Contains(sc, "drip.example"); ok {
		t.Fatal("host excluded despite window reset")
	}
}

// TestNormalize_HostOnlyCollision pins that casing, trailing dot, and port
// variants collapse to one key on BOTH write and read.
func TestNormalize_HostOnlyCollision(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1}, clk)
	obs(c, "EXAMPLE.com.", ReasonUnsupportedParams, "ip:1.1.1.1")
	if _, ok := c.Contains(sc, "example.com:443"); !ok {
		t.Fatal("normalized key mismatch: EXAMPLE.com. did not collide with example.com:443")
	}
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (variants must be one entry)", c.Len())
	}
}

// TestHits_BlastRadius pins that Contains increments the per-entry hit counter.
func TestHits_BlastRadius(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1}, clk)
	obs(c, "h.example", ReasonUnsupportedParams, "ip:1.1.1.1")
	for i := 0; i < 3; i++ {
		c.Contains(sc, "h.example")
	}
	list := c.List()
	if len(list) != 1 || list[0].Hits != 3 || list[0].ScopeID != sc {
		t.Fatalf("hits/scope = %+v, want one entry with Hits=3 ScopeID=%q", list, sc)
	}
}

// TestRemoveClear pins manual operator control.
func TestRemoveClear(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1}, clk)
	obs(c, "a.example", ReasonUnsupportedParams, "ip:1.1.1.1")
	obs(c, "b.example", ReasonUnsupportedParams, "ip:1.1.1.1")
	if !c.Remove(sc, "A.example:443") { // normalized remove
		t.Fatal("Remove should normalize and find the entry")
	}
	if _, ok := c.Contains(sc, "a.example"); ok {
		t.Fatal("removed host still present")
	}
	if n := c.Clear(); n != 1 {
		t.Fatalf("Clear returned %d, want 1 remaining", n)
	}
	if c.Len() != 0 {
		t.Fatal("Clear left entries behind")
	}
}

// TestPendingBounded pins that unconfirmed observations cannot grow the pending
// map without bound (a fail-open rule seeing many never-confirming hosts).
func TestPendingBounded(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 5, MaxEntries: 16}, clk) // pending cap follows MaxEntries
	for i := 0; i < 500; i++ {
		host := "h" + string(rune('a'+i%26)) + string(rune('0'+(i/26)%10)) + string(rune('0'+i/260)) + ".example"
		if obs(c, host, ReasonClientPinned, "ip:10.0.0.1") { // one token, never reaches confirmN=5
			t.Fatal("single token should never promote")
		}
	}
	if n := c.PendingLen(); n > 16 {
		t.Fatalf("pending map grew unbounded: PendingLen=%d > maxPending 16", n)
	}
	if c.Len() != 0 {
		t.Fatalf("nothing should have promoted: active=%d", c.Len())
	}
}

// TestEviction_CapBoundsGrowth pins that the cache stays bounded and eviction
// only ever removes entries (re-enabling inspection = fail-closed).
func TestEviction_CapBoundsGrowth(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1, MaxEntries: 10}, clk)
	for i := 0; i < 100; i++ {
		clk.add(time.Second)
		host := "h" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ".example"
		obs(c, host, ReasonUnsupportedParams, "ip:1.1.1.1")
	}
	if n := c.Len(); n > 10 {
		t.Fatalf("cache exceeded MaxEntries: Len=%d > 10", n)
	}
}

// TestStats_ReportsPosture pins the provable-OFF/config surface.
func TestStats_ReportsPosture(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 3, TTL: 6 * time.Hour, PinnedTTL: 30 * time.Minute, Window: 5 * time.Minute, MaxEntries: 2048}, clk)
	s := c.Stats()
	if s.ConfirmN != 3 || s.TTLSecs != 21600 || s.PinnedSecs != 1800 || s.WindowSecs != 300 || s.MaxEntries != 2048 {
		t.Fatalf("Stats posture mismatch: %+v", s)
	}
	if s.Active != 0 || s.Pending != 0 {
		t.Fatalf("fresh cache should be inert: %+v", s)
	}
}

// TestEmptyScopeOrHost_NoOp guards the degenerate keys.
func TestEmptyScopeOrHost_NoOp(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1}, clk)
	if c.Observe("", "", "h.example", ReasonUnsupportedParams, "ip:1.1.1.1") {
		t.Fatal("empty scope must not promote")
	}
	if obs(c, "", ReasonUnsupportedParams, "ip:1.1.1.1") {
		t.Fatal("empty host must not promote")
	}
	if _, ok := c.Contains("", "h.example"); ok {
		t.Fatal("empty scope must never match")
	}
}
