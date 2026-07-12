package autoexclude

import (
	"testing"
	"time"
)

// fakeClock is an injectable monotonic clock so expiry/window tests never sleep
// (the determinism gate re-runs -shuffle; time.Sleep would be flaky and slow).
type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }
func (f *fakeClock) add(d time.Duration) { f.t = f.t.Add(d) }

func newTestCache(cfg Config, clk *fakeClock) *Cache {
	cfg.Now = clk.now
	return New(cfg)
}

// TestConfirmCount_DistinctIPs pins the core anti-poison invariant: one client
// can never promote a host on its own; confirmN DISTINCT client IPs are required.
func TestConfirmCount_DistinctIPs(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 2}, clk)

	// Same client failing repeatedly must NOT promote (self-poison guard).
	for i := 0; i < 5; i++ {
		if promoted := c.Observe("evil.example", ReasonClientPinned, "10.0.0.1"); promoted {
			t.Fatalf("single client promoted on attempt %d — self-poison not blocked", i)
		}
	}
	if _, ok := c.Contains("evil.example"); ok {
		t.Fatal("host excluded from a single client — confirm-count bypassed")
	}
	// A second DISTINCT client crosses the threshold → promote.
	if promoted := c.Observe("evil.example", ReasonClientPinned, "10.0.0.2"); !promoted {
		t.Fatal("second distinct client did not promote")
	}
	if r, ok := c.Contains("evil.example"); !ok || r != ReasonClientPinned {
		t.Fatalf("post-promotion Contains = (%q,%v), want (client_pinned,true)", r, ok)
	}
}

// TestObserve_PromotesOncePerHost confirms promotion fires exactly once (the
// audit/alert trigger must not re-fire on every subsequent failure).
func TestObserve_PromotesOncePerHost(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1}, clk)
	if !c.Observe("h.example", ReasonUnsupported, "1.1.1.1") {
		t.Fatal("first observation with confirmN=1 should promote")
	}
	if c.Observe("h.example", ReasonUnsupported, "2.2.2.2") {
		t.Fatal("already-excluded host must not re-promote")
	}
}

// TestExpiry_ReasonTTL pins that client_pinned uses the shorter pinnedTTL and
// server-observed reasons use the full TTL, and that an expired entry reads as
// absent (fail-closed — inspection resumes).
func TestExpiry_ReasonTTL(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1, TTL: 12 * time.Hour, PinnedTTL: 1 * time.Hour}, clk)

	c.Observe("pinned.example", ReasonClientPinned, "1.1.1.1")
	c.Observe("unsup.example", ReasonUnsupported, "1.1.1.1")

	clk.add(90 * time.Minute) // past pinnedTTL, within TTL
	if _, ok := c.Contains("pinned.example"); ok {
		t.Fatal("client_pinned entry should have expired after pinnedTTL")
	}
	if _, ok := c.Contains("unsup.example"); !ok {
		t.Fatal("unsupported entry should still be active within TTL")
	}
	clk.add(12 * time.Hour) // past TTL
	if _, ok := c.Contains("unsup.example"); ok {
		t.Fatal("unsupported entry should have expired after TTL")
	}
	if n := c.Len(); n != 0 {
		t.Fatalf("Len after all expired = %d, want 0", n)
	}
}

// TestWindow_ResetsPartialObservation pins that distinct-IP observations older
// than the window do not accumulate — a slow drip from rotating IPs cannot
// silently reach the threshold across hours.
func TestWindow_ResetsPartialObservation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 2, Window: 10 * time.Minute}, clk)
	c.Observe("drip.example", ReasonClientPinned, "1.1.1.1")
	clk.add(11 * time.Minute) // window elapsed
	if c.Observe("drip.example", ReasonClientPinned, "2.2.2.2") {
		t.Fatal("observations across a lapsed window must not combine to promote")
	}
	if _, ok := c.Contains("drip.example"); ok {
		t.Fatal("host excluded despite window reset")
	}
}

// TestNormalize_HostOnlyCollision pins Security M5 / config-arch M6: casing,
// trailing dot, and port variants collapse to one key on BOTH write and read.
func TestNormalize_HostOnlyCollision(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1}, clk)
	c.Observe("EXAMPLE.com.", ReasonUnsupported, "1.1.1.1") // learn upper + trailing dot
	if _, ok := c.Contains("example.com:443"); !ok {        // read lower + port
		t.Fatal("normalized key mismatch: EXAMPLE.com. did not collide with example.com:443")
	}
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (variants must be one entry)", c.Len())
	}
}

// TestHits_BlastRadius pins that Contains increments the per-entry hit counter
// surfaced to the operator for triage.
func TestHits_BlastRadius(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1}, clk)
	c.Observe("h.example", ReasonUnsupported, "1.1.1.1")
	for i := 0; i < 3; i++ {
		c.Contains("h.example")
	}
	list := c.List()
	if len(list) != 1 || list[0].Hits != 3 {
		t.Fatalf("hits = %+v, want one entry with Hits=3", list)
	}
}

// TestRemoveClear pins manual operator control.
func TestRemoveClear(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1}, clk)
	c.Observe("a.example", ReasonUnsupported, "1.1.1.1")
	c.Observe("b.example", ReasonUnsupported, "1.1.1.1")
	if !c.Remove("A.example:443") { // normalized remove
		t.Fatal("Remove should normalize and find the entry")
	}
	if _, ok := c.Contains("a.example"); ok {
		t.Fatal("removed host still present")
	}
	if n := c.Clear(); n != 1 {
		t.Fatalf("Clear returned %d, want 1 remaining", n)
	}
	if c.Len() != 0 {
		t.Fatal("Clear left entries behind")
	}
}

// TestEviction_CapBoundsGrowth pins that the cache stays bounded and eviction
// only ever removes entries (re-enabling inspection = fail-closed).
func TestEviction_CapBoundsGrowth(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1, MaxEntries: 10}, clk)
	for i := 0; i < 100; i++ {
		clk.add(time.Second) // distinct learnedAt for stable oldest-first eviction
		host := "h" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ".example"
		c.Observe(host, ReasonUnsupported, "1.1.1.1")
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

// TestEmptyHost_NoOp guards the degenerate key.
func TestEmptyHost_NoOp(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := newTestCache(Config{ConfirmN: 1}, clk)
	if c.Observe("", ReasonUnsupported, "1.1.1.1") {
		t.Fatal("empty host must not promote")
	}
	if _, ok := c.Contains(""); ok {
		t.Fatal("empty host must never match")
	}
}
