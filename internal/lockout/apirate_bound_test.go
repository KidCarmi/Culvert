package lockout

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// The APIRateLimiter is keyed by the client IP of a request nobody has
// authenticated yet, so the number of keys is a caller's choice. These tests
// pin the bound on that number, what happens at the bound, and that nothing
// about an ordinary (below-cap) decision changed.

// checkAPIRateInvariants asserts the structural contract between the map and
// the start-order list: every retained window has exactly one live slot, the
// list holds nothing else, and the population respects the cap.
func checkAPIRateInvariants(t *testing.T, a *APIRateLimiter, limit int) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) > limit {
		t.Fatalf("entries = %d, exceeds cap %d", len(a.entries), limit)
	}
	live := map[string]int{}
	for _, s := range a.order[a.head:] {
		if a.entries[s.ip] == s.entry {
			live[s.ip]++
		}
	}
	if len(live) != len(a.entries) {
		t.Fatalf("live slots cover %d keys, map holds %d", len(live), len(a.entries))
	}
	for ip, n := range live {
		if n != 1 {
			t.Fatalf("key %q has %d live slots, want 1", ip, n)
		}
	}
	if pending := len(a.order) - a.head; pending > 2*limit+1 {
		t.Fatalf("order holds %d pending slots for a cap of %d", pending, limit)
	}
}

// TestAPIRateLimiter_CapBoundsDistinctKeys is the regression guard for the
// defect: before the cap, N distinct addresses left N entries until the next
// 5-minute janitor pass.
func TestAPIRateLimiter_CapBoundsDistinctKeys(t *testing.T) {
	const limit = 8
	for _, op := range []string{"Allow", "Reserve"} {
		t.Run(op, func(t *testing.T) {
			a := &APIRateLimiter{entries: map[string]*apiRateEntry{}, limit: limit}
			for i := 0; i < 500; i++ {
				ip := fmt.Sprintf("2001:db8::%x", i)
				if op == "Allow" {
					if !a.Allow(ip) {
						t.Fatalf("first request from %s refused: a full table must never refuse a new address", ip)
					}
				} else if _, ok := a.Reserve(ip); !ok {
					t.Fatalf("first reservation from %s refused: a full table must never refuse a new address", ip)
				}
				if got := len(a.entries); got > limit {
					t.Fatalf("after %d distinct addresses entries = %d, want <= %d", i+1, got, limit)
				}
			}
			checkAPIRateInvariants(t, a, limit)
			// The survivors are the most recent addresses: eviction is oldest-first.
			for i := 500 - limit; i < 500; i++ {
				if a.entries[fmt.Sprintf("2001:db8::%x", i)] == nil {
					t.Errorf("address #%d (one of the %d newest) was evicted", i, limit)
				}
			}
		})
	}
}

// TestAPIRateLimiter_DefaultCap pins the production bound on a limiter built
// the way package main builds it, and on the bare-literal form the older tests
// use (limit left zero).
func TestAPIRateLimiter_DefaultCap(t *testing.T) {
	for name, a := range map[string]*APIRateLimiter{
		"constructor": NewAPIRateLimiter(),
		"literal":     {entries: map[string]*apiRateEntry{}},
	} {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < MaxAPIRateEntries+5000; i++ {
				a.Allow(fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff))
			}
			if got := len(a.entries); got != MaxAPIRateEntries {
				t.Fatalf("entries = %d after %d distinct addresses, want exactly the cap %d",
					got, MaxAPIRateEntries+5000, MaxAPIRateEntries)
			}
			checkAPIRateInvariants(t, a, MaxAPIRateEntries)
		})
	}
}

// TestAPIRateLimiter_LiveWindowSurvivesBelowCap is the security half: a
// rate-limited client stays limited for as long as the table has room, however
// many other addresses come and go. Only reaching the cap forgets it.
func TestAPIRateLimiter_LiveWindowSurvivesBelowCap(t *testing.T) {
	const limit = 16
	a := &APIRateLimiter{entries: map[string]*apiRateEntry{}, limit: limit}
	const victim = "198.51.100.7"
	for i := 0; i < Burst; i++ {
		if !a.Allow(victim) {
			t.Fatalf("request %d within Burst refused", i)
		}
	}
	// Fill every remaining place. The limited client must stay limited.
	for i := 0; i < limit-1; i++ {
		a.Allow(fmt.Sprintf("203.0.113.%d", i))
	}
	if a.Allow(victim) {
		t.Fatal("a client over Burst was allowed while the table still had room for it")
	}
	if got := len(a.entries); got != limit {
		t.Fatalf("entries = %d, want the table exactly full at %d", got, limit)
	}
	// One more distinct address reaches the cap; the OLDEST window (the
	// limited client's) is the one given up. This is the documented saturation
	// behaviour — see reclaimLocked for why it grants a flooder nothing.
	a.Allow("203.0.113.200")
	if a.entries[victim] != nil {
		t.Fatal("at the cap the oldest window must be the eviction victim")
	}
	if a.entries["203.0.113.0"] == nil {
		t.Fatal("eviction took more than the single oldest window")
	}
	checkAPIRateInvariants(t, a, limit)
}

// TestAPIRateLimiter_ExpiredReclaimedOnRequestPath: expired windows are dropped
// when the next window starts, without waiting for the janitor.
func TestAPIRateLimiter_ExpiredReclaimedOnRequestPath(t *testing.T) {
	a := NewAPIRateLimiter()
	for i := 0; i < 50; i++ {
		a.Allow(fmt.Sprintf("10.0.0.%d", i))
	}
	for _, e := range a.entries {
		e.windowStart = e.windowStart.Add(-2 * RateWindow)
	}
	a.Allow("10.9.9.9")
	if got := len(a.entries); got != 1 {
		t.Fatalf("entries = %d after one new window, want 1 (the 50 expired ones reclaimed)", got)
	}
	if pending := len(a.order) - a.head; pending != 1 {
		t.Fatalf("order holds %d pending slots, want 1", pending)
	}
	checkAPIRateInvariants(t, a, MaxAPIRateEntries)
}

// TestAPIRateLimiter_RenewedWindowLeavesNoStaleSlot: a client returning after
// its window expired gets a fresh window and exactly one slot, repeatedly.
func TestAPIRateLimiter_RenewedWindowLeavesNoStaleSlot(t *testing.T) {
	a := NewAPIRateLimiter()
	const ip = "192.0.2.1"
	for round := 0; round < 100; round++ {
		for i := 0; i < Burst; i++ {
			if !a.Allow(ip) {
				t.Fatalf("round %d: request %d within Burst refused", round, i)
			}
		}
		if a.Allow(ip) {
			t.Fatalf("round %d: request over Burst allowed", round)
		}
		a.entries[ip].windowStart = time.Now().Add(-2 * RateWindow)
	}
	if got := len(a.order) - a.head; got > 2 {
		t.Fatalf("order holds %d pending slots for one client, want <= 2", got)
	}
}

// TestAPIRateLimiter_RefundAfterEvictionIsNoOp: a Reservation is bound to the
// window it was claimed in. If that window was evicted and the client has a new
// one, a late Refund must not decrement the new window's count.
func TestAPIRateLimiter_RefundAfterEvictionIsNoOp(t *testing.T) {
	const limit = 4
	a := &APIRateLimiter{entries: map[string]*apiRateEntry{}, limit: limit}
	const ip = "198.51.100.9"
	old, ok := a.Reserve(ip)
	if !ok {
		t.Fatal("first reservation refused")
	}
	for i := 0; i < limit; i++ { // push ip's window out
		a.Allow(fmt.Sprintf("203.0.113.%d", i))
	}
	if a.entries[ip] != nil {
		t.Fatal("setup: ip's window should have been evicted")
	}
	a.Refund(old) // window gone entirely
	if _, ok := a.Reserve(ip); !ok {
		t.Fatal("reservation in a fresh window refused")
	}
	a.Refund(old) // window replaced by a newer one
	if got := a.entries[ip].count; got != 1 {
		t.Fatalf("count = %d after a stale refund, want 1 (refund must not cross windows)", got)
	}
}

// refAPIRate is the pre-cap implementation, kept verbatim as the oracle for
// TestAPIRateLimiter_DecisionsMatchReferenceBelowCap.
type refAPIRate struct{ entries map[string]*apiRateEntry }

func (r *refAPIRate) allow(ip string, now time.Time) bool {
	e := r.entries[ip]
	if e == nil || now.Sub(e.windowStart) > RateWindow {
		r.entries[ip] = &apiRateEntry{count: 1, windowStart: now}
		return true
	}
	e.count++
	return e.count <= Burst
}

func (r *refAPIRate) reserve(ip string, now time.Time) bool {
	e := r.entries[ip]
	if e == nil || now.Sub(e.windowStart) > RateWindow {
		r.entries[ip] = &apiRateEntry{count: 1, windowStart: now}
		return true
	}
	if e.count >= Burst {
		return false
	}
	e.count++
	return true
}

// refund mirrors APIRateLimiter.Refund for a reservation the limiter reports
// as still belonging to ip's current window.
func (r *refAPIRate) refund(ip string) {
	if e := r.entries[ip]; e != nil && e.count > 0 {
		e.count--
	}
}

// liveCount is the count of ip's window, or 0 when it has none or it expired.
func liveCount(entries map[string]*apiRateEntry, ip string) int {
	if e := entries[ip]; e != nil && time.Since(e.windowStart) <= RateWindow {
		return e.count
	}
	return 0
}

// expireWindow backdates ip's window past RateWindow, if it has one.
func expireWindow(entries map[string]*apiRateEntry, ip string) {
	if e := entries[ip]; e != nil {
		e.windowStart = e.windowStart.Add(-2 * RateWindow)
	}
}

// apiRateDiff holds the two models under comparison and the reservations the
// sequence still holds.
type apiRateDiff struct {
	a    *APIRateLimiter
	ref  *refAPIRate
	held map[string]Reservation
}

// step applies one random operation to both models and returns a description
// of the first disagreement, or "".
func (d *apiRateDiff) step(op int, ip string) string {
	switch {
	case op < 55:
		if got, want := d.a.Allow(ip), d.ref.allow(ip, time.Now()); got != want {
			return fmt.Sprintf("Allow(%s) = %v, reference %v", ip, got, want)
		}
	case op < 85:
		res, got := d.a.Reserve(ip)
		if want := d.ref.reserve(ip, time.Now()); got != want {
			return fmt.Sprintf("Reserve(%s) = %v, reference %v", ip, got, want)
		}
		if got {
			d.held[ip] = res
		}
	case op < 93:
		if res, ok := d.held[ip]; ok {
			delete(d.held, ip)
			d.a.Refund(res)
			if d.a.entries[ip] == res.entry {
				d.ref.refund(ip)
			}
		}
	case op < 98:
		expireWindow(d.a.entries, ip)
		expireWindow(d.ref.entries, ip)
		delete(d.held, ip)
	default:
		d.a.Cleanup()
	}
	if got, want := liveCount(d.a.entries, ip), liveCount(d.ref.entries, ip); got != want {
		return fmt.Sprintf("live count for %s = %d, reference %d", ip, got, want)
	}
	return ""
}

// TestAPIRateLimiter_DecisionsMatchReferenceBelowCap drives the limiter and the
// pre-cap implementation with the same random sequence of Allow, Reserve,
// Refund, window expiry and Cleanup, and requires every decision and every
// retained count to agree. The population (40 addresses) stays far below the
// cap, which is the claim under test: the bound changes nothing until it is
// reached. Expiry is applied to arbitrary keys, so start order is deliberately
// violated — the decisions must not depend on it.
func TestAPIRateLimiter_DecisionsMatchReferenceBelowCap(t *testing.T) {
	seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // test sequence, not a secret
	d := &apiRateDiff{
		a:    NewAPIRateLimiter(),
		ref:  &refAPIRate{entries: map[string]*apiRateEntry{}},
		held: map[string]Reservation{},
	}
	for step := 0; step < 60000; step++ {
		ip := fmt.Sprintf("10.1.0.%d", rng.Intn(40))
		if msg := d.step(rng.Intn(100), ip); msg != "" {
			t.Fatalf("seed %d step %d: %s", seed, step, msg)
		}
	}
}

// TestAPIRateLimiter_CleanupReleasesFloodMemory: after a flood has drained, the
// janitor moves the survivors to a right-sized map instead of keeping the
// peak-sized one for the life of the process.
func TestAPIRateLimiter_CleanupReleasesFloodMemory(t *testing.T) {
	a := NewAPIRateLimiter()
	const flood = 4 * apiRateShrinkFloor
	for i := 0; i < flood; i++ {
		a.Allow(fmt.Sprintf("2001:db8::%x", i))
	}
	if a.peak != flood {
		t.Fatalf("peak = %d, want %d", a.peak, flood)
	}
	for _, e := range a.entries {
		e.windowStart = e.windowStart.Add(-2 * RateWindow)
	}
	a.Allow("192.0.2.77") // one live client rides through the sweep
	for i := 0; i < Burst; i++ {
		a.Allow("192.0.2.77")
	}
	a.Cleanup()
	if got := len(a.entries); got != 1 {
		t.Fatalf("entries = %d after the sweep, want the 1 live client", got)
	}
	if a.peak != 1 {
		t.Fatalf("peak = %d after the sweep, want 1 (the map was not rebuilt)", a.peak)
	}
	if c := cap(a.order); c > 64 {
		t.Fatalf("order capacity = %d after the sweep, want it released", c)
	}
	if a.Allow("192.0.2.77") {
		t.Fatal("the rebuild lost a live client's count: it is over Burst and must stay refused")
	}
	checkAPIRateInvariants(t, a, MaxAPIRateEntries)
}

// TestAPIRateLimiter_CleanupKeepsSmallMap: an ordinary population never
// triggers the rebuild.
func TestAPIRateLimiter_CleanupKeepsSmallMap(t *testing.T) {
	a := NewAPIRateLimiter()
	for i := 0; i < 20; i++ {
		a.Allow(fmt.Sprintf("10.0.0.%d", i))
	}
	for _, e := range a.entries {
		e.windowStart = e.windowStart.Add(-2 * RateWindow)
	}
	a.Cleanup()
	if len(a.entries) != 0 || a.peak != 20 {
		t.Fatalf("entries = %d peak = %d, want 0 and an untouched peak of 20", len(a.entries), a.peak)
	}
}

// TestAPIRateLimiter_ConcurrentAtCap runs every entry point concurrently
// against a table that is permanently saturated. Under -race this is the data
// race check; the invariants afterwards are the lost-update check.
func TestAPIRateLimiter_ConcurrentAtCap(t *testing.T) {
	const limit = 64
	a := &APIRateLimiter{entries: map[string]*apiRateEntry{}, limit: limit}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 4000; i++ {
				ip := fmt.Sprintf("10.%d.%d.%d", g, i>>8, i&0xff)
				switch i % 4 {
				case 0:
					a.Allow(ip)
				case 1:
					if r, ok := a.Reserve(ip); ok {
						a.Refund(r)
					}
				case 2:
					a.Allow(fmt.Sprintf("192.0.2.%d", i%16)) // shared, repeating keys
				default:
					if i%200 == 3 {
						a.Cleanup()
					}
				}
			}
		}(g)
	}
	wg.Wait()
	checkAPIRateInvariants(t, a, limit)
}

// BenchmarkAPIRateLimiter_DistinctAddresses is the flood shape: every request
// from an address never seen before. It reports the entries retained, which is
// the number the cap exists to bound.
//
//	go test -run '^$' -bench APIRateLimiter -benchmem ./internal/lockout
func BenchmarkAPIRateLimiter_DistinctAddresses(b *testing.B) {
	a := NewAPIRateLimiter()
	ips := make([]string, 1<<20)
	for i := range ips {
		ips[i] = fmt.Sprintf("2001:db8:%x::%x", i>>16, i&0xffff)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Allow(ips[i&(len(ips)-1)])
	}
	b.ReportMetric(float64(len(a.entries)), "entries")
}

// BenchmarkAPIRateLimiter_RepeatClient is the ordinary shape: one administrator
// inside its window. The cap must not tax it.
func BenchmarkAPIRateLimiter_RepeatClient(b *testing.B) {
	a := NewAPIRateLimiter()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		a.Allow("198.51.100.7")
	}
}
