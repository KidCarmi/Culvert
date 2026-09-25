package main

import (
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"
)

// RateLimiter.IsExempt moved from "take a process-wide read lock, then run a
// linear net.IPNet.Contains scan" to "load one immutable view, then probe a
// prefix-length-bucketed set". That is a COST change, so the verdict must be
// preserved byte for byte — an exemption is a rate-limit BYPASS, and widening
// one is a security regression, not an improvement.
//
// legacyIsExempt is a VERBATIM copy of the pre-change implementation, kept as
// the oracle for the differential test below. Do not "tidy" it: its value is
// that it is exactly what shipped.
func legacyIsExempt(exemptIPs map[string]bool, exemptNets []*net.IPNet, ip string) bool {
	if exemptIPs[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range exemptNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// newExemptFixture builds a limiter from entries and returns it alongside the
// authoritative write-side state the oracle needs.
func newExemptFixture(t *testing.T, entries []string) *RateLimiter {
	t.Helper()
	r := newRateLimiter()
	for _, e := range entries {
		// Invalid entries are deliberately fed in too — the oracle and the
		// implementation must agree about an entry neither of them stored.
		_ = r.AddExemption(e)
	}
	return r
}

func (r *RateLimiter) oracleIsExempt(ip string) bool {
	r.exemptMu.RLock()
	defer r.exemptMu.RUnlock()
	return legacyIsExempt(r.exemptIPs, r.exemptNets, ip)
}

// divergenceShapes are the probe/entry combinations where a netip-based
// rewrite is most likely to disagree with net.IP: family normalisation,
// IPv4-mapped forms, zones, boundary prefix lengths, and malformed input.
var exemptDivergenceEntries = []string{
	"10.0.0.0/8",
	"10.0.0.1",
	"0.0.0.0/0",
	"255.255.255.255/32",
	"192.0.2.128/25",
	"::ffff:10.0.0.0/104", // v4 network stored over 16 bytes — see prefixFromIPNet
	"2001:db8::/32",
	"2001:db8::1",
	"::/0",
	"::1",
	"fe80::/10",
	"not-an-ip",
	"10.0.0.0/33",
	"",
}

var exemptDivergenceProbes = []string{
	"10.0.0.1",
	"10.255.255.254",
	"11.0.0.1",
	"0.0.0.0",
	"255.255.255.255",
	"192.0.2.129",
	"192.0.2.127",
	"::ffff:10.0.0.1", // IPv4-mapped form of an entry stored as plain v4
	"::ffff:11.0.0.1",
	"2001:db8::1",
	"2001:db9::1",
	"::1",
	"fe80::1",
	"fe80::1%eth0", // zoned: net.ParseIP rejects, so it matches nothing
	"not-an-ip",
	"",
	"203.0.113.7",
}

func TestRLExemptView_DifferentialAgainstLegacy_Shapes(t *testing.T) {
	// Every non-empty subset would be 2^14; instead every entry is exercised
	// alone (isolating its own normalisation) and all together (exercising the
	// family split and the bucket ordering).
	subsets := [][]string{exemptDivergenceEntries}
	for _, e := range exemptDivergenceEntries {
		subsets = append(subsets, []string{e})
	}

	for _, entries := range subsets {
		r := newExemptFixture(t, entries)
		for _, probe := range exemptDivergenceProbes {
			want := r.oracleIsExempt(probe)
			got := r.IsExempt(probe)
			if got != want {
				t.Errorf("entries=%v probe=%q: IsExempt=%v, legacy=%v", entries, probe, got, want)
			}
		}
	}
}

func TestRLExemptView_DifferentialAgainstLegacy_Randomized(t *testing.T) {
	// #nosec G404 -- deterministic seeded generator for reproducible test data
	rng := rand.New(rand.NewSource(20260911))

	randV4 := func() string {
		return fmt.Sprintf("%d.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
	}
	randEntry := func() string {
		switch rng.Intn(4) {
		case 0:
			return randV4()
		case 1:
			return fmt.Sprintf("%s/%d", randV4(), rng.Intn(33))
		case 2:
			return fmt.Sprintf("2001:db8:%x::/%d", rng.Intn(65536), 32+rng.Intn(65))
		default:
			return fmt.Sprintf("2001:db8:%x::%x", rng.Intn(65536), rng.Intn(65536))
		}
	}

	for iter := 0; iter < 300; iter++ {
		entries := make([]string, 0, 8)
		for i := 0; i < 1+rng.Intn(8); i++ {
			entries = append(entries, randEntry())
		}
		r := newExemptFixture(t, entries)

		probes := make([]string, 0, 12)
		probes = append(probes, exemptDivergenceProbes...)
		for i := 0; i < 8; i++ {
			probes = append(probes, randEntry())
		}
		// Probe the entries themselves too, so hits are actually exercised
		// rather than relying on a random address landing inside a prefix.
		probes = append(probes, entries...)

		for _, probe := range probes {
			want := r.oracleIsExempt(probe)
			if got := r.IsExempt(probe); got != want {
				t.Fatalf("iter=%d entries=%v probe=%q: IsExempt=%v, legacy=%v",
					iter, entries, probe, got, want)
			}
		}
	}
}

// TestRLExemptView_MappedProbeStaysNonExempt pins the one semantic the view
// could plausibly have "fixed" and must not: canonicalising the single-IP set
// to netip.Addr would make an IPv4-mapped probe hit a plain-v4 exemption,
// handing a client a rate-limit bypass it does not have today.
func TestRLExemptView_MappedProbeStaysNonExempt(t *testing.T) {
	r := newRateLimiter()
	if err := r.AddExemption("198.51.100.7"); err != nil {
		t.Fatalf("AddExemption: %v", err)
	}
	if !r.IsExempt("198.51.100.7") {
		t.Fatal("plain v4 probe should be exempt")
	}
	if r.IsExempt("::ffff:198.51.100.7") {
		t.Fatal("IPv4-mapped probe must NOT be exempt: a single-IP exemption is " +
			"stored and probed as a raw string, and widening that is a rate-limit bypass")
	}
}

// TestRLExemptView_EveryMutatorRepublishes is the security gate for the
// lock-free read path: a mutator that changes the authoritative state without
// republishing leaves IsExempt answering from a stale view — a revoked
// exemption that keeps bypassing the rate limit, or a new one that never
// takes effect. Each case drives a real mutator and asserts the LOCK-FREE
// answer changed, which is only true if that mutator published.
func TestRLExemptView_EveryMutatorRepublishes(t *testing.T) {
	cases := []struct {
		mutator string
		apply   func(r *RateLimiter)
		probe   string
		want    bool
	}{
		{"AddExemption/ip", func(r *RateLimiter) { _ = r.AddExemption("203.0.113.9") }, "203.0.113.9", true},
		{"AddExemption/cidr", func(r *RateLimiter) { _ = r.AddExemption("198.51.100.0/24") }, "198.51.100.5", true},
		{"AddExemptions", func(r *RateLimiter) { _ = r.AddExemptions([]string{"192.0.2.0/24"}) }, "192.0.2.7", true},
		{"ReplaceExemptions/set", func(r *RateLimiter) { r.ReplaceExemptions([]string{"10.0.0.0/8"}) }, "10.1.2.3", true},
		{"RemoveExemption/ip", func(r *RateLimiter) {
			_ = r.AddExemption("203.0.113.9")
			r.RemoveExemption("203.0.113.9")
		}, "203.0.113.9", false},
		{"RemoveExemption/cidr", func(r *RateLimiter) {
			_ = r.AddExemption("198.51.100.0/24")
			r.RemoveExemption("198.51.100.0/24")
		}, "198.51.100.5", false},
		{"ReplaceExemptions/clear", func(r *RateLimiter) {
			_ = r.AddExemption("10.0.0.0/8")
			r.ReplaceExemptions(nil)
		}, "10.1.2.3", false},
	}

	for _, tc := range cases {
		t.Run(tc.mutator, func(t *testing.T) {
			r := newRateLimiter()
			tc.apply(r)
			if got := r.IsExempt(tc.probe); got != tc.want {
				t.Fatalf("%s: IsExempt(%q)=%v, want %v — mutator did not publish "+
					"the derived view (see publishExemptViewLocked)", tc.mutator, tc.probe, got, tc.want)
			}
			// The lock-free view must also agree with the authoritative state.
			if want := r.oracleIsExempt(tc.probe); r.IsExempt(tc.probe) != want {
				t.Fatalf("%s: view disagrees with authoritative state for %q", tc.mutator, tc.probe)
			}
		})
	}
}

// TestRLExemptView_MutatorInventoryIsComplete fails when a NEW exported
// mutator appears on RateLimiter's exempt surface without being classified
// here, so the republish contract above cannot silently stop covering it.
func TestRLExemptView_MutatorInventoryIsComplete(t *testing.T) {
	// Exported methods whose names touch the exempt surface, split into the
	// ones that MUTATE it (must republish, and are covered above) and the ones
	// that only READ it.
	mutators := map[string]bool{"AddExemption": true, "AddExemptions": true,
		"RemoveExemption": true, "ReplaceExemptions": true}
	readers := map[string]bool{"IsExempt": true, "ListExemptions": true}

	var unclassified []string
	rt := reflect.TypeOf(&RateLimiter{})
	for i := 0; i < rt.NumMethod(); i++ {
		name := rt.Method(i).Name
		if !containsExemptToken(name) {
			continue
		}
		if !mutators[name] && !readers[name] {
			unclassified = append(unclassified, name)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Fatalf("unclassified exempt-surface method(s) %v: if it MUTATES the exempt "+
			"list it must call publishExemptViewLocked and be added to "+
			"TestRLExemptView_EveryMutatorRepublishes; if it only reads, add it to `readers`",
			unclassified)
	}
}

func containsExemptToken(name string) bool {
	for i := 0; i+6 <= len(name); i++ {
		if name[i:i+6] == "Exempt" {
			return true
		}
	}
	return false
}

// TestRLExemptView_ConcurrentReadersAndMutators is the other half of the
// lock-free contract, enforced by the race detector: nothing reachable from a
// PUBLISHED view may be mutated in place. It matters specifically because
// RemoveExemption compacts r.exemptNets IN PLACE (`filtered := r.exemptNets[:0]`),
// which would be a data race if the view aliased that slice instead of holding
// a derived copy.
//
//	go test -race -run TestRLExemptView_ConcurrentReadersAndMutators .
func TestRLExemptView_ConcurrentReadersAndMutators(t *testing.T) {
	r := newRateLimiter()
	_ = r.AddExemptions([]string{"10.0.0.0/8", "198.51.100.0/24", "203.0.113.9"})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = r.IsExempt("10.1.2.3")
					_ = r.IsExempt("203.0.113.9")
					_ = r.IsExempt("2001:db8::1")
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			_ = r.AddExemption("192.0.2.0/24")
			r.RemoveExemption("192.0.2.0/24")
			_ = r.AddExemptions([]string{"172.16.0.0/12"})
			r.ReplaceExemptions([]string{"10.0.0.0/8", "198.51.100.0/24", "203.0.113.9"})
			_ = r.ListExemptions()
		}
		close(stop)
	}()

	wg.Wait()
}

// TestRLExemptView_BareLiteralLimiterIsSafe pins that IsExempt has a
// well-defined answer before any mutator has published — `&RateLimiter{}` is
// constructed as a bare composite literal by the cluster tests, so the nil
// view must not panic.
func TestRLExemptView_BareLiteralLimiterIsSafe(t *testing.T) {
	r := &RateLimiter{}
	if r.IsExempt("203.0.113.7") {
		t.Fatal("a limiter with no exemptions must exempt nothing")
	}
	// And it must still accept a first mutation.
	if err := r.AddExemption("203.0.113.7"); err != nil {
		t.Fatalf("AddExemption on bare literal: %v", err)
	}
	if !r.IsExempt("203.0.113.7") {
		t.Fatal("exemption added to a bare-literal limiter did not take effect")
	}
}

// TestRLExemptView_AddExemptionsMatchesAddLoop pins that the bulk primitive is
// a pure cost optimisation over the per-entry loop it replaced at the boot and
// config-import call sites — same accepted set, same rejected set.
func TestRLExemptView_AddExemptionsMatchesAddLoop(t *testing.T) {
	entries := []string{"10.0.0.0/8", "bogus", "203.0.113.9", "", "2001:db8::/32", "10.0.0.0/33"}

	loop := newRateLimiter()
	var loopInvalid []string
	for _, e := range entries {
		if err := loop.AddExemption(e); err != nil {
			loopInvalid = append(loopInvalid, e)
		}
	}

	bulk := newRateLimiter()
	var bulkInvalid []string
	for _, bad := range bulk.AddExemptions(entries) {
		bulkInvalid = append(bulkInvalid, bad.Entry)
	}

	if !reflect.DeepEqual(loopInvalid, bulkInvalid) {
		t.Errorf("rejected entries differ: loop=%v bulk=%v", loopInvalid, bulkInvalid)
	}

	got, want := loop.ListExemptions(), bulk.ListExemptions()
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("accepted set differs: loop=%v bulk=%v", got, want)
	}

	for _, probe := range exemptDivergenceProbes {
		if loop.IsExempt(probe) != bulk.IsExempt(probe) {
			t.Errorf("probe %q: loop=%v bulk=%v", probe,
				loop.IsExempt(probe), bulk.IsExempt(probe))
		}
	}
}

// TestExemptBenchFixturesProbeWhatTheyClaim guards the benchmark fixtures
// themselves. A "hit" benchmark whose probe silently misses measures the miss
// path twice and cannot detect a regression in the hit path at all — which is
// exactly what happened on this PR: benchExemptCIDRs derives its octets as
// (i/256, i%256), so for n<=256 the high octet is always 0, and the original
// 10.255.255.1 probe was outside every generated prefix (caught in review).
// Prose alone could not catch that; the numbers simply came out wrong.
func TestExemptBenchFixturesProbeWhatTheyClaim(t *testing.T) {
	miss := newRateLimiter()
	_ = miss.AddExemptions(benchExemptCIDRs(256))
	if !miss.IsExempt(benchExemptCIDRHitIP) {
		t.Errorf("benchExemptCIDRHitIP (%s) is not inside benchExemptCIDRs(256): "+
			"the CIDR-hit benchmark and alloc posture are measuring a MISS",
			benchExemptCIDRHitIP)
	}
	if miss.IsExempt(benchExemptProbeIP) {
		t.Errorf("benchExemptProbeIP (%s) is inside benchExemptCIDRs(256): "+
			"the miss benchmarks are measuring a hit", benchExemptProbeIP)
	}

	// The realistic fixture must also hit on its single-IP probe and miss on
	// the shared miss probe, for the same reason.
	realistic := newRateLimiter()
	_ = realistic.AddExemptions(benchExemptRealistic)
	if !realistic.IsExempt("198.51.100.7") {
		t.Error("benchExemptRealistic does not exempt 198.51.100.7: BenchmarkIsExempt_Hit measures a miss")
	}
	if realistic.IsExempt(benchExemptProbeIP) {
		t.Errorf("benchExemptRealistic exempts %s: the realistic miss benchmark measures a hit", benchExemptProbeIP)
	}

	// And no client IP the end-to-end Allow benchmark uses may be exempt, or it
	// would skip the limiter entirely and measure nothing.
	for _, n := range []int{0, 16, 256} {
		r := newRateLimiter()
		_ = r.AddExemptions(benchExemptCIDRs(n))
		for _, ip := range benchClientIPs(256) {
			if r.IsExempt(ip) {
				t.Fatalf("benchClientIPs contains %s which is exempt under benchExemptCIDRs(%d): "+
					"BenchmarkRateLimitAllow_WithExemptions would bypass the limiter", ip, n)
			}
		}
	}
}

// ─── Cost-shape gates ───────────────────────────────────────────────────────

// TestBenchGate_IsExemptTakesNoLock is STRUCTURAL, not timing-based: it holds
// the limiter's exempt write lock and requires IsExempt to answer anyway. A
// return to a lock-guarded read path deadlocks the helper goroutine and the
// test fails deterministically on any hardware, at any load, with or without
// -race. (A scaling-ratio gate was considered and rejected for the reason
// recorded throughout this repo: a gate that can flake gets muted.)
func TestBenchGate_IsExemptTakesNoLock(t *testing.T) {
	r := newRateLimiter()
	_ = r.AddExemptions([]string{"198.51.100.0/24", "203.0.113.9"})

	r.exemptMu.Lock()
	defer r.exemptMu.Unlock()

	probes := []struct {
		ip   string
		want bool
		note string
	}{
		{"203.0.113.47", false, "unlisted IP is not exempt"},
		{"198.51.100.9", true, "IP inside an exempt range is exempt"},
		{"203.0.113.9", true, "exact exempt IP is exempt"},
	}

	type result struct {
		i   int
		got bool
	}
	done := make(chan result, len(probes))
	for i := range probes {
		go func(i int, ip string) { done <- result{i, r.IsExempt(ip)} }(i, probes[i].ip)
	}

	// Completion order is not deterministic, so each result carries its index
	// and every verdict is checked individually — the gate proves the read path
	// still ANSWERS under the write lock, and still answers CORRECTLY.
	for range probes {
		select {
		case res := <-done:
			if p := probes[res.i]; res.got != p.want {
				t.Errorf("IsExempt(%q) = %v, want %v (%s)", p.ip, res.got, p.want, p.note)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("IsExempt blocked while the exempt write lock was held: the " +
				"per-request read path has taken a lock again")
		}
	}
}

// TestBenchGate_ExemptMutatorsStillTakeTheLock is the CONTROL for the gate
// above: without it, a "passing" no-lock gate could also mean the write side
// simply stopped locking, which would be a data race rather than an
// optimisation. A mutator must still block while the lock is held.
func TestBenchGate_ExemptMutatorsStillTakeTheLock(t *testing.T) {
	r := newRateLimiter()

	r.exemptMu.Lock()
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		_ = r.AddExemption("203.0.113.9")
		close(done)
	}()
	<-started

	select {
	case <-done:
		r.exemptMu.Unlock()
		t.Fatal("AddExemption completed while the exempt write lock was held: " +
			"the write side is no longer serialised, so the lock-free read path is unsound")
	case <-time.After(100 * time.Millisecond):
		// Correct: still blocked.
	}
	r.exemptMu.Unlock()
	<-done // and it completes once the lock is released
}

// TestBenchGate_IsExemptIsFlatInCIDRCount is a RATIO gate, so it is
// machine-independent: it compares the limiter against itself at two exempt-
// list sizes rather than against an absolute nanosecond budget.
//
// The pre-change linear net.IPNet.Contains scan cost ~14 ns per exempt CIDR,
// so 256 exempt prefixes cost ~57x what 1 costs — measured at 3.6 µs per
// request on a 4-core Xeon, inside the request goroutine, which was ~74% of
// the entire rate-limit gate. Bucketing by prefix length makes the cost depend
// on the number of DISTINCT prefix lengths (here: one, /24) instead. Measured
// ratio after the change is ~1.0; the bound is 4x so the gate keeps a wide
// margin under -race on a shared CI runner while still failing hard if the
// linear scan returns.
func TestBenchGate_IsExemptIsFlatInCIDRCount(t *testing.T) {
	if testing.Short() {
		t.Skip("cost-shape gate skipped in -short")
	}
	const (
		small = 1
		large = 256
		bound = 4.0
	)

	measure := func(n int) time.Duration {
		r := newRateLimiter()
		_ = r.AddExemptions(benchExemptCIDRs(n))
		const iters = 20000
		// Warm up so neither size pays first-touch costs the other does not.
		for i := 0; i < 1000; i++ {
			_ = r.IsExempt(benchExemptProbeIP)
		}
		start := time.Now()
		for i := 0; i < iters; i++ {
			_ = r.IsExempt(benchExemptProbeIP)
		}
		return time.Since(start)
	}

	// Best-of-three: a scheduler hiccup inflates a sample, never deflates it.
	best := func(n int) time.Duration {
		d := measure(n)
		for i := 0; i < 2; i++ {
			if e := measure(n); e < d {
				d = e
			}
		}
		return d
	}

	dSmall, dLarge := best(small), best(large)
	ratio := float64(dLarge) / float64(dSmall)
	t.Logf("cidrs=%d: %v, cidrs=%d: %v, ratio=%.2fx (flat ~1x, linear ~57x, bound %.1fx)",
		small, dSmall, large, dLarge, ratio, bound)
	if ratio > bound {
		t.Errorf("IsExempt cost scales with the exempt CIDR count (%.2fx for %dx the "+
			"prefixes, bound %.1fx): the linear net.IPNet.Contains scan has returned",
			ratio, large/small, bound)
	}
}

// TestBenchGate_RateLimitExemptBulkLoadIsLinear pins that a list-restoring
// caller uses AddExemptions rather than an AddExemption loop. Publishing the
// derived view per entry makes a bulk load quadratic, and this list's
// ConfigSnapshot cap is maxSnapRateLimitExempt (10,000) — reached by the boot
// admin_settings restore and by config import.
//
// A RATIO gate, so it is machine-independent: 4x the entries should cost ~4x
// if the load is linear and ~16x if it is quadratic. The bound is 8x, midway
// on a log scale.
func TestBenchGate_RateLimitExemptBulkLoadIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("cost-shape gate skipped in -short")
	}
	const (
		small = 2500
		large = 10000 // 4x, and the ConfigSnapshot cap for this list
		bound = 8.0
	)

	entries := func(n int) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("10.%d.%d.1", i/256, i%256))
		}
		return out
	}

	measure := func(n int) time.Duration {
		list := entries(n)
		r := newRateLimiter()
		// Settle the collector before the clock starts, as testing.B does — the
		// same fix, measurement and reasoning as the sibling gate
		// TestBenchGate_IPFilterBulkLoadIsLinear (see the comment there).
		runtime.GC()
		start := time.Now()
		r.AddExemptions(list)
		return time.Since(start)
	}

	best := func(n int) time.Duration {
		d := measure(n)
		for i := 0; i < 2; i++ {
			if e := measure(n); e < d {
				d = e
			}
		}
		return d
	}

	dSmall, dLarge := best(small), best(large)
	ratio := float64(dLarge) / float64(dSmall)
	t.Logf("entries=%d: %v, entries=%d: %v, ratio=%.2fx (linear ~4x, quadratic ~16x, bound %.1fx)",
		small, dSmall, large, dLarge, ratio, bound)
	if ratio > bound {
		t.Errorf("bulk exempt load scales superlinearly (%.2fx for 4x the entries, "+
			"bound %.1fx): the view is being republished per entry again", ratio, bound)
	}
}

// TestBenchGate_IsExemptAllocsFree pins that the read path allocates nothing in
// every posture. netip.ParseAddr returns a VALUE, so the probe formats no
// string and copies no byte slice — where net.ParseIP returned a net.IP
// (a slice) that only escape analysis kept off the heap.
func TestBenchGate_IsExemptAllocsFree(t *testing.T) {
	postures := []struct {
		name    string
		entries []string
		probe   string
	}{
		{"no-exemptions", nil, benchExemptProbeIP},
		{"singles-only/miss", []string{"198.51.100.7"}, benchExemptProbeIP},
		{"singles-only/hit", []string{"198.51.100.7"}, "198.51.100.7"},
		{"realistic/miss", benchExemptRealistic, benchExemptProbeIP},
		{"realistic/hit", benchExemptRealistic, "198.51.100.7"},
		{"cidrs=256/miss", benchExemptCIDRs(256), benchExemptProbeIP},
		{"cidrs=256/hit", benchExemptCIDRs(256), benchExemptCIDRHitIP},
		{"v6", []string{"2001:db8::/32"}, "2001:db8::1"},
	}

	for _, p := range postures {
		t.Run(p.name, func(t *testing.T) {
			r := newRateLimiter()
			_ = r.AddExemptions(p.entries)
			if got := testing.AllocsPerRun(200, func() { _ = r.IsExempt(p.probe) }); got != 0 {
				t.Errorf("IsExempt allocates %.0f times per call in posture %q; want 0", got, p.name)
			}
		})
	}
}

// TestBenchGate_IsExemptUnparseableProbeAllocBound records, rather than hides,
// the one posture that is NOT allocation-free: netip.ParseAddr boxes an error
// value on a malformed address (measured: 1 alloc; 0 on a valid one), where
// net.ParseIP returned a nil slice for free.
//
// It is carried as a bounded, documented exception rather than guarded in the
// hot path, for two reasons. It is UNREACHABLE on the request path —
// realClientIP returns either peerHost(RemoteAddr), which net/http fills from
// the accepted socket, or a canonical net.IP.String() of an XFF hop that
// already parsed — so no caller can drive it. And it is PRE-EXISTING rather
// than introduced here: the shipped IPFilter.Allowed, which has used
// netip.ParseAddr on the same request-path input since the ipFilterView
// change, measures the identical 1 alloc on the identical input. Adding a
// pre-validation guard would be complexity bought for an unreachable case.
//
// The bound is 1, so a future change that makes this path allocate MORE — or
// that makes a reachable posture allocate at all (the gate above) — still
// fails.
func TestBenchGate_IsExemptUnparseableProbeAllocBound(t *testing.T) {
	r := newRateLimiter()
	_ = r.AddExemptions(benchExemptRealistic)
	if got := testing.AllocsPerRun(200, func() { _ = r.IsExempt("not-an-ip") }); got > 1 {
		t.Errorf("IsExempt allocates %.0f times on a malformed probe; bound is 1 "+
			"(netip.ParseAddr's boxed error)", got)
	}
}
