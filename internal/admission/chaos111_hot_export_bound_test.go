package admission

// chaos111_hot_export_bound_test.go — CHAOS-111 gates for the engine half of
// the hot-IP gossip plane: the export is BOUNDED, the bound selects the
// HOTTEST, the selection is deterministic, and a hot set that fits is exported
// exactly as it was before the bound existed.
//
// Why the bound is in the engine and not only at the wire adapter: the quantity
// is produced here, and the receiving Control Plane applies the same bound to
// what a peer sends it (hottestDeltas in package main). Sender and receiver
// must agree on what "hottest" means and on how ties break, or a gate that
// asserts WHICH entries ride is flaky by construction.

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

// primeHot drives n distinct IPs to the given in-window count on r.
func primeHot(t *testing.T, r *RateLimiter, n, count int, prefix string) {
	t.Helper()
	for i := range n {
		ip := fmt.Sprintf("%s-%06d", prefix, i)
		for range count {
			if !r.Allow(ip) {
				t.Fatalf("priming %s: Allow denied below the limit", ip)
			}
		}
	}
}

// TestCHAOS111_ExportIsBoundedAndHottestFirst is the defect gate. Before the
// bound, ExportHotDeltas returned one entry per qualifying IP — a quantity
// traffic chooses, not the operator — so the gossip message, the Control
// Plane's retained heap and the per-round aggregation cost were all set by a
// flood.
func TestCHAOS111_ExportIsBoundedAndHottestFirst(t *testing.T) {
	r := NewRateLimiter()
	r.Configure(100, time.Minute) // threshold 50

	// 60 IPs at count 80 (the hot ones) and 300 at count 50 (also qualifying,
	// but colder). A bound of 50 must choose 50 of the 80s.
	primeHot(t, r, 60, 80, "hot")
	primeHot(t, r, 300, 50, "cold")

	deltas, omitted := r.ExportHotDeltasCapped(50)
	if len(deltas) != 50 {
		t.Fatalf("export carried %d entries, want exactly the bound 50", len(deltas))
	}
	if want := 360 - 50; omitted != want {
		t.Fatalf("omitted = %d, want %d (every qualifying IP the bound left out)", omitted, want)
	}
	for i := range deltas {
		if deltas[i].Count != 80 {
			t.Fatalf("entry %d has count %d; the bound must keep the HOTTEST, and 60 IPs sat at 80", i, deltas[i].Count)
		}
		if i > 0 && deltas[i-1].Count < deltas[i].Count {
			t.Fatalf("entry %d (%d) is hotter than entry %d (%d): the result must be hottest first",
				i, deltas[i].Count, i-1, deltas[i-1].Count)
		}
	}
}

// TestCHAOS111_ControlFittingHotSetIsExportedWholeAndUnchanged is the CONTROL
// that stops the bound from being a silent behaviour change. The cheapest way
// to pass the gate above is to truncate aggressively; this pins that an
// ordinary deployment — a hot set inside the bound — exports exactly what it
// exported before CHAOS-111, with nothing omitted.
func TestCHAOS111_ControlFittingHotSetIsExportedWholeAndUnchanged(t *testing.T) {
	r := NewRateLimiter()
	r.Configure(100, time.Minute)
	primeHot(t, r, 120, 60, "ip")
	// 40 below threshold: still excluded by the threshold, not by the bound.
	primeHot(t, r, 40, 10, "quiet")

	deltas, omitted := r.ExportHotDeltasCapped(MaxExportedHotIPs)
	if omitted != 0 {
		t.Fatalf("omitted = %d for a hot set well inside the bound, want 0", omitted)
	}
	if len(deltas) != 120 {
		t.Fatalf("export carried %d entries, want all 120 qualifying IPs", len(deltas))
	}
	seen := map[string]int{}
	for _, d := range deltas {
		seen[d.IP] = d.Count
	}
	for i := range 120 {
		ip := fmt.Sprintf("ip-%06d", i)
		if seen[ip] != 60 {
			t.Fatalf("%s exported as %d, want its absolute in-window count 60", ip, seen[ip])
		}
	}
	for i := range 40 {
		if _, ok := seen[fmt.Sprintf("quiet-%06d", i)]; ok {
			t.Fatal("a below-threshold IP was exported: the bound must not change which IPs QUALIFY")
		}
	}
}

// TestCHAOS111_ExportSelectionIsDeterministic pins that the chosen set depends
// only on the data. The walk is over Go maps, whose iteration order is
// randomised per run, so a selector that broke ties by arrival would make every
// assertion about WHICH entries ride flaky — and would also let the Control
// Plane and the Data Plane disagree about the same input.
func TestCHAOS111_ExportSelectionIsDeterministic(t *testing.T) {
	build := func(seed uint64) []HotCount {
		r := NewRateLimiter()
		r.Configure(100, time.Minute)
		for _, i := range shuffledIndexes(200, seed) {
			ip := fmt.Sprintf("ip-%06d", i)
			// Deliberately many ties at count 60 so the tie-break is exercised.
			count := 60
			if i%7 == 0 {
				count = 90
			}
			for range count {
				r.Allow(ip)
			}
		}
		deltas, _ := r.ExportHotDeltasCapped(40)
		return deltas
	}
	first := build(1)
	for seed := uint64(2); seed <= 6; seed++ {
		got := build(seed)
		if len(got) != len(first) {
			t.Fatalf("seed %d chose %d entries, first run chose %d", seed, len(got), len(first))
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("seed %d entry %d = %+v, first run = %+v: selection must not depend on map order",
					seed, i, got[i], first[i])
			}
		}
	}
}

// TestCHAOS111_ControlExportRetainsWindowAccounting re-pins, under the bound,
// the property the pre-existing TestExportHotDeltas_RetainsWindowAccounting
// owns: exporting is a READ. A selector that consumed counts, or that reported
// a delta since the last export rather than absolute occupancy, would silently
// un-limit every exported IP.
func TestCHAOS111_ControlExportRetainsWindowAccounting(t *testing.T) {
	r := NewRateLimiter()
	r.Configure(100, time.Minute)
	primeHot(t, r, 10, 70, "ip")
	for round := range 3 {
		deltas, omitted := r.ExportHotDeltasCapped(4)
		if len(deltas) != 4 || omitted != 6 {
			t.Fatalf("round %d: %d entries, %d omitted; want 4 and 6", round, len(deltas), omitted)
		}
		for _, d := range deltas {
			if d.Count != 70 {
				t.Fatalf("round %d: %s exported as %d, want the unchanged absolute count 70", round, d.IP, d.Count)
			}
		}
	}
}

// TestCHAOS111_ExportStaysNilWhenTheLimiterIsNotArmed keeps the two early
// returns the wire adapter depends on: rateLimitWireDeltas maps nil to JSON
// null, and the gossip round is skipped entirely when the limiter is off.
func TestCHAOS111_ExportStaysNilWhenTheLimiterIsNotArmed(t *testing.T) {
	r := NewRateLimiter()
	if deltas, omitted := r.ExportHotDeltasCapped(MaxExportedHotIPs); deltas != nil || omitted != 0 {
		t.Fatalf("unconfigured limiter exported %v (%d omitted), want nil and 0", deltas, omitted)
	}
	r.Configure(0, time.Minute)
	if deltas, omitted := r.ExportHotDeltasCapped(MaxExportedHotIPs); deltas != nil || omitted != 0 {
		t.Fatalf("limit 0 exported %v (%d omitted), want nil and 0", deltas, omitted)
	}
}

// TestCHAOS111_HotSelectorUnboundedKeepsEverything pins the limit<=0 escape the
// gates above rely on to compute an oracle, so a future change cannot quietly
// make it bound too.
func TestCHAOS111_HotSelectorUnboundedKeepsEverything(t *testing.T) {
	sel := NewHotSelector(0)
	for i := range 500 {
		sel.Offer(HotCount{IP: fmt.Sprintf("ip-%03d", i), Count: i})
	}
	got, omitted := sel.Result()
	if len(got) != 500 || omitted != 0 {
		t.Fatalf("unbounded selector kept %d (%d omitted), want 500 and 0", len(got), omitted)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Count < got[i].Count {
			t.Fatalf("unbounded result is not hottest first at %d", i)
		}
	}
}

// shuffledIndexes returns 0..n-1 in a seed-dependent order. It is a local
// splitmix64 keyed sort rather than math/rand because the ONLY thing this
// fixture needs is a different insertion order per seed — the point is to vary
// Go's map iteration order, not to be statistically random — and sorting by a
// generated key keeps the helper free of the integer conversions a shuffle
// needs.
func shuffledIndexes(n int, seed uint64) []int {
	state := seed + 0x9e3779b97f4a7c15
	next := func() uint64 {
		state += 0x9e3779b97f4a7c15
		z := state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		return z ^ (z >> 31)
	}
	keys := make([]uint64, n)
	out := make([]int, n)
	for i := range out {
		out[i] = i
		keys[i] = next()
	}
	sort.Slice(out, func(a, b int) bool { return keys[out[a]] < keys[out[b]] })
	return out
}
