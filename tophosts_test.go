package main

// tophosts_test.go — bounded-memory contract for the top-hosts counter. The
// hostname is attacker-controllable, so the counter MUST stay bounded and MUST
// keep heavy hitters visible despite a high-cardinality flood of one-off hosts.

import (
	"fmt"
	"testing"
)

// withTopHostsCap swaps the distinct-host cap for a test and restores it.
func withTopHostsCap(t *testing.T, maxEntries int) {
	t.Helper()
	prev := topHostsMaxEntries
	topHostsMaxEntries = maxEntries
	t.Cleanup(func() { topHostsMaxEntries = prev })
}

func freshHostCounter() *hostCounter {
	return &hostCounter{hosts: map[string]*int64{}}
}

func TestTopHosts_MemoryBounded(t *testing.T) {
	withTopHostsCap(t, 100)
	hc := freshHostCounter()

	// Flood with far more distinct hosts than the cap.
	for i := 0; i < 50_000; i++ {
		hc.Record(fmt.Sprintf("flood-%d.example", i))
	}

	hc.mu.Lock()
	n := len(hc.hosts)
	hc.mu.Unlock()
	if n > topHostsMaxEntries {
		t.Fatalf("map grew to %d entries, want <= cap %d (unbounded-memory DoS)", n, topHostsMaxEntries)
	}
}

func TestTopHosts_HeavyHittersSurviveFlood(t *testing.T) {
	withTopHostsCap(t, 100)
	hc := freshHostCounter()

	// Realistic heavy hitters are CONTINUOUSLY requested — interleave their
	// traffic with a high-cardinality flood of one-off junk hosts. The decay
	// eviction must keep the continuously-reinforced hot hosts on top while the
	// count-1 junk decays out, so memory stays bounded without top-N poisoning.
	for i := 0; i < 20_000; i++ {
		hc.Record("hot-a.example")
		hc.Record("hot-b.example")
		hc.Record(fmt.Sprintf("junk-%d.example", i))
	}

	hc.mu.Lock()
	n := len(hc.hosts)
	hc.mu.Unlock()
	if n > topHostsMaxEntries {
		t.Fatalf("map grew to %d entries, want <= cap %d", n, topHostsMaxEntries)
	}

	top := hc.Top(2)
	if len(top) < 2 {
		t.Fatalf("Top(2) returned %d entries", len(top))
	}
	got := map[string]bool{top[0].Host: true, top[1].Host: true}
	if !got["hot-a.example"] || !got["hot-b.example"] {
		t.Fatalf("heavy hitters evicted by flood; Top(2) = %+v (top-N poisoning)", top)
	}
}

func TestTopHosts_TrackedHostAlwaysCounts(t *testing.T) {
	withTopHostsCap(t, 10)
	hc := freshHostCounter()

	// Fill to capacity with distinct hosts.
	for i := 0; i < 10; i++ {
		hc.Record(fmt.Sprintf("h-%d.example", i))
	}
	// A host already in the map must keep incrementing even at capacity.
	for i := 0; i < 5; i++ {
		hc.Record("h-0.example")
	}
	hc.mu.Lock()
	p := hc.hosts["h-0.example"]
	hc.mu.Unlock()
	if p == nil {
		t.Fatal("tracked host evicted — already-tracked hosts must never be gated")
	}
	c := *p
	if c < 6 {
		t.Fatalf("tracked host count = %d, want >= 6 (already-tracked hosts must never be gated)", c)
	}
}

func TestTopHosts_TopSortedDescending(t *testing.T) {
	hc := freshHostCounter()
	hc.Record("a")
	hc.Record("a")
	hc.Record("a")
	hc.Record("b")
	hc.Record("b")
	hc.Record("c")

	top := hc.Top(3)
	if len(top) != 3 {
		t.Fatalf("Top(3) = %d entries, want 3", len(top))
	}
	if top[0].Host != "a" || top[0].Count != 3 {
		t.Errorf("top[0] = %+v, want a:3", top[0])
	}
	if top[2].Host != "c" || top[2].Count != 1 {
		t.Errorf("top[2] = %+v, want c:1", top[2])
	}
}
