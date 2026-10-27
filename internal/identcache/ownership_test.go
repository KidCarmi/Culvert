package identcache

import (
	"fmt"
	"testing"
	"time"
)

// The cap and the eviction sink are construction dependencies (ADR-0041). These
// pin that each cache is owned by whoever built it: its cap is the one it was
// given, its displacements reach only its own sink, and two caches share
// nothing.

func TestOwnership_OnEvictSeesEveryDisplacement(t *testing.T) {
	var sunk int
	c := New[int](Options{MaxEntries: 4, OnEvict: func() { sunk++ }})
	for i := 0; i < 10; i++ {
		c.Set(fmt.Sprintf("k-%d", i), "client", i, true, time.Hour)
	}
	if got := c.Len(); got != 4 {
		t.Fatalf("Len = %d, want the cap of 4", got)
	}
	if sunk != 6 || c.Evictions() != 6 {
		t.Fatalf("OnEvict saw %d and Evictions() = %d after 10 inserts against a cap of 4, want 6 and 6",
			sunk, c.Evictions())
	}
}

func TestOwnership_IndependentCachesShareNoState(t *testing.T) {
	var sunkA, sunkB int
	a := New[int](Options{MaxEntries: 2, OnEvict: func() { sunkA++ }})
	b := New[int](Options{MaxEntries: 2, OnEvict: func() { sunkB++ }})
	for i := 0; i < 8; i++ {
		a.Set(fmt.Sprintf("k-%d", i), "flood", i, false, time.Hour)
	}
	b.Set("k-0", "honest", 1, true, time.Hour)
	if sunkB != 0 || b.Evictions() != 0 {
		t.Fatalf("a flood of one cache reached another: sink %d, Evictions %d", sunkB, b.Evictions())
	}
	if _, _, hit := b.Get("k-0"); !hit {
		t.Fatal("the other cache's entry was displaced by a flood it never saw")
	}
	if sunkA != 6 {
		t.Fatalf("the flooded cache's sink saw %d displacements, want 6", sunkA)
	}
}

func TestOwnership_ANilSinkIsAllowed(t *testing.T) {
	c := New[int](Options{MaxEntries: 1})
	c.Set("a", "", 1, true, time.Hour)
	c.Set("b", "", 2, true, time.Hour)
	if c.Evictions() != 1 {
		t.Fatalf("Evictions() = %d, want 1", c.Evictions())
	}
}

func TestOwnership_ACapBelowOneHoldsOneEntry(t *testing.T) {
	for _, cache := range map[string]*Cache[int]{
		"New with MaxEntries 0": New[int](Options{}),
		"zero Cache":            new(Cache[int]),
	} {
		for i := 0; i < 3; i++ {
			cache.Set(fmt.Sprintf("k-%d", i), "", i, true, time.Hour)
		}
		if got := cache.Len(); got != 1 {
			t.Fatalf("Len = %d, want 1: a cap below one must still bound the cache", got)
		}
	}
}

func TestOwnership_ExpiryReportsTheRecordedDeadline(t *testing.T) {
	c := New[int](Options{MaxEntries: 4})
	deadline := time.Unix(time.Now().Add(time.Minute).Unix(), 0)
	c.SetUntil("k", "", 1, true, deadline)
	if got, ok := c.Expiry("k"); !ok || !got.Equal(deadline) {
		t.Fatalf("Expiry = %v, %v; want %v, true", got, ok, deadline)
	}
	if _, ok := c.Expiry("absent"); ok {
		t.Fatal("Expiry reported an entry that was never recorded")
	}
}

// BetterVictim is a total order: most live entries first, then the oldest
// entry, then the smaller client key. Package main's local credential cache uses
// it too, so a change here changes both.
func TestBetterVictim_TotalOrder(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	t1 := t0.Add(time.Second)
	cases := []struct {
		name       string
		live       int
		added      time.Time
		client     string
		bestLive   int
		bestAdded  time.Time
		bestClient string
		want       bool
	}{
		{"more live entries wins", 3, t1, "b", 2, t0, "a", true},
		{"fewer live entries loses", 2, t0, "a", 3, t1, "b", false},
		{"older entry wins a live tie", 2, t0, "b", 2, t1, "a", true},
		{"newer entry loses a live tie", 2, t1, "a", 2, t0, "b", false},
		{"smaller client wins a full tie", 2, t0, "a", 2, t0, "b", true},
		{"equal candidate is not better", 2, t0, "a", 2, t0, "a", false},
	}
	for _, tc := range cases {
		if got := BetterVictim(tc.live, tc.added, tc.client, tc.bestLive, tc.bestAdded, tc.bestClient); got != tc.want {
			t.Errorf("%s: BetterVictim = %v, want %v", tc.name, got, tc.want)
		}
	}
}
