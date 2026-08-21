package main

// controlplane_delta_test.go — T3 P1 slice 3: CP-side blocklist delta ring.

import (
	"sort"
	"testing"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

func sortedEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func TestDiffHosts(t *testing.T) {
	added, removed := diffHosts([]string{"a", "b", "c"}, []string{"b", "c", "d"})
	if !sortedEqual(added, []string{"d"}) {
		t.Errorf("added=%v want [d]", added)
	}
	if !sortedEqual(removed, []string{"a"}) {
		t.Errorf("removed=%v want [a]", removed)
	}
	// Identical sets → empty delta.
	a2, r2 := diffHosts([]string{"x", "x", "y"}, []string{"y", "x"})
	if len(a2) != 0 || len(r2) != 0 {
		t.Errorf("identical sets should diff empty, got added=%v removed=%v", a2, r2)
	}
}

// TestDeltaRing_ChainToLatest: a DP at base gets the ordered chain that advances
// it to the newest version, and applying that chain to a blocklist Store
// converges to the fingerprint the ring advertises.
func TestDeltaRing_ChainToLatest(t *testing.T) {
	var r blocklistDeltaRing
	// v1: {a,b}. v2: {a,b,c}. v3: {a,c,*.d} (drops b, adds *.d).
	v1 := []string{"a.example", "b.example"}
	v2 := []string{"a.example", "b.example", "c.example"}
	v3 := []string{"a.example", "c.example", "*.d.example"}
	r.record(0, 1, nil, v1, blocklist.FeedSetFingerprint(v1), 0)
	r.record(1, 2, v1, v2, blocklist.FeedSetFingerprint(v2), 0)
	r.record(2, 3, v2, v3, blocklist.FeedSetFingerprint(v3), 0)

	chain, latest, ok := r.chain(1)
	if !ok || latest != 3 {
		t.Fatalf("chain(1): ok=%v latest=%d, want ok latest=3", ok, latest)
	}
	if len(chain) != 2 || chain[0].Version != 2 || chain[1].Version != 3 {
		t.Fatalf("chain(1) versions = %v, want [2 3]", versionsOf(chain))
	}

	// Apply the chain to a store that starts at v1 and confirm convergence.
	store := blocklist.New()
	store.ReplaceFeedEntries(v1)
	if store.SyncedFingerprint() != blocklist.FeedSetFingerprint(v1) {
		t.Fatal("store did not start at v1 fingerprint")
	}
	for _, d := range chain {
		store.ApplyDelta(d.Added, d.Removed)
	}
	if store.SyncedFingerprint() != blocklist.FeedSetFingerprint(v3) {
		t.Fatal("applying the delta chain did not converge to the latest fingerprint")
	}
	if store.SyncedFingerprint() != chain[len(chain)-1].FP {
		t.Fatal("converged fingerprint must equal the ring's advertised target FP")
	}
}

func versionsOf(chain []blocklistDelta) []int64 {
	out := make([]int64, len(chain))
	for i := range chain {
		out[i] = chain[i].Version
	}
	return out
}

// TestDeltaRing_AlreadyCurrent: a DP at the newest version gets an empty chain
// with ok=true (nothing to apply).
func TestDeltaRing_AlreadyCurrent(t *testing.T) {
	var r blocklistDeltaRing
	r.record(0, 1, nil, []string{"a"}, blocklist.FeedSetFingerprint([]string{"a"}), 0)
	chain, latest, ok := r.chain(1)
	if !ok || latest != 1 || len(chain) != 0 {
		t.Fatalf("chain(1) at latest: ok=%v latest=%d len=%d, want ok/1/0", ok, latest, len(chain))
	}
}

// TestDeltaRing_GapResync: a DP older than the oldest retained delta cannot be
// served incrementally and must resync.
func TestDeltaRing_GapResync(t *testing.T) {
	var r blocklistDeltaRing
	for v := int64(1); v <= 5; v++ {
		r.record(v-1, v, nil, []string{"a"}, "fp", 0)
	}
	// Force eviction so v1..v2 fall out.
	// (With small deltas eviction is count-driven; shrink the ring by exceeding
	// the entry cap is impractical here, so assert the base-too-old path via a
	// base below the oldest retained Base.)
	_, _, ok := r.chain(-5)
	if ok {
		t.Fatal("a base older than the oldest retained delta must not be servable (resync)")
	}
}

// TestDeltaRing_OversizedDeltaMarker: a single delta above the per-delta byte
// cap becomes a resync marker; a DP that would traverse it resyncs.
func TestDeltaRing_OversizedDeltaMarker(t *testing.T) {
	var r blocklistDeltaRing
	r.record(0, 1, nil, []string{"a.example"}, "fp1", 0)
	// v2: a huge added set that blows maxSingleDeltaBytes (each ~24 B, 600k → ~14 MiB).
	huge := make([]string, 0, 600000)
	for i := 0; i < 600000; i++ {
		huge = append(huge, "host-"+padNum(i)+".example.com")
	}
	r.record(1, 2, []string{"a.example"}, huge, "fp2", 0)

	// The v2 entry must be a resync marker with no retained host slices.
	_, _, ok := r.chain(1) // traversing base=1 → must hit the v2 resync marker
	if ok {
		t.Fatal("a chain crossing a resync-marker delta must not be servable")
	}
	// But a DP already at v2 is current (no traversal needed).
	_, _, ok2 := r.chain(2)
	if !ok2 {
		t.Fatal("a DP already at the marker version should be current")
	}
	ents, bytes, _, _ := r.stats()
	if ents != 2 {
		t.Fatalf("ring should retain 2 entries, got %d", ents)
	}
	if bytes > maxSingleDeltaBytes {
		t.Fatalf("resync marker must not retain its oversized payload; totalBytes=%d", bytes)
	}
}

func padNum(i int) string {
	s := ""
	for n := i; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	if s == "" {
		s = "0"
	}
	return s
}

// TestDeltaRing_CountEviction: past the entry cap, oldest entries are evicted;
// a base pointing into the evicted range resyncs.
func TestDeltaRing_CountEviction(t *testing.T) {
	var r blocklistDeltaRing
	total := int64(maxDeltaRingEntries + 50)
	for v := int64(1); v <= total; v++ {
		// Non-nil oldHosts so each entry is a real delta (not a nil-baseline
		// resync marker); this test exercises count eviction + servability.
		r.record(v-1, v, []string{"prev"}, []string{"a"}, "fp", 0)
	}
	ents, _, oldest, newest := r.stats()
	if ents != maxDeltaRingEntries {
		t.Fatalf("ring should cap at %d entries, got %d", maxDeltaRingEntries, ents)
	}
	if newest != total {
		t.Fatalf("newest should be %d, got %d", total, newest)
	}
	if oldest != total-int64(maxDeltaRingEntries)+1 {
		t.Fatalf("oldest should be %d, got %d", total-int64(maxDeltaRingEntries)+1, oldest)
	}
	// A base in the evicted range → resync.
	if _, _, ok := r.chain(1); ok {
		t.Fatal("a base in the evicted range must resync")
	}
	// A base still retained → servable.
	if _, _, ok := r.chain(oldest); !ok {
		t.Fatal("a base at the oldest retained version must be servable")
	}
}

// TestDeltaRing_NonContiguousClears: a publish whose base does not match the
// newest retained version invalidates the chain (ring cleared).
func TestDeltaRing_NonContiguousClears(t *testing.T) {
	var r blocklistDeltaRing
	r.record(0, 1, nil, []string{"a"}, "fp", 0)
	r.record(1, 2, []string{"a"}, []string{"a", "b"}, "fp", 0)
	// A jump (e.g. HA promotion): base=100, target=101 — not contiguous with v2.
	r.record(100, 101, nil, []string{"c"}, "fp", 0)
	ents, _, oldest, newest := r.stats()
	if ents != 1 || oldest != 101 || newest != 101 {
		t.Fatalf("non-contiguous publish should clear the ring to just the new entry; got ents=%d oldest=%d newest=%d", ents, oldest, newest)
	}
	// The old versions are no longer servable.
	if _, _, ok := r.chain(1); ok {
		t.Fatal("versions before a non-contiguous jump must not be servable")
	}
}

// TestDeltaRing_ByteEviction exercises the byte-budget bound (a memory-DoS
// control): recording enough sub-maxSingleDeltaBytes deltas to exceed the 32 MiB
// total must evict oldest-first while keeping totalBytes within budget and ≥1
// entry retained.
func TestDeltaRing_ByteEviction(t *testing.T) {
	var r blocklistDeltaRing
	// Each delta ~1 MiB of added hosts (well under maxSingleDeltaBytes) so it is
	// retained (not a resync marker); ~40 of them exceed the 32 MiB total.
	perDelta := 1 << 20
	mk := func(seed int) []string {
		hosts := make([]string, 0, perDelta/24)
		for b := 0; b < perDelta; b += 24 {
			hosts = append(hosts, "host-"+padNum(seed)+"-"+padNum(b)+".example.com")
		}
		return hosts
	}
	total := int64(40)
	for v := int64(1); v <= total; v++ {
		r.record(v-1, v, []string{"prev"}, mk(int(v)), "fp", 0)
	}
	ents, bytes, oldest, newest := r.stats()
	if bytes > maxDeltaRingBytes {
		t.Fatalf("totalBytes=%d exceeds byte budget %d after eviction", bytes, maxDeltaRingBytes)
	}
	if ents < 1 || ents >= int(total) || newest != total {
		t.Fatalf("byte eviction should drop oldest and retain newest; ents=%d newest=%d", ents, newest)
	}
	// A base in the byte-evicted range (v1 was recorded first and evicted) resyncs;
	// the oldest retained delta's base (oldest-1) is still servable.
	if _, _, ok := r.chain(1); ok {
		t.Fatal("a base in the byte-evicted range must resync")
	}
	if _, _, ok := r.chain(oldest - 1); !ok {
		t.Fatalf("the oldest retained delta's base (%d) must be servable", oldest-1)
	}
}
