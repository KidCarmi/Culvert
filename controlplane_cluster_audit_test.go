package main

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
)

// Behavioral contract for the Control Plane's centralized audit ring. The ring
// rewrite (clusterAuditLog in controlplane.go) is a PERFORMANCE change to a
// compliance surface, so the window it exposes has to be provably the same
// window the growing-slice form exposed — not merely the same in the two
// hand-written cases that existed before. legacyClusterAuditLog in
// controlplane_cluster_audit_bench_test.go is that pre-change implementation,
// used here as the differential oracle.

// clusterAuditOracleStep applies one Append to both implementations.
func clusterAuditOracleStep(t *testing.T, got *clusterAuditLog, want *legacyClusterAuditLog, nodeID string, events []AuditEntry, step int) {
	t.Helper()
	got.Append(nodeID, events)
	want.Append(nodeID, events)

	if g, w := got.Count(), want.Count(); g != w {
		t.Fatalf("step %d: Count() = %d, oracle = %d", step, g, w)
	}
	// Every read width, not just the one the UI uses: an off-by-one in the wrap
	// arithmetic shows up at a specific n, and n == c.n (the full window) and
	// n == 1 are the two edges.
	for n := -1; n <= want.Count()+2; n++ {
		g, w := got.Recent(n), want.Recent(n)
		if len(g) != len(w) {
			t.Fatalf("step %d: Recent(%d) len = %d, oracle = %d", step, n, len(g), len(w))
		}
		for i := range w {
			if g[i] != w[i] {
				t.Fatalf("step %d: Recent(%d)[%d] = %+v, oracle = %+v", step, n, i, g[i], w[i])
			}
		}
	}
}

// clusterAuditEvents builds a batch whose entries are individually
// identifiable, so a lost, duplicated or reordered entry is visible rather
// than hidden behind equal-looking structs.
func clusterAuditEvents(tag string, n int) []AuditEntry {
	out := make([]AuditEntry, n)
	for i := range out {
		out[i] = AuditEntry{
			TS:       int64(i),
			Action:   "policy.update",
			Object:   fmt.Sprintf("%s/%d", tag, i),
			ObjectID: fmt.Sprintf("01JAX%s%04d", tag, i),
		}
	}
	return out
}

func TestClusterAuditLog_MatchesLegacy(t *testing.T) {
	// Sizes around the interesting boundaries: 1 (every append wraps), sizes
	// smaller than a realistic batch (oversized-batch path), and a size no
	// batch sequence reaches (never wraps).
	for _, maxSize := range []int{1, 2, 3, 7, 16, 64} {
		t.Run(fmt.Sprintf("maxSize=%d", maxSize), func(t *testing.T) {
			rng := rand.New(rand.NewSource(int64(maxSize) * 7919)) //nolint:gosec // deterministic test input, not a security decision
			got := &clusterAuditLog{maxSize: maxSize}
			want := &legacyClusterAuditLog{maxSize: maxSize}
			for step := 0; step < 120; step++ {
				// Batch sizes spanning empty, single, sub-window and
				// over-window, which is where the two forms could diverge.
				batch := rng.Intn(2*maxSize + 3)
				node := fmt.Sprintf("node-%d", rng.Intn(3))
				clusterAuditOracleStep(t, got, want, node, clusterAuditEvents(fmt.Sprintf("s%d", step), batch), step)
			}
		})
	}
}

func TestClusterAuditLog_OversizedBatchKeepsNewestTail(t *testing.T) {
	log := &clusterAuditLog{maxSize: 3}
	// One push larger than the whole window: the DP queue caps a batch at 1000
	// events (internal/audit maxPending), which exceeds a tuned-down ring.
	log.Append("node-a", clusterAuditEvents("big", 10))
	if got := log.Count(); got != 3 {
		t.Fatalf("Count() = %d, want 3", got)
	}
	recent := log.Recent(3)
	for i, wantObj := range []string{"big/7", "big/8", "big/9"} {
		if recent[i].Entry.Object != wantObj {
			t.Fatalf("Recent(3)[%d].Object = %q, want %q", i, recent[i].Entry.Object, wantObj)
		}
	}
}

func TestClusterAuditLog_DisabledWhenMaxSizeNonPositive(t *testing.T) {
	// A non-positive size disables the log instead of panicking. The
	// re-slicing form panicked for a negative size (entries[len+1:]), which is
	// not a contract worth preserving on an audit surface.
	for _, maxSize := range []int{0, -1} {
		log := &clusterAuditLog{maxSize: maxSize}
		log.Append("node-a", clusterAuditEvents("x", 4))
		if got := log.Count(); got != 0 {
			t.Fatalf("maxSize=%d: Count() = %d, want 0", maxSize, got)
		}
		if got := log.Recent(10); got != nil {
			t.Fatalf("maxSize=%d: Recent(10) = %v, want nil", maxSize, got)
		}
	}
}

func TestClusterAuditLog_RecentDoesNotAliasRing(t *testing.T) {
	log := &clusterAuditLog{maxSize: 4}
	log.Append("node-a", clusterAuditEvents("a", 4))

	out := log.Recent(4)
	// The caller owns the returned slice: writing to it must not reach the ring.
	out[0].NodeID = "tampered"
	if again := log.Recent(4); again[0].NodeID != "node-a" {
		t.Fatalf("caller write reached the ring: NodeID = %q", again[0].NodeID)
	}
	// And the converse: a later Append must not mutate an already-returned
	// snapshot, which is what the admin UI is holding while it renders.
	before := log.Recent(4)
	log.Append("node-b", clusterAuditEvents("b", 4))
	for i := range before {
		if before[i].NodeID != "node-a" {
			t.Fatalf("Append mutated a prior snapshot at %d: NodeID = %q", i, before[i].NodeID)
		}
	}
}

// TestClusterAuditLog_AppendAllocationFree is the REGRESSION guard: the point
// of the ring is that a saturated window stops churning the heap. Reintroducing
// any per-append allocation (a growing slice, a per-entry pointer, a formatted
// string) fails here rather than silently restoring ~4.4x write amplification
// on the fleet's audit aggregation point.
func TestClusterAuditLog_AppendAllocationFree(t *testing.T) {
	const maxSize = 512
	log := &clusterAuditLog{maxSize: maxSize}
	batch := clusterAuditEvents("warm", 8)
	for filled := 0; filled < 2*maxSize; filled += len(batch) {
		log.Append("node-warm", batch) // saturate, including the one-time buffer
	}
	// A full LAP per run, not a single Append: testing.AllocsPerRun averages
	// with INTEGER division, so a cost paid in periodic reallocations rounds to
	// a reported 0.000 over 200 single-Append runs and the assertion would hold
	// for the growing-slice shape too. Per lap the pre-change shape measures 1-2.
	got := testing.AllocsPerRun(5, func() {
		for filled := 0; filled < 2*maxSize; filled += len(batch) {
			log.Append("node-a", batch)
		}
	})
	if got != 0 {
		t.Fatalf("Append allocated %.1f times per lap of a saturated ring, want 0", got)
	}
}

// TestClusterAuditLog_ConcurrentAppendRecent is the concurrency shape the CP
// actually sees — many Data Planes pushing while the admin UI polls — run for
// the race detector and for the wrap arithmetic under interleaving.
func TestClusterAuditLog_ConcurrentAppendRecent(t *testing.T) {
	const (
		writers = 8
		rounds  = 200
		maxSize = 64
	)
	log := &clusterAuditLog{maxSize: maxSize}
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			batch := clusterAuditEvents(fmt.Sprintf("w%d", w), 5)
			for i := 0; i < rounds; i++ {
				log.Append(fmt.Sprintf("node-%d", w), batch)
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			// Never more than the window, never a short read, never a panic
			// from the wrap arithmetic mid-write.
			if got := log.Recent(maxSize); len(got) > maxSize {
				t.Errorf("Recent(%d) returned %d entries", maxSize, len(got))
				return
			}
		}
	}()
	wg.Wait()

	if got := log.Count(); got != maxSize {
		t.Fatalf("Count() = %d, want %d (window saturated)", got, maxSize)
	}
	// Every surviving slot holds a real entry: a torn write would leave the
	// zero value behind.
	for i, e := range log.Recent(maxSize) {
		if e.NodeID == "" || e.Entry.ObjectID == "" {
			t.Fatalf("Recent(%d)[%d] is a zero entry: %+v", maxSize, i, e)
		}
	}
}

// TestClusterAuditLog_BufferNeverGrows is the STRUCTURAL wall, and the thing
// that actually stops the cost being reintroduced: it is deterministic on any
// hardware, needs no build tag and no timing, and it fails the moment the ring
// goes back to a backing array that grows.
//
// The window is bounded at maxSize, so the buffer that holds it is exactly
// maxSize entries wide forever. The pre-change form satisfied the WINDOW bound
// while its backing array grew to ~2x behind it, which is why asserting on
// Count() alone never caught this: at the production maxSize of 5000 that was
// ~1.0 MB resident for a 760 kB window (measured, 999 467 B vs 761 915 B).
func TestClusterAuditLog_BufferNeverGrows(t *testing.T) {
	const maxSize = 64
	log := &clusterAuditLog{maxSize: maxSize}
	batch := clusterAuditEvents("lap", 7) // not a divisor of maxSize: every lap lands at a different offset
	for i := 0; i < 50*maxSize/len(batch); i++ {
		log.Append("node-a", batch)
		if got := len(log.buf); got != maxSize {
			t.Fatalf("after %d appends: len(buf) = %d, want %d", i+1, got, maxSize)
		}
		if got := cap(log.buf); got != maxSize {
			t.Fatalf("after %d appends: cap(buf) = %d, want %d — the backing array grew", i+1, got, maxSize)
		}
	}
	if got := log.Count(); got != maxSize {
		t.Fatalf("Count() = %d, want %d", got, maxSize)
	}
}
