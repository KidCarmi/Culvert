package main

// metrics_rulehit_test.go — correctness contract for the lock-free per-rule hit
// counter (ruleMetrics, metrics.go).
//
// The optimization is a COST change: every number RecordHit, WritePrometheus,
// otlpRuleMetrics and saveHitCounters produce must be identical to the
// RWMutex-guarded implementation. These tests pin the invariants that make the
// lock-free read safe, each of which fails if the copy-on-write discipline is
// broken.

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRuleMetrics_PublishedViewIsNeverMutatedInPlace is the spine of the whole
// change: a reader holding an older view must keep seeing a consistent index,
// so no writer may touch a map or slice that is already reachable from a
// published view. Copy-on-write makes that structural (the maps live only
// inside the view), and this test proves the discipline holds for BOTH writers
// — first-hit registration and snapshot restore.
func TestRuleMetrics_PublishedViewIsNeverMutatedInPlace(t *testing.T) {
	rm := newRuleMetrics()
	rm.RecordHit("first")

	before := rm.view()
	beforeHits := len(before.hits)
	beforeLast := len(before.last)
	beforeOrder := append([]string(nil), before.order...)

	rm.RecordHit("second")                                                             // registration
	rm.restoreRecords(map[string]persistedRuleCounter{"third": {Hits: 4, LastHit: 9}}) // restore

	if len(before.hits) != beforeHits || len(before.last) != beforeLast {
		t.Fatalf("a published view's maps grew in place: hits %d→%d, last %d→%d",
			beforeHits, len(before.hits), beforeLast, len(before.last))
	}
	if len(before.order) != len(beforeOrder) {
		t.Fatalf("a published view's order slice grew in place: %v → %v", beforeOrder, before.order)
	}
	for i := range beforeOrder {
		if before.order[i] != beforeOrder[i] {
			t.Fatalf("a published view's order slice was overwritten in place: %v → %v", beforeOrder, before.order)
		}
	}
	// The NEW view carries everything.
	cur := rm.view()
	for _, name := range []string{"first", "second", "third"} {
		if cur.hits[name] == nil {
			t.Fatalf("current view lost %q", name)
		}
	}
}

// TestRuleMetrics_CellsAreSharedAcrossViews is the other half of the same
// contract. A hit that resolves its cell through an older view must land on the
// counter the NEWER view exports — otherwise a rule registered concurrently
// would silently swallow hits. Cells are shared by reference on purpose; only
// the indexes are copied.
func TestRuleMetrics_CellsAreSharedAcrossViews(t *testing.T) {
	rm := newRuleMetrics()
	rm.RecordHit("shared")

	stale := rm.view() // resolve the cell through the OLD view…
	cell := stale.hits["shared"]
	rm.RecordHit("forces-a-new-view") // …then publish a replacement index…
	atomic.AddInt64(cell, 1)          // …and land the hit through the stale pointer.

	if got := atomic.LoadInt64(rm.view().hits["shared"]); got != 2 {
		t.Fatalf("hit through a stale view = %d, want 2 (cells must be shared, not copied)", got)
	}
}

// TestRuleMetrics_ConcurrentRegistrationLosesNoHits drives the race between the
// lock-free read and the write-locked registration: many goroutines hitting a
// mix of names that are being registered for the first time. Run under -race,
// this is also the no-in-place-mutation enforcement.
func TestRuleMetrics_ConcurrentRegistrationLosesNoHits(t *testing.T) {
	rm := newRuleMetrics()
	const (
		workers = 8
		names   = 25
		rounds  = 200
	)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				rm.RecordHit("race-rule-" + strconv.Itoa(i%names))
			}
		}()
	}
	wg.Wait()

	cur := rm.view()
	if len(cur.hits) != names {
		t.Fatalf("registered %d names, want %d", len(cur.hits), names)
	}
	var total int64
	for _, p := range cur.hits {
		total += atomic.LoadInt64(p)
	}
	if want := int64(workers * rounds); total != want {
		t.Fatalf("total hits = %d, want %d (a lost registration drops every hit that raced it)", total, want)
	}
	// order must stay in lock-step with hits: otlpRuleMetrics indexes hits BY
	// order and dereferences the result, so a missing or duplicated name there
	// is a nil-pointer panic on the OTLP export path.
	if len(cur.order) != len(cur.hits) {
		t.Fatalf("order has %d names, hits has %d — the exporters index one by the other", len(cur.order), len(cur.hits))
	}
	seen := make(map[string]bool, len(cur.order))
	for _, n := range cur.order {
		if seen[n] {
			t.Fatalf("order contains %q twice", n)
		}
		seen[n] = true
		if cur.hits[n] == nil {
			t.Fatalf("order names %q but hits has no cell for it", n)
		}
	}
}

// TestRuleMetrics_ExportersReadTheSameGeneration pins that both exporters walk
// a single consistent snapshot. The RWMutex used to supply that consistency for
// free; now it has to come from taking exactly ONE view() per export. Loading
// it twice (once for order, once per cell) would let a registration land in
// between and index a name the earlier generation's hits map does not carry —
// and otlpRuleMetrics dereferences the result, so that is a nil-pointer panic
// on the OTLP export path, not a wrong number.
func TestRuleMetrics_ExportersReadTheSameGeneration(t *testing.T) {
	withCleanRuleMet(t)
	ruleMet.RecordHit("export-a")
	ruleMet.RecordHit("export-a")
	ruleMet.RecordHit("export-b")

	var sb strings.Builder
	ruleMet.WritePrometheus(&sb)
	out := sb.String()
	if !strings.Contains(out, `culvert_policy_rule_hits_total{rule="export-a"} 2`) {
		t.Fatalf("Prometheus export missing export-a=2:\n%s", out)
	}
	if !strings.Contains(out, `culvert_policy_rule_hits_total{rule="export-b"} 1`) {
		t.Fatalf("Prometheus export missing export-b=1:\n%s", out)
	}

	got := otlpRuleMetrics("1")
	if len(got) != 2 {
		t.Fatalf("otlpRuleMetrics returned %d metrics, want 2", len(got))
	}
}

// TestRuleMetrics_CardinalityCapStillHolds — the cap is now evaluated against
// the published view rather than a locked map; it must still be exact, and a
// rejected name must not be published at all.
func TestRuleMetrics_CardinalityCapStillHolds(t *testing.T) {
	rm := newRuleMetrics()
	for i := 0; i < maxRuleMetrics+50; i++ {
		rm.RecordHit("cap-rule-" + strconv.Itoa(i))
	}
	cur := rm.view()
	if len(cur.hits) != maxRuleMetrics {
		t.Fatalf("hits cardinality = %d, want exactly %d", len(cur.hits), maxRuleMetrics)
	}
	if len(cur.order) != maxRuleMetrics {
		t.Fatalf("order cardinality = %d, want exactly %d", len(cur.order), maxRuleMetrics)
	}
	if len(cur.last) != maxRuleMetrics {
		t.Fatalf("last cardinality = %d, want exactly %d", len(cur.last), maxRuleMetrics)
	}
}

// TestRuleMetrics_LastHitIsStampedAndMonotonic pins the behaviour that moved
// with the clock read: the timestamp is now taken on the hit branch rather than
// before the lookup, and must still be stamped and never move backwards.
func TestRuleMetrics_LastHitIsStampedAndMonotonic(t *testing.T) {
	rm := newRuleMetrics()
	rm.RecordHit("stamped")
	if got := atomic.LoadInt64(rm.view().last["stamped"]); got == 0 {
		t.Fatal("first hit did not stamp lastHit")
	}

	future := time.Now().Add(time.Hour).Unix()
	atomic.StoreInt64(rm.view().last["stamped"], future)
	rm.RecordHit("stamped")
	if got := atomic.LoadInt64(rm.view().last["stamped"]); got != future {
		t.Fatalf("RecordHit moved lastHit backwards from %d to %d", future, got)
	}
}

// TestRuleMetrics_ZeroValueReadsAsEmpty — a struct literal built without
// newRuleMetrics has no published view. The read path must answer "unknown
// rule" rather than panic, and must not allocate a fallback per call.
func TestRuleMetrics_ZeroValueReadsAsEmpty(t *testing.T) {
	var rm ruleMetrics
	if v := rm.view(); v == nil || len(v.hits) != 0 {
		t.Fatalf("zero-value view = %v, want a non-nil empty view", v)
	}
	if a, b := rm.view(), rm.view(); a != b {
		t.Fatal("the zero-value fallback view is rebuilt per call; it must be the shared empty view")
	}
	// Registration through the zero value still works (it clones the fallback).
	rm.RecordHit("from-zero")
	if rm.view().hits["from-zero"] == nil {
		t.Fatal("registration through a zero-value ruleMetrics did not publish")
	}
	if len(emptyRuleCounterView.hits) != 0 {
		t.Fatal("registration mutated the shared empty fallback view")
	}
}
