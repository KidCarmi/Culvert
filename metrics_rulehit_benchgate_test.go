//go:build benchgate

package main

// Regression gates for the lock-free per-rule hit counter (ruleMetrics.view,
// metrics.go). Pairs with the benchgate family (bench_regression_test.go).
//
//	go test -tags benchgate -run 'TestBenchGate_RecordHit' -v .
//
// The scaling gate this replaces was built first and thrown away, for the same
// reason internal/connlimit's and the IP filter's were: a ns/op ratio measured
// on a shared CI runner, under -race, is too thin a margin to gate a PR on, and
// a gate that can flake gets muted. Both gates here are STRUCTURAL — they hold
// the write lock and require RecordHit to answer anyway — so they are
// deterministic on any hardware, at any load, with or without -race.

import (
	"fmt"
	"testing"
	"time"
)

// callWithWriteLockHeld runs fn while rm.mu is held for WRITING and reports
// whether it completed. A path that takes rm.mu — in either mode — cannot.
func callWithWriteLockHeld(rm *ruleMetrics, fn func()) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

// TestBenchGate_RecordHitTakesNoLock is the gate: on the steady-state path — a
// rule name that already has a counter cell, which is every request after the
// first on a stable rule set — RecordHit must reach its counters without
// touching rm.mu.
//
// It runs on EVERY proxied request that matched a policy rule, so a regression
// back to the lock is not a constant cost but a throughput ceiling: the
// RWMutex read lock is an atomic read-modify-write on one process-wide word,
// measured at 15.2 ns/op at GOMAXPROCS=1 but 71.6 ns at 4 — it got worse the
// more cores carried traffic.
func TestBenchGate_RecordHitTakesNoLock(t *testing.T) {
	rm, names := benchRuleHitStore(8)
	if !callWithWriteLockHeld(rm, func() { rm.RecordHit(names[0]) }) {
		t.Fatal("RecordHit blocked on rm.mu for an already-tracked rule: the per-request " +
			"lock is back. Read the ruleMetricsView comment in metrics.go before changing this.")
	}
}

// TestBenchGate_RecordHitSealedTakesNoLock covers the other per-request path a
// deployment can sit on: more than maxRuleMetrics distinct rule names. Those
// over-cap names are ignored, but deciding that used to cost the EXCLUSIVE
// lock on every request that matched one — full serialisation of the request
// path, strictly worse than the read lock the view removes.
func TestBenchGate_RecordHitSealedTakesNoLock(t *testing.T) {
	rm, _ := benchRuleHitStore(maxRuleMetrics)
	if v := rm.view.Load(); v == nil || !v.sealed {
		t.Fatal("precondition: the view must be sealed at the cardinality cap")
	}
	if !callWithWriteLockHeld(rm, func() { rm.RecordHit("never-seen-before") }) {
		t.Fatal("RecordHit blocked on rm.mu for an over-cap rule name: the sealed " +
			"short-circuit is gone and every such request now serialises")
	}
}

// TestBenchGate_RecordHitFirstSightingStillLocks is the CONTROL. Without it a
// passing gate above could mean nothing at all — RecordHit having stopped
// taking the lock because it stopped doing the work, or the harness failing to
// hold the lock it thinks it holds. A genuinely NEW name on an UNSEALED store
// must still go through the mutator, and therefore must still block.
func TestBenchGate_RecordHitFirstSightingStillLocks(t *testing.T) {
	rm, _ := benchRuleHitStore(8)
	if callWithWriteLockHeld(rm, func() { rm.RecordHit("first-sighting") }) {
		t.Fatal("control failed: a first sighting completed while the write lock was " +
			"held, so the gates above prove nothing")
	}
}

// TestBenchGate_LegacyRecordHitBlocks is the DEFECT PROOF. The gates above are
// only worth their runtime if they would actually reject the shape they were
// written to keep out, so this runs the frozen pre-view body
// (recordHitLegacy, metrics_rulehit_view_test.go) through the identical
// harness and requires it to block. If this ever passes, the harness has
// stopped discriminating and the gates above have quietly become vacuous.
func TestBenchGate_LegacyRecordHitBlocks(t *testing.T) {
	rm, names := benchRuleHitStore(8)
	if callWithWriteLockHeld(rm, func() { recordHitLegacy(rm, names[0], 1) }) {
		t.Fatal("the pre-view body completed while the write lock was held — the " +
			"no-lock gates cannot be detecting what they claim to detect")
	}
}

// TestBenchGate_RecordHitAllocsFree pins the hot path at zero allocations.
// allocs/op are hardware-independent, so this is a hard cross-runner bound.
func TestBenchGate_RecordHitAllocsFree(t *testing.T) {
	for _, n := range []int{1, 24, maxRuleMetrics} {
		t.Run(fmt.Sprintf("rules=%d", n), func(t *testing.T) {
			rm, names := benchRuleHitStore(n)
			res := testing.Benchmark(func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					rm.RecordHit(names[i%len(names)])
				}
			})
			if got := res.AllocsPerOp(); got != 0 {
				t.Fatalf("RecordHit allocates %d allocs/op on the request path, want 0", got)
			}
		})
	}
}
