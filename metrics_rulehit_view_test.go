package main

// metrics_rulehit_view_test.go — correctness + regression gates for the
// lock-free per-rule hit counter read path (ruleMetrics.view, metrics.go).
//
// ruleMet.RecordHit runs on EVERY proxied request that matched a policy rule
// (applyPolicyDecision, proxy.go), so this file has two jobs.
//
// The COST job is to keep the read path from silently reverting to a
// process-wide lock. TestBenchGate_RecordHitTakesNoLock is STRUCTURAL — it holds
// the write lock and requires a hit on an already-registered rule to complete
// anyway — rather than timing-based, so it cannot flake on a shared runner or
// under -race. That is the lesson recorded on internal/connlimit's shard gate:
// a gate that can flake gets muted. TestBenchGate_UnregisteredRuleStillLocks is
// its control, so a pass cannot mean the lock simply stopped being taken.
//
// The CORRECTNESS job is the view invariant: the mu-guarded maps stay
// authoritative, and every mutator must republish before releasing mu. A missing
// republish is a silent correctness failure — a restored counter that never
// increments, or a rule whose hits never reach /metrics — so it is pinned per
// mutator rather than by one end-to-end assertion.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestRuleMetrics() *ruleMetrics {
	return &ruleMetrics{
		hits:          make(map[string]*int64),
		last:          make(map[string]*int64),
		byID:          make(map[string]persistedRuleCounter),
		loadedByName:  make(map[string]persistedRuleCounter),
		appliedByName: make(map[string]int64),
	}
}

// ruleMetView returns the published view, failing if none exists.
func ruleMetView(t *testing.T, rm *ruleMetrics) map[string]ruleCounter {
	t.Helper()
	v := rm.view.Load()
	if v == nil {
		t.Fatal("no view published")
	}
	return *v
}

// assertViewMatchesAuthoritative is the invariant every mutator must leave true:
// the derived view names exactly the rules the authoritative maps name, and each
// entry points at the SAME counter cells — not copies, which would silently
// split live increments from what /metrics reports.
func assertViewMatchesAuthoritative(t *testing.T, rm *ruleMetrics, mutator string) {
	t.Helper()
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	view := ruleMetView(t, rm)
	if len(view) != len(rm.hits) {
		t.Fatalf("%s: view has %d entries, authoritative hits has %d — mutator did not republish",
			mutator, len(view), len(rm.hits))
	}
	for name, ptr := range rm.hits {
		c, ok := view[name]
		if !ok {
			t.Fatalf("%s: rule %q missing from view — mutator did not republish", mutator, name)
		}
		if c.hits != ptr {
			t.Fatalf("%s: rule %q view hits cell %p != authoritative %p — view holds a stale or copied cell",
				mutator, name, c.hits, ptr)
		}
		if c.last != rm.last[name] {
			t.Fatalf("%s: rule %q view last cell %p != authoritative %p",
				mutator, name, c.last, rm.last[name])
		}
	}
}

// TestRuleMetricsView_EveryMutatorRepublishes walks every mutator of the
// authoritative hits/last maps and requires each to leave the view consistent.
// Adding a mutator without a publishViewLocked call fails here.
func TestRuleMetricsView_EveryMutatorRepublishes(t *testing.T) {
	t.Run("RecordHit_registersNewRule", func(t *testing.T) {
		rm := newTestRuleMetrics()
		rm.RecordHit("alpha")
		assertViewMatchesAuthoritative(t, rm, "RecordHit")
	})

	t.Run("RecordHit_secondDistinctRule", func(t *testing.T) {
		rm := newTestRuleMetrics()
		rm.RecordHit("alpha")
		rm.RecordHit("beta")
		assertViewMatchesAuthoritative(t, rm, "RecordHit(second)")
		if len(ruleMetView(t, rm)) != 2 {
			t.Fatalf("expected 2 rules in view, got %d", len(ruleMetView(t, rm)))
		}
	})

	t.Run("restoreRecords_newNames", func(t *testing.T) {
		rm := newTestRuleMetrics()
		rm.restoreRecords(map[string]persistedRuleCounter{
			"restored-a": {ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Hits: 7, LastHit: 1000},
			"restored-b": {Hits: 3},
		})
		assertViewMatchesAuthoritative(t, rm, "restoreRecords")
	})

	t.Run("restoreRecords_ontoExistingRule", func(t *testing.T) {
		rm := newTestRuleMetrics()
		rm.RecordHit("live")
		rm.restoreRecords(map[string]persistedRuleCounter{"live": {Hits: 42, LastHit: 9999}})
		assertViewMatchesAuthoritative(t, rm, "restoreRecords(existing)")
	})

	// The back-fill case: a bare literal has `hits` but no `last`, so
	// restoreRecordLocked creates the missing last cell. The view must pick it up.
	t.Run("restoreRecords_backfillsMissingLastCell", func(t *testing.T) {
		rm := &ruleMetrics{hits: map[string]*int64{}}
		rm.RecordHit("x") // registers through the locked path
		rm.mu.Lock()
		delete(rm.last, "x") // simulate a literal that never had a last cell
		rm.publishViewLocked()
		rm.mu.Unlock()
		if c := ruleMetView(t, rm)["x"]; c.last != nil {
			t.Fatal("precondition: last cell should be absent")
		}
		rm.restoreRecords(map[string]persistedRuleCounter{"x": {Hits: 5, LastHit: 77}})
		assertViewMatchesAuthoritative(t, rm, "restoreRecords(backfill)")
		if c := ruleMetView(t, rm)["x"]; c.last == nil {
			t.Fatal("REGRESSION: back-filled last cell never reached the view")
		}
	})
}

// TestBenchGate_RecordHitTakesNoLock is the hard cost gate, and it is
// deliberately STRUCTURAL rather than timing-based.
//
// It holds ruleMet's WRITE lock and requires a hit on an already-registered rule
// to complete anyway. If RecordHit reverts to taking rm.mu on the steady-state
// path — exactly the regression to catch — it blocks until the deadline and
// fails deterministically, on any hardware, at any load, with or without -race.
//
// The throughput this protects is recorded on the ruleCounter block comment in
// metrics.go and on BenchmarkRecordHit_Spread_View.
func TestBenchGate_RecordHitTakesNoLock(t *testing.T) {
	rm := newTestRuleMetrics()
	rm.RecordHit("hot") // register it, so this is a pure read
	before := atomic.LoadInt64(rm.hits["hot"])

	rm.mu.Lock()
	defer rm.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		rm.RecordHit("hot")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("REGRESSION: RecordHit on a registered rule blocked while the ruleMetrics write " +
			"lock was held — the per-request read path took a process-wide lock again")
	}
	if got := atomic.LoadInt64(rm.hits["hot"]); got != before+1 {
		t.Fatalf("hit not counted through the view: got %d, want %d", got, before+1)
	}
}

// TestBenchGate_UnregisteredRuleStillLocks is the control for the gate above. It
// proves the gate can actually fail: registering a NEW rule is a write and must
// still serialize on rm.mu. Without this, a build where RecordHit stopped
// touching the lock entirely — and therefore stopped registering rules at all —
// would pass the gate while being far worse than the regression.
func TestBenchGate_UnregisteredRuleStillLocks(t *testing.T) {
	rm := newTestRuleMetrics()

	rm.mu.Lock()
	blocked := make(chan struct{})
	go func() {
		defer close(blocked)
		rm.RecordHit("brand-new")
	}()

	select {
	case <-blocked:
		rm.mu.Unlock()
		t.Fatal("control failed: registering a new rule did not serialize on the write lock, " +
			"so TestBenchGate_RecordHitTakesNoLock proves nothing")
	case <-time.After(100 * time.Millisecond):
	}
	rm.mu.Unlock()

	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("registration never completed after the lock was released")
	}
	if rm.hits["brand-new"] == nil {
		t.Fatal("new rule was not registered")
	}
	assertViewMatchesAuthoritative(t, rm, "RecordHit(control)")
}

// TestRuleMetricsView_AllocFree pins the per-request read path at zero
// allocations. A regression here (e.g. a view rebuilt per call) would put
// garbage on 100% of allowed proxied traffic.
func TestRuleMetricsView_AllocFree(t *testing.T) {
	rm := newTestRuleMetrics()
	rm.RecordHit("hot")
	if n := testing.AllocsPerRun(200, func() { rm.RecordHit("hot") }); n != 0 {
		t.Fatalf("RecordHit allocated %.1f times per call on the steady-state path, want 0", n)
	}
}

// TestRuleMetricsView_BehaviourMatchesPreViewSemantics pins the decisions the
// view path must make identically to the locked path it replaced: the empty name
// is ignored, counts accumulate, lastHit advances monotonically, and the
// cardinality cap still refuses new rules past maxRuleMetrics.
func TestRuleMetricsView_BehaviourMatchesPreViewSemantics(t *testing.T) {
	rm := newTestRuleMetrics()

	rm.RecordHit("")
	if len(rm.hits) != 0 {
		t.Fatal("empty rule name must not register a counter")
	}

	for i := 0; i < 5; i++ {
		rm.RecordHit("counted")
	}
	if got := atomic.LoadInt64(rm.hits["counted"]); got != 5 {
		t.Fatalf("hits = %d, want 5", got)
	}

	// lastHit is monotonic: a stale stamp must never move it backwards.
	lastPtr := rm.last["counted"]
	atomic.StoreInt64(lastPtr, 1<<40)
	rm.RecordHit("counted")
	if got := atomic.LoadInt64(lastPtr); got != 1<<40 {
		t.Fatalf("lastHit moved backwards: got %d, want %d", got, int64(1)<<40)
	}

	// Cardinality cap.
	rm = newTestRuleMetrics()
	for i := 0; i < maxRuleMetrics+25; i++ {
		rm.RecordHit("rule-" + itoaTest(i))
	}
	if len(rm.hits) != maxRuleMetrics {
		t.Fatalf("cap not enforced: %d registered, want %d", len(rm.hits), maxRuleMetrics)
	}
	if len(ruleMetView(t, rm)) != maxRuleMetrics {
		t.Fatalf("view disagrees with cap: %d entries", len(ruleMetView(t, rm)))
	}
}

// TestRuleMetricsView_ConcurrentReadersAndWriters is the race-detector half of
// the "a published map is never mutated in place" contract. Run under -race it
// fails if a mutator ever edits a map a reader can reach.
func TestRuleMetricsView_ConcurrentReadersAndWriters(t *testing.T) {
	rm := newTestRuleMetrics()
	rm.RecordHit("stable")

	var readers, writer sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					rm.RecordHit("stable")
				}
			}
		}()
	}
	// Writers: registration + restore, both of which republish.
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; i < 60; i++ {
			rm.RecordHit("churn-" + itoaTest(i))
			rm.restoreRecords(map[string]persistedRuleCounter{"stable": {Hits: int64(i), LastHit: int64(i)}})
		}
	}()

	writer.Wait() // writer finished; readers still spinning
	close(stop)
	readers.Wait()

	assertViewMatchesAuthoritative(t, rm, "concurrent")
	if atomic.LoadInt64(rm.hits["stable"]) == 0 {
		t.Fatal("concurrent hits were lost entirely")
	}
}

func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
