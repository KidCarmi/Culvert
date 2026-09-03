package main

// metrics_rulehit_view_test.go — correctness gates for the lock-free per-rule
// hit counter (ruleMetrics.view, metrics.go).
//
// ruleMet.RecordHit runs on EVERY proxied request that matched a policy rule
// (applyPolicyDecision, proxy.go), so this file has two jobs.
//
// The CORRECTNESS job is the important one: the derived view is only safe while
// every mutator of the authoritative hits/last maps republishes it before
// releasing rm.mu. A mutator added without that publish is a silent
// TELEMETRY-LOSS bug — hits counted into a cell nothing exports, or a rule that
// stops being counted at all — which no functional test would notice, because
// the request still succeeds. TestRuleMetricsView_EveryMutatorRepublishes pins
// it per mutator, in the same shape as internal/threatfeed's
// TestReadView_EveryMutatorRepublishes and the IP filter's
// TestIPFilterView_EveryMutatorRepublishes.
//
// The DIFFERENTIAL job is TestRuleMetricsRecordHit_MatchesLegacy: the verbatim
// pre-view body is kept here as the oracle, so the claim "this is a cost change,
// not a behaviour change" is checked rather than asserted.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newRuleHitTestMetrics() *ruleMetrics {
	return &ruleMetrics{
		hits:          make(map[string]*int64),
		last:          make(map[string]*int64),
		byID:          make(map[string]persistedRuleCounter),
		loadedByName:  make(map[string]persistedRuleCounter),
		appliedByName: make(map[string]int64),
	}
}

// assertRuleHitViewMatchesMaps is the invariant every mutator must leave true:
// the published view names exactly the entries the authoritative maps hold, and
// ALIASES their cells rather than copying them.
func assertRuleHitViewMatchesMaps(t *testing.T, rm *ruleMetrics, mutator string) {
	t.Helper()
	v := rm.view.Load()
	if v == nil {
		t.Fatalf("%s: no view published — RecordHit would take the lock on every request", mutator)
	}
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if len(v.cells) != len(rm.hits) {
		t.Fatalf("%s: view has %d cells, maps have %d entries", mutator, len(v.cells), len(rm.hits))
	}
	for name, ptr := range rm.hits {
		c, ok := v.cells[name]
		if !ok {
			t.Fatalf("%s: view is missing %q — its hits would be counted nowhere", mutator, name)
		}
		// Pointer identity, not value equality: a copied cell would diverge the
		// moment either side is incremented.
		if c.hits != ptr {
			t.Fatalf("%s: view cell for %q is not the map's live counter", mutator, name)
		}
		if c.last != rm.last[name] {
			t.Fatalf("%s: view last-cell for %q is not the map's live cell", mutator, name)
		}
	}
	if want := len(rm.hits) >= maxRuleMetrics; v.sealed != want {
		t.Fatalf("%s: view sealed=%v, want %v at %d entries", mutator, v.sealed, want, len(rm.hits))
	}
}

// TestRuleMetricsView_EveryMutatorRepublishes walks every production path that
// mutates hits/last and requires each to leave a consistent published view.
//
// Adding a mutator means adding a case here. If you are reading this because
// the test failed on a path you just wrote: call rm.publishViewLocked() before
// releasing rm.mu.
func TestRuleMetricsView_EveryMutatorRepublishes(t *testing.T) {
	for _, tc := range []struct {
		mutator string
		run     func(rm *ruleMetrics)
	}{
		{"RecordHit/firstSighting", func(rm *ruleMetrics) { rm.RecordHit("alpha") }},
		{"RecordHit/secondName", func(rm *ruleMetrics) { rm.RecordHit("alpha"); rm.RecordHit("beta") }},
		{"restoreRecords", func(rm *ruleMetrics) {
			rm.restoreRecords(map[string]persistedRuleCounter{
				"gamma": {ID: "11111111-1111-4111-8111-111111111111", Hits: 9, LastHit: 1234},
			})
		}},
		{"restoreRecords/overExisting", func(rm *ruleMetrics) {
			rm.RecordHit("delta")
			rm.restoreRecords(map[string]persistedRuleCounter{
				"delta": {ID: "22222222-2222-4222-8222-222222222222", Hits: 40, LastHit: 99},
			})
		}},
		{"restoreRecords/lastCellReplaced", func(rm *ruleMetrics) {
			// The one path that REPLACES a live last-cell pointer rather than
			// inserting: hits exists, last does not.
			rm.RecordHit("eps")
			rm.mu.Lock()
			delete(rm.last, "eps")
			rm.mu.Unlock()
			rm.restoreRecords(map[string]persistedRuleCounter{"eps": {Hits: 3, LastHit: 77}})
		}},
	} {
		t.Run(tc.mutator, func(t *testing.T) {
			rm := newRuleHitTestMetrics()
			tc.run(rm)
			assertRuleHitViewMatchesMaps(t, rm, tc.mutator)
		})
	}
}

// recordHitLegacy is the VERBATIM pre-view body, kept as the differential
// oracle. Do not "modernise" it — its value is that it is the old code.
func recordHitLegacy(rm *ruleMetrics, ruleName string, now int64) {
	if ruleName == "" {
		return
	}
	rm.mu.RLock()
	ctr, ok := rm.hits[ruleName]
	lastPtr := rm.last[ruleName]
	rm.mu.RUnlock()
	if ok {
		atomic.AddInt64(ctr, 1)
		if lastPtr != nil {
			atomicStoreMax(lastPtr, now)
		}
		return
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.last == nil {
		rm.last = make(map[string]*int64)
	}
	if ctr, ok = rm.hits[ruleName]; ok {
		atomic.AddInt64(ctr, 1)
		if lp := rm.last[ruleName]; lp != nil {
			atomicStoreMax(lp, now)
		}
		return
	}
	if len(rm.hits) >= maxRuleMetrics {
		return
	}
	v := int64(1)
	rm.hits[ruleName] = &v
	lv := now
	rm.last[ruleName] = &lv
	rm.order = append(rm.order, ruleName)
}

// TestRuleMetricsRecordHit_MatchesLegacy runs the new body and the frozen old
// body over the same call sequence and requires identical observable state:
// counts, last-hit stamps, insertion order, and the cardinality cap.
func TestRuleMetricsRecordHit_MatchesLegacy(t *testing.T) {
	// A sequence that exercises first sightings, repeats, the empty-name
	// guard, and — past maxRuleMetrics — the cap.
	seq := []string{"", "a", "b", "a", "c", "b", "a", ""}
	for i := 0; i < maxRuleMetrics+40; i++ {
		seq = append(seq, fmt.Sprintf("rule-%03d", i), fmt.Sprintf("rule-%03d", i))
	}

	got, want := newRuleHitTestMetrics(), newRuleHitTestMetrics()
	for _, name := range seq {
		got.RecordHit(name)
		recordHitLegacy(want, name, time.Now().Unix())
	}

	if len(got.hits) != len(want.hits) {
		t.Fatalf("tracked names: got %d, want %d", len(got.hits), len(want.hits))
	}
	if len(got.hits) != maxRuleMetrics {
		t.Fatalf("precondition: sequence must reach the cap; got %d names", len(got.hits))
	}
	for name, wantPtr := range want.hits {
		gotPtr, ok := got.hits[name]
		if !ok {
			t.Fatalf("%q tracked by legacy body but not by the new one", name)
		}
		if *gotPtr != *wantPtr {
			t.Errorf("%q: hits got %d, want %d", name, *gotPtr, *wantPtr)
		}
		if (got.last[name] == nil) != (want.last[name] == nil) {
			t.Errorf("%q: last-cell presence diverged", name)
		}
	}
	if len(got.order) != len(want.order) {
		t.Fatalf("order length: got %d, want %d", len(got.order), len(want.order))
	}
	for i := range want.order {
		if got.order[i] != want.order[i] {
			t.Fatalf("order[%d]: got %q, want %q", i, got.order[i], want.order[i])
		}
	}
}

// TestRuleMetricsRecordHit_StampsLastHit pins the one ordering detail the split
// changed: the clock is now read AFTER the cell is resolved rather than before
// the lock. The stamp must still land, and must still only move forward.
func TestRuleMetricsRecordHit_StampsLastHit(t *testing.T) {
	rm := newRuleHitTestMetrics()
	before := time.Now().Unix()
	rm.RecordHit("stamped") // first sighting: slow path
	rm.RecordHit("stamped") // steady state: fast path
	after := time.Now().Unix()

	lp := rm.last["stamped"]
	if lp == nil {
		t.Fatal("no last-hit cell created")
	}
	if v := atomic.LoadInt64(lp); v < before || v > after {
		t.Fatalf("last-hit %d outside [%d,%d]", v, before, after)
	}
	// atomicStoreMax must not let a later, smaller stamp win.
	atomicStoreMax(lp, 1)
	if v := atomic.LoadInt64(lp); v < before {
		t.Fatalf("last-hit regressed to %d", v)
	}
	if *rm.hits["stamped"] != 2 {
		t.Fatalf("hits = %d, want 2", *rm.hits["stamped"])
	}
}

// TestRuleMetricsRecordHit_NoLostHitsUnderConcurrency is the counting proof.
// Run with -race it also enforces the "never mutate a published map in place"
// half of the contract.
func TestRuleMetricsRecordHit_NoLostHitsUnderConcurrency(t *testing.T) {
	rm := newRuleHitTestMetrics()
	const (
		workers = 8
		perW    = 2000
		names   = 16
	)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perW; i++ {
				rm.RecordHit(fmt.Sprintf("rule-%02d", (w+i)%names))
			}
		}(w)
	}
	wg.Wait()

	var total int64
	for _, ptr := range rm.hits {
		total += atomic.LoadInt64(ptr)
	}
	if want := int64(workers * perW); total != want {
		t.Fatalf("total hits = %d, want %d (hits were lost or double-counted)", total, want)
	}
	assertRuleHitViewMatchesMaps(t, rm, "concurrent RecordHit")
}

// TestRuleMetricsView_StaleViewStillCountsIntoLiveCells pins why the view
// aliases cells instead of copying them: a reader that resolved an older view
// must increment the very same counter the current view names, so a publish
// racing a hit can never lose it.
func TestRuleMetricsView_StaleViewStillCountsIntoLiveCells(t *testing.T) {
	rm := newRuleHitTestMetrics()
	rm.RecordHit("shared")
	stale := rm.view.Load()

	rm.RecordHit("other") // republishes; "shared" keeps its cell
	fresh := rm.view.Load()
	if stale == fresh {
		t.Fatal("precondition: adding a name must publish a new view")
	}

	atomic.AddInt64(stale.cells["shared"].hits, 1) // a reader on the old view
	if got := atomic.LoadInt64(fresh.cells["shared"].hits); got != 2 {
		t.Fatalf("hit through the stale view did not land in the live cell: got %d, want 2", got)
	}
}

// TestRuleMetricsRecordHit_SealedViewIgnoresNewNames pins the cap behaviour the
// sealed flag short-circuits: past maxRuleMetrics a new name is ignored, which
// is exactly what the pre-view body did — it just paid an exclusive lock to
// decide it.
func TestRuleMetricsRecordHit_SealedViewIgnoresNewNames(t *testing.T) {
	rm := newRuleHitTestMetrics()
	for i := 0; i < maxRuleMetrics; i++ {
		rm.RecordHit(fmt.Sprintf("rule-%03d", i))
	}
	if v := rm.view.Load(); v == nil || !v.sealed {
		t.Fatal("view must be sealed once the cap is reached")
	}
	rm.RecordHit("one-too-many")
	if _, ok := rm.hits["one-too-many"]; ok {
		t.Fatal("over-cap rule name was admitted")
	}
	if len(rm.hits) != maxRuleMetrics {
		t.Fatalf("tracked names = %d, want %d", len(rm.hits), maxRuleMetrics)
	}
	// A name already tracked must still be counted after sealing.
	rm.RecordHit("rule-000")
	if got := atomic.LoadInt64(rm.hits["rule-000"]); got != 2 {
		t.Fatalf("tracked rule stopped counting after the cap: got %d, want 2", got)
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────
//
// BenchmarkRuleRecordHit_Legacy keeps the pre-view body measurable in-tree on
// the identical store and inputs, so the before/after comparison is
// reproducible from one run instead of requiring a checkout of the parent
// commit (the internal/blocklist convention).
//
//	go test -run '^$' -bench 'BenchmarkRuleRecordHit' -cpu=1,2,4 .

// benchRuleHitStore returns a store already carrying count rule names, each
// with its steady-state counter cell established, plus those names.
func benchRuleHitStore(count int) (rm *ruleMetrics, ruleNames []string) {
	rm = newRuleHitTestMetrics()
	ruleNames = make([]string, 0, count)
	for i := 0; i < count; i++ {
		n := fmt.Sprintf("corp-egress-rule-%02d", i)
		ruleNames = append(ruleNames, n)
		rm.RecordHit(n) // establish the steady-state cell
	}
	return rm, ruleNames
}

// NOTE ON FAIRNESS: the legacy body takes `now` as a parameter because the
// pre-view code read the clock before the lock. It must therefore be called
// with a FRESH time.Now().Unix() per iteration — hoisting that read out of the
// loop measures a body production never ran and silently flatters the new
// path by ~25 ns/op. (Written that way first; the 1-core numbers inverted,
// which is what exposed it.)

func BenchmarkRuleRecordHit_Serial(b *testing.B) {
	rm, names := benchRuleHitStore(24)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm.RecordHit(names[i%len(names)])
	}
}

func BenchmarkRuleRecordHit_LegacySerial(b *testing.B) {
	rm, names := benchRuleHitStore(24)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recordHitLegacy(rm, names[i%len(names)], time.Now().Unix())
	}
}

func BenchmarkRuleRecordHit_Parallel(b *testing.B) {
	rm, names := benchRuleHitStore(24)
	b.ReportAllocs()
	var ctr int64
	b.RunParallel(func(pb *testing.PB) {
		i := int(atomic.AddInt64(&ctr, 1))
		for pb.Next() {
			rm.RecordHit(names[i%len(names)])
		}
	})
}

func BenchmarkRuleRecordHit_LegacyParallel(b *testing.B) {
	rm, names := benchRuleHitStore(24)
	b.ReportAllocs()
	var ctr int64
	b.RunParallel(func(pb *testing.PB) {
		i := int(atomic.AddInt64(&ctr, 1))
		for pb.Next() {
			recordHitLegacy(rm, names[i%len(names)], time.Now().Unix())
		}
	})
}
