package main

// store_stats_bench_test.go — benchmarks + deterministic regression gate for
// the per-request stats accounting hot path (recordStats). Every proxied
// request — HTTP, CONNECT, WebSocket, SOCKS5 — runs tsRecordResult, and every
// allowed request additionally runs topHosts.Record, so both are global
// serialization points on 100% of traffic. The benchmarks measure the
// steady-state cases those requests actually hit: an already-tracked host and
// a same-minute bucket increment. The parallel variants expose lock
// contention, the way BenchmarkAddParallel does for the reqlog ring.
//
// Measured outcome (4-core, 2026-07): converting topHosts.Record to
// RLock+atomic cut the parallel tracked-host path 363→124 ns/op (2.9x) —
// counters for different hosts live on different cache lines, so atomic adds
// parallelize. The same conversion for tsRecordResult measured FLAT (~154
// ns/op both ways), and was read at the time as "every request bumps the SAME
// current-minute bucket, so the shared cache line, not the mutex, is the
// bound".
//
// That reading was half right and it is why these benchmarks must be run
// ACROSS CORE COUNTS, not at one. RWMutex cannot help a path that mutates, so
// the flat result said nothing about the bound; and the shared cache line is
// only inherent while the counter stays shared. Sharding the current minute
// (2026-09, store.go) took tsRecordResult from 172.6 → 36.1 ns/op at
// GOMAXPROCS=4 and the full recordStats fan-out from 275.8 → 131.2 ns/op, with
// one core coming out ahead too. The ceiling, not the constant, is the thing
// these benchmarks exist to expose:
//
//	                        │ -cpu=1 │ -cpu=4 │
//	tsRecordResult   before │  87.4  │ 172.6  │  cores SUBTRACTED throughput
//	tsRecordResult    after │  78.6  │  36.1  │
//	recordStats      before │ 142.9  │ 275.8  │
//	recordStats       after │ 130.0  │ 131.2  │
//
// Those recordStats rows are TIGHT-LOOP figures and are kept only because the
// tsRecordResult rows beside them are the component measurement. For the
// fan-out as a whole, read the marginal-cost table further down instead — the
// methodology note explains why the tight-loop total is the wrong number.
//
// Follow-up (4-core, 2026-09): that 2.9x was real but measured only against
// the plain mutex at ONE concurrency, and the RLock version turned out not to
// SCALE — RLock/RUnlock are two atomic read-modify-writes on one shared word,
// so the tracked-host path still serialised the whole process on a single
// cache line. Isolated runs, n=7, medians:
//
//	GOMAXPROCS      │    1    │    2    │    4    │ 1→4 throughput
//	RLock+atomic    │ 35.8 ns │ 92.6 ns │ 96.8 ns │ 0.37x (cores SUBTRACTED it)
//	sync.Map        │ 42.0 ns │ 26.1 ns │ 16.1 ns │ 2.6x
//
// The tsRecordResult half was re-tested in that same pass and the 2026-07
// conclusion was recorded as HOLDING. It did not: the sharded shape is what
// this file's table above measures and what store.go now ships. The two
// findings were developed in parallel and met at a merge, so read the table
// above and the timeSeries doc comment in store.go as the current record for
// tsRecordResult, and this section as the current record for topHosts.
//
// Under the marginal-cost method below — the one this file argues for — the
// two changes COMPOSE, and that pairing is the number a gateway actually pays.
// BenchmarkRequestCycle, isolated processes, n=5, medians, ns of stats fan-out
// per request (WithStats minus WithoutStats):
//
//	                          │ -cpu=1 │ -cpu=4 │
//	sharded topHosts only     │  129   │  490   │  cores made it WORSE
//	+ sharded tsRecordResult  │  111   │   87   │
//
// Sharding topHosts alone left the fan-out's marginal cost rising 3.8x from
// one core to four — the ceiling simply moved to the other component. With
// both sharded it FALLS with core count, 5.6x cheaper at four cores. The
// contended arm's bimodality warned about below is visible in exactly the
// arm that still has a contended component: main's 4-core WithStats spread
// 755-784 ns across five runs, this branch's 364-371.
//
// A METHODOLOGY NOTE, because it changed the conclusion twice. A tight
// recordStats loop is not the production duty cycle: with every core
// re-entering the fan-out immediately, speeding up one component only raises
// the arrival rate at the next contended one, and the measured TOTAL got ~8%
// worse even though the component got 6x faster. BenchmarkRequestCycle_* below
// exists for that reason — it separates the fan-out with ~1 us of unrelated
// work and reports the marginal cost, which is the number a gateway actually
// pays. Measure this path with those, and always in an isolated process: the
// contended arm is bimodal (its 4-core marginal cost landed at 160 ns in one
// round and 445 ns in the next), so a single run of the two arms in one binary
// can show any result you like.
//
// Run locally:
//   go test -run '^$' -bench 'BenchmarkTopHosts|BenchmarkTSRecord|BenchmarkRecordStats' -benchmem -cpu=1,2,4 .
//   go test -run '^$' -bench 'BenchmarkTopHosts|BenchmarkTSRecord|BenchmarkRecordStats' -benchmem .
//   go test -run '^$' -bench BenchmarkTopHostsRecord_HitParallel -cpu=1,2,4 -count=7 .
//   go test -run '^$' -bench BenchmarkRequestCycle -cpu=1,2,4 -count=5 .

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// benchHostCounter returns a counter pre-filled with n tracked hosts, so
// Record measures the steady-state already-tracked path — the case ~all
// production traffic hits (the distinct-host working set repeats heavily).
func benchHostCounter(n int) *hostCounter {
	hc := freshHostCounter()
	for _, h := range benchHostNames(n) {
		hc.Record(h)
	}
	return hc
}

// benchHostNames precomputes the working-set hostnames so the timed loops
// index a slice instead of calling fmt.Sprintf per iteration (which would
// fold formatting + allocator contention into the measurement).
func benchHostNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("host-%d.example.com", i)
	}
	return names
}

// BenchmarkTopHostsRecord_Hit measures the serial cost of counting one
// request against an already-tracked host.
func BenchmarkTopHostsRecord_Hit(b *testing.B) {
	hc := benchHostCounter(512)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hc.Record("host-7.example.com")
	}
}

// BenchmarkTopHostsRecord_HitParallel measures the tracked-host path under
// concurrent request goroutines — the production shape: many in-flight
// requests, a hot working set of repeated hosts.
func BenchmarkTopHostsRecord_HitParallel(b *testing.B) {
	hc := benchHostCounter(512)
	hosts := benchHostNames(512)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hc.Record(hosts[i%512])
			i++
		}
	})
}

// BenchmarkTSRecordResult measures the serial cost of the per-request
// time-series bucket increment (same-minute steady state).
func BenchmarkTSRecordResult(b *testing.B) {
	tsRecordResult(true) // arm lastMin so the loop measures the same-minute path
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tsRecordResult(i%8 != 0)
	}
}

// BenchmarkTSRecordResultParallel measures the bucket increment under
// concurrent request goroutines.
func BenchmarkTSRecordResultParallel(b *testing.B) {
	tsRecordResult(true)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tsRecordResult(true)
		}
	})
}

// BenchmarkRecordStatsAllowedParallel measures the full per-request stats
// fan-out for the dominant traffic class (an allowed request): statTotal,
// the time-series bucket, and the top-hosts counter, under concurrency.
// Uses the package globals — exactly what handleRequest exercises.
func BenchmarkRecordStatsAllowedParallel(b *testing.B) {
	hosts := benchHostNames(512)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			recordStats("203.0.113.7", hosts[i%512], "OK", "allow-rule", "Allow")
			i++
		}
	})
}

// TestStatsHotPath_ZeroAllocSteadyState is the deterministic regression gate
// for the stats hot path (mirrors reqlog's TestAdd_ZeroAllocSteadyState):
// counting a request against an already-tracked host and bumping the
// same-minute time-series bucket must not allocate. Allocation counts are
// hardware-independent, so this fails on any runner if a per-request
// allocation sneaks into recordStats' accounting.
func TestStatsHotPath_ZeroAllocSteadyState(t *testing.T) {
	hc := freshHostCounter()
	hc.Record("hot.example.com")
	if allocs := testing.AllocsPerRun(1000, func() { hc.Record("hot.example.com") }); allocs != 0 {
		t.Errorf("REGRESSION: topHosts.Record allocates %.1f/op on the tracked-host path, want 0", allocs)
	}

	tsRecordResult(true) // arm lastMin
	if allocs := testing.AllocsPerRun(1000, func() { tsRecordResult(true) }); allocs != 0 {
		t.Errorf("REGRESSION: tsRecordResult allocates %.1f/op on the same-minute path, want 0", allocs)
	}
}

// BenchmarkTopHostsRecord_SaturatedMissParallel measures the path a
// high-cardinality flood drives once the counter is at capacity: every host is
// new, so every call misses and falls through to the serialised insert branch.
// The lock-free fast path must not have made this case worse — it is the shape
// an attacker controls.
func BenchmarkTopHostsRecord_SaturatedMissParallel(b *testing.B) {
	prev := topHostsMaxEntries
	topHostsMaxEntries = 512
	b.Cleanup(func() { topHostsMaxEntries = prev })

	hc := benchHostCounter(512)
	miss := benchHostNames(4096)
	for i := range miss {
		miss[i] = "miss-" + miss[i]
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hc.Record(miss[i%len(miss)])
			i++
		}
	})
}

// TestBenchGate_TopHostsRecordTakesNoLock is the STRUCTURAL regression gate for
// the tracked-host fast path: it holds hc.mu — the lock the insert, decay and
// Top paths take — and requires Record to count an already-tracked host anyway.
//
// Structural, not timing-based, and deliberately so: a scaling-ratio gate over
// this path narrows under -race on a shared CI runner, and the repo's own
// history (internal/connlimit, internal/threatfeed, the IP filter) is that a
// gate which can flake gets muted. This one fails deterministically on any
// hardware, at any load, with or without -race, the moment someone reintroduces
// a lock acquisition on the per-request path.
func TestBenchGate_TopHostsRecordTakesNoLock(t *testing.T) {
	hc := freshHostCounter()
	hc.Record("hot.example.com")

	hc.mu.Lock()
	defer hc.mu.Unlock()

	done := make(chan struct{})
	go func() {
		hc.Record("hot.example.com")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("REGRESSION: Record blocked on hc.mu for an already-tracked host — " +
			"the per-request path must not acquire a process-wide lock")
	}
	if c, ok := hc.count("hot.example.com"); !ok || c != 2 {
		t.Fatalf("tracked host count = %d (tracked=%v), want 2", c, ok)
	}
}

// TestBenchGate_TopHostsNewHostStillSerialises is the CONTROL for the gate
// above. Without it, a passing gate could mean the lock simply stopped being
// taken anywhere — including by the insert path, which MUST stay serialised to
// keep the cap and the decay pass sound. A brand-new host must still block.
func TestBenchGate_TopHostsNewHostStillSerialises(t *testing.T) {
	hc := freshHostCounter()
	hc.Record("hot.example.com")

	hc.mu.Lock()
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		hc.Record("brand-new.example.com")
		close(done)
	}()
	<-started

	select {
	case <-done:
		hc.mu.Unlock()
		t.Fatal("CONTROL FAILED: inserting a NEW host completed while hc.mu was held — " +
			"the insert path must stay serialised, or the cap and decay pass are unsound")
	case <-time.After(200 * time.Millisecond):
	}
	hc.mu.Unlock()
	<-done

	if _, ok := hc.count("brand-new.example.com"); !ok {
		t.Fatal("new host was not inserted once the lock was released")
	}
}

// TestTopHosts_ConcurrentRecordDecayAndTop is the concurrency contract for the
// lock-free reader: hot-host increments, high-cardinality inserts that force
// decay passes, and Top snapshots all run at once. Under -race this proves the
// sync.Map/atomic pairing is sound; the assertions prove the bounded-memory and
// heavy-hitter guarantees survive the concurrency, not just the serial path.
func TestTopHosts_ConcurrentRecordDecayAndTop(t *testing.T) {
	withTopHostsCap(t, 128)
	hc := freshHostCounter()

	// The flood is the clock: the heavy hitters must be reinforced for as long
	// as it runs, exactly as the serial TestTopHosts_HeavyHittersSurviveFlood
	// interleaves them. A hot host that STOPS being requested is supposed to age
	// out — that is the decay pass working — so a test whose hot workers finish
	// early would be asserting the opposite of the documented contract.
	flood := make(chan struct{})
	var wg sync.WaitGroup

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-flood:
					return
				default:
				}
				hc.Record("hot-a.example")
				hc.Record("hot-b.example")
			}
		}()
	}
	// Concurrent readers, for the same duration.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-flood:
				return
			default:
			}
			hc.Top(10)
		}
	}()
	// A high-cardinality flood, which drives inserts and decay passes. It is
	// PACED by the heavy hitters: every reinforcementChunk inserts it waits for
	// them to be incremented again, so the flood stays INTERLEAVED with the hot
	// workers instead of racing them — which is what the comment above already
	// says this test means by "the flood is the clock".
	//
	// Without the pacing this test was FLAKY under CPU contention (chaos register
	// row ST-9, found by the CHAOS-67 sweep's determinism gate). The flood
	// goroutine could complete all 20 000 inserts — ~156 decay passes at this cap
	// — while the scheduler starved the four hot workers, so hot-a/hot-b were
	// halved to 1 and lost an arbitrary tie to a count-1 junk entry. Measured
	// before this fix, with six spinning CPU hogs: 3 failures in 30 runs, and one
	// observed Top(2) was {hot-b Count:4} plus a junk host — i.e. the heavy
	// hitters were not actually heavy. That is the TEST's premise failing, not the
	// engine's contract, which is why the fix restores the interleaving rather
	// than loosening the assertion: a tie-tolerant assertion would have passed
	// while the engine's heavy-hitter guarantee went unchecked.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(flood)
		for i := 0; i < 20000; i++ {
			hc.Record(fmt.Sprintf("junk-%d.example", i))
			if i%reinforcementChunk == reinforcementChunk-1 &&
				!awaitReinforcement(t, hc, "hot-a.example", "hot-b.example") {
				// The hot workers stopped. Abandon the flood immediately rather
				// than spending the bounded wait on every remaining chunk: with
				// 20 000 inserts that would be ~78 x 10 s before the test
				// reported. The assertion below then fails on what it saw.
				return
			}
		}
	}()
	wg.Wait()

	if n := hc.size(); n > topHostsMaxEntries {
		t.Fatalf("live entries = %d, want <= cap %d (bounded-memory contract)", n, topHostsMaxEntries)
	}
	top := hc.Top(2)
	if len(top) < 2 {
		t.Fatalf("Top(2) returned %d entries", len(top))
	}
	got := map[string]bool{top[0].Host: true, top[1].Host: true}
	if !got["hot-a.example"] || !got["hot-b.example"] {
		t.Fatalf("heavy hitters lost under concurrency; Top(2) = %+v", top)
	}
}

// reinforcementChunk is how many junk inserts the flood may run before it waits
// for the heavy hitters to be reinforced again. Small enough that the hot hosts
// are re-incremented between decay passes (which fire about once per cap-many
// new-host drops), large enough that the pacing costs a few dozen waits rather
// than one per insert.
const reinforcementChunk = 256

// awaitReinforcement blocks until every named host's count has increased since
// the call began, so the caller can guarantee interleaving instead of hoping the
// scheduler provides it. It reports false when it gave up.
//
// The wait is BOUNDED: a hot worker that is genuinely not running must fail the
// test rather than hang it, and it reports through t.Errorf (safe from a
// non-test goroutine, unlike t.Fatalf) so the run still completes and the
// enclosing assertion reports what it saw. Returning false lets the caller stop
// paying the bound on every subsequent chunk — verified while building this fix:
// a control that killed the hot workers took the test past 120 s before the
// early return was added, because ~78 chunks each waited the full 10 s.
func awaitReinforcement(t *testing.T, hc *hostCounter, hosts ...string) bool {
	t.Helper()
	before := make([]int64, len(hosts))
	for i, h := range hosts {
		before[i], _ = hc.count(h) // absent reads 0, which the > test below handles
	}
	deadline := time.Now().Add(10 * time.Second)
	for i, h := range hosts {
		for {
			if now, ok := hc.count(h); ok && now > before[i] {
				break
			}
			if time.Now().After(deadline) {
				t.Errorf("hot host %q was not reinforced within 10s — the hot workers are not running, "+
					"so this test can no longer establish the heavy-hitter contract", h)
				return false
			}
			runtime.Gosched()
		}
	}
	return true
}

// TestTopHosts_TrackedCountsAreNotLost pins the accounting guarantee the
// lock-free path must keep in the UNSATURATED regime — the one ~all production
// deployments run in. Below the cap no decay pass runs, so nothing evicts a
// counter and every single increment must be retained exactly.
func TestTopHosts_TrackedCountsAreNotLost(t *testing.T) {
	withTopHostsCap(t, 10000)
	hc := freshHostCounter()
	hc.Record("hot.example")

	const workers, perWorker = 8, 5000
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				hc.Record("hot.example")
			}
		}()
	}
	wg.Wait()

	want := int64(workers*perWorker) + 1
	if c, _ := hc.count("hot.example"); c != want {
		t.Fatalf("count = %d, want exactly %d — no increment may be lost below the cap", c, want)
	}
}

// benchSimulatedRequestWork stands in for the work a real proxied request does
// between two recordStats calls — TLS, policy evaluation, upstream I/O. It
// touches only goroutine-local state, so it adds no contention of its own.
//
// It exists because a tight recordStats loop is NOT the production duty cycle,
// and the difference changes conclusions. In a tight loop every core re-enters
// the stats fan-out immediately, so speeding up ONE component just raises the
// arrival rate at the next contended one and the measured total can get worse.
// Real traffic pays the fan-out once per request, separated by microseconds of
// unrelated work. Measuring the MARGINAL cost (with-stats minus without-stats)
// at that duty cycle is what says whether a change helps a real gateway.
//
//go:noinline
func benchSimulatedRequestWork(seed uint64) uint64 {
	// ~1 us of pure ALU work on a goroutine-local value.
	x := seed
	for i := 0; i < 600; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
	}
	return x
}

var benchSink uint64

// BenchmarkRequestCycle_WithoutStats is the control arm: the simulated request
// work alone. Subtract it from the arm below to get the marginal stats cost.
func BenchmarkRequestCycle_WithoutStats(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		x := uint64(1)
		for pb.Next() {
			x = benchSimulatedRequestWork(x)
		}
		atomic.StoreUint64(&benchSink, x)
	})
}

// BenchmarkRequestCycle_WithStats is the measurement arm: the same work plus
// the per-request stats fan-out, at a realistic ratio of the two.
func BenchmarkRequestCycle_WithStats(b *testing.B) {
	hosts := benchHostNames(512)
	b.RunParallel(func(pb *testing.PB) {
		x := uint64(1)
		i := 0
		for pb.Next() {
			x = benchSimulatedRequestWork(x)
			recordStats("203.0.113.7", hosts[i%512], "OK", "allow-rule", "Allow")
			i++
		}
		atomic.StoreUint64(&benchSink, x)
	})
}
