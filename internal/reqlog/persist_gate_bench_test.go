package reqlog

// Per-request cost of the request-log persistence GATE (Performance Guardian).
//
// Add runs once per logged request, on the proxy request goroutine, and hands
// the entry to three sinks. The second of them — the JSONL drain queue — used
// to open with an unconditional persistMu.Lock(), purely to read two pointers
// that are nil for the entire life of the process in the default
// configuration (Init("") starts no drain goroutine). That is two atomic
// read-modify-writes on one process-wide word per request: a throughput
// ceiling, not a constant cost.
//
// The arms below measure BOTH shapes in ONE run so the comparison stays
// reproducible in-tree on any runner rather than living in a commit message —
// the convention BenchmarkFeedCheckRequestURL_MissLegacy already follows. The
// _LegacyGate arms are the baseline, never the thing under test.
//
//	go test -run '^$' -bench 'Gate|BenchmarkAdd' -benchmem -count=5 -cpu 1,2,4 ./internal/reqlog/

import (
	"testing"
	"time"
)

// gateSink keeps the ratio gate's two arms symmetric — see its comment. It is
// written ONLY from serial code (the ratio gate and the serial benchmarks).
// The parallel arms deliberately consume their value through a branch instead:
// writing one shared bool from every RunParallel worker is a data race that
// `go test -race -bench . ./internal/reqlog` reports, and it would have put a
// contended store inside the loop whose cost is the thing being measured. The
// branch form is also what the sibling arms in
// internal/threatfeed/checkrequesturl_bench_test.go use, and it asserts what
// the sink could not: that these benchmarks really did measure the DISABLED
// gate, rather than silently timing the enabled path.
var gateSink bool

// raceDetectorOn is set true by the //go:build race companion file
// (race_on_test.go).
var raceDetectorOn = false

// legacyEnqueueGate freezes the PRE-CHANGE shape of enqueue's disabled path:
// take the process-wide mutex, read the two pointers, discover persistence is
// off, return. Nothing else about enqueue is reproduced, because nothing else
// about it changed.
func legacyEnqueueGate() bool {
	persistMu.Lock()
	ch := persistCh
	persistMu.Unlock()
	return ch != nil
}

// disableGateForBench puts the package in the configuration the benchmarks
// measure: empty ring, persistence off, no history hook.
func disableGateForBench(b *testing.B) {
	b.Helper()
	restoreRing := SwapRingForTest()
	b.Cleanup(restoreRing)
	restoreW := SwapPersistenceForTest()
	b.Cleanup(restoreW)
	old := history
	history = nil
	b.Cleanup(func() { history = old })
	fillRing(b)
}

// BenchmarkPersistGate_LegacyGate and its sibling isolate the gate itself, so
// the saving is readable without ringMu's copy cost on top of it.
func BenchmarkPersistGate_LegacyGate(b *testing.B) {
	disableGateForBench(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gateSink = legacyEnqueueGate()
	}
}

func BenchmarkPersistGate(b *testing.B) {
	disableGateForBench(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gateSink = persistRunning.Load()
	}
}

// BenchmarkPersistGate_LegacyGateParallel and its sibling are the scaling
// halves, and they are the point of the change: the legacy arm's cost RISES
// with core count because every core writes the same word, while the atomic
// load is a read of a shared cache line that every core can hold at once.
func BenchmarkPersistGate_LegacyGateParallel(b *testing.B) {
	disableGateForBench(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if legacyEnqueueGate() {
				b.Fatal("persistence is running: this arm must measure the disabled gate")
			}
		}
	})
}

// BenchmarkPersistGateParallel is the shipped shape's scaling half.
func BenchmarkPersistGateParallel(b *testing.B) {
	disableGateForBench(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if persistRunning.Load() {
				b.Fatal("persistence is running: this arm must measure the disabled gate")
			}
		}
	})
}

// BenchmarkAddLegacyGateParallel is the whole-Add baseline: the ring write
// (unchanged, and still the remaining four-core ceiling) plus the legacy
// mutex gate. Read it against BenchmarkAddParallel, which is the shipped
// shape, to see what fraction of one logged request the gate was.
func BenchmarkAddLegacyGateParallel(b *testing.B) {
	disableGateForBench(b)
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if addWithLegacyGate(e) {
				b.Fatal("persistence is running: this arm must measure the disabled gate")
			}
		}
	})
}

// BenchmarkAddLegacyGate is the serial baseline for BenchmarkAdd.
func BenchmarkAddLegacyGate(b *testing.B) {
	disableGateForBench(b)
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gateSink = addWithLegacyGate(e)
	}
}

// addWithLegacyGate mirrors Add with the pre-change gate in place. It
// deliberately duplicates Add's ring write instead of calling Add: calling Add
// would measure the shipped gate AND the legacy one.
// It returns the legacy gate's verdict rather than writing gateSink, so the
// parallel arm above can consume it without a shared store — see gateSink.
func addWithLegacyGate(e Entry) bool {
	ringMu.Lock()
	if ringBuf == nil {
		ringBuf = make([]Entry, MaxRing)
	}
	ringBuf[ringHead] = e
	ringHead = (ringHead + 1) % MaxRing
	if ringLen < MaxRing {
		ringLen++
	}
	ringMu.Unlock()
	gate := legacyEnqueueGate()
	if h := history; h != nil {
		h(e)
	}
	return gate
}

// ── Regression gates ─────────────────────────────────────────────────────────

// TestGate_DisabledAddNeverTakesPersistMu is the DETERMINISTIC half, and it is
// structural rather than timed: it holds persistMu for the duration of an Add
// with persistence disabled. Pre-change that Add blocked until the test
// released the mutex; post-change it must complete regardless. Allocation
// counts cannot express this regression (both shapes allocate nothing) and
// ns/op on a shared CI box does not mean the same thing on every runner — a
// lock that is or is not taken does, on every lane including -race.
func TestGate_DisabledAddNeverTakesPersistMu(t *testing.T) {
	restoreRing := SwapRingForTest()
	defer restoreRing()
	restoreW := SwapPersistenceForTest()
	defer restoreW()
	oldHistory := history
	history = nil
	defer func() { history = oldHistory }()

	if persistRunning.Load() {
		t.Fatal("precondition: the persistence gate is open after SwapPersistenceForTest")
	}

	persistMu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Add(benchEntry(1))
	}()
	select {
	case <-done:
		persistMu.Unlock()
	case <-time.After(5 * time.Second):
		persistMu.Unlock()
		<-done
		t.Fatal("REGRESSION: Add blocked on persistMu with persistence disabled — " +
			"the per-request path must consult the lock-free gate, never the " +
			"process-wide mutex, to discover that the JSONL sink is off")
	}

	// The entry still has to be in the ring: a gate that short-circuits the
	// whole of Add would also pass the deadlock check above.
	if got := Get(); len(got) != 1 {
		t.Fatalf("ring holds %d entries, want 1 — the gate must skip the JSONL queue, not the ring", len(got))
	}
}

// TestGate_MirrorsPersistChAcrossLifecycle pins the invariant the fast path
// rests on: the gate is NEVER closed while the drain channel is live. The
// reverse skew (open gate, no channel) is the safe direction — enqueue falls
// back to persistMu and returns on the nil, exactly as it always did — but it
// must not survive a stop, or every request pays the mutex forever for a sink
// that is not running.
func TestGate_MirrorsPersistChAcrossLifecycle(t *testing.T) {
	restoreW := SwapPersistenceForTest()
	defer restoreW()

	channelLive := func() bool {
		persistMu.Lock()
		defer persistMu.Unlock()
		return persistCh != nil
	}

	if persistRunning.Load() {
		t.Fatal("after SwapPersistenceForTest: gate must be closed")
	}
	if channelLive() {
		t.Fatal("after SwapPersistenceForTest: drain channel must be nil")
	}

	startPersist()
	if !channelLive() {
		t.Fatal("after startPersist: drain channel must be live")
	}
	if !persistRunning.Load() {
		t.Fatal("after startPersist: gate closed over a live channel — enqueue would silently drop every entry")
	}

	startPersist() // idempotent: must not close the gate it already opened
	if !persistRunning.Load() {
		t.Fatal("after a second startPersist: gate must still be open")
	}

	stopPersist()
	if channelLive() {
		t.Fatal("after stopPersist: drain channel must be nil")
	}
	if persistRunning.Load() {
		t.Fatal("after stopPersist: gate must be closed, or every request pays persistMu for a sink that is off")
	}

	stopPersist() // idempotent
	if persistRunning.Load() {
		t.Fatal("after a second stopPersist: gate must still be closed")
	}
}

// TestBenchGate_PersistGateBeatsLegacy is the timing half, expressed as a
// RATIO measured in ONE run so it is machine-independent and needs no
// re-baselining. The bound is deliberately loose (the measured saving is far
// larger) because its job is to catch the mutex coming back, not to police a
// few nanoseconds.
//
// It does not run under -race: the detector instruments both arms far more
// heavily than the difference being timed, so the verdict becomes a coin toss.
// Nothing is lost by stepping aside — TestGate_DisabledAddNeverTakesPersistMu
// pins the same regression structurally on every lane.
func TestBenchGate_PersistGateBeatsLegacy(t *testing.T) {
	if testing.Short() {
		t.Skip("timing gate")
	}
	if raceDetectorOn {
		t.Skip("timing gate: -race instrumentation swamps the lock being removed; the structural gate covers this lane")
	}
	restoreW := SwapPersistenceForTest()
	defer restoreW()

	// Both arms assign into the same package-level sink so neither can be
	// optimised away differently from the other.
	fast := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			gateSink = persistRunning.Load()
		}
	})
	legacy := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			gateSink = legacyEnqueueGate()
		}
	})
	if fast.NsPerOp() >= legacy.NsPerOp() {
		t.Errorf("atomic gate %d ns/op is not faster than the persistMu gate %d ns/op",
			fast.NsPerOp(), legacy.NsPerOp())
	}
}
