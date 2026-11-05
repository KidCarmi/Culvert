package scanner

// CHAOS-110 gates for the DPI scan worker's in-flight accounting.
//
// Every test here drives the match step through the patternSet.matcher seam, so
// the assertions are decided by the test rather than by how fast the machine
// happens to run a regex. Nothing below asserts on a heap figure: the
// measurements that motivated the cap are in the dated review, and a heap
// assertion on a shared CI runner is a flake. The invariant these gates hold is
// the one that actually bounds the heap — Inflight() never exceeds the cap, and
// it counts a worker for as long as that worker is alive, abandoned or not.

import (
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gatedSet returns a one-pattern set whose match step reports that it has been
// entered and then blocks until release is closed.
func gatedSet(entered *atomic.Int64, release <-chan struct{}) *patternSet {
	ps := &patternSet{raw: []string{"p0"}, compiled: []*regexp.Regexp{regexp.MustCompile("p0")}}
	ps.matcher = func(*regexp.Regexp, []byte) bool {
		entered.Add(1)
		<-release
		return false
	}
	return ps
}

// withGate pins the cap for one test and restores the production sizing after,
// because the gate and its counters are package globals.
//
// The reset Stores the in-flight counter, so it must not run while a worker
// from an earlier test is still alive: that worker's deferred release would
// land AFTER the Store and decrement this test's counter, making its exact-count
// assertions fail (seen under -shuffle as "Inflight() = 7, want 8" followed by
// inflight=-1). Every test that abandons a worker owns its whole lifetime and
// waits for the release itself (TestScan_TimeoutFailsClosed); this check
// covers the remaining handoff window — a worker that has sent its verdict but
// not yet run its deferred release — and turns a test that leaks a worker into
// a named failure here instead of a silent miscount in whichever test follows.
func withGate(t *testing.T, limit int) {
	t.Helper()
	if got := waitInflight(t, 0); got != 0 {
		t.Fatalf("Inflight() = %d before resetting the gate, want 0: a preceding test left a "+
			"scan worker alive — a test that abandons a worker must wait for its release", got)
	}
	resetInflightForTest(limit)
	t.Cleanup(func() { resetInflightForTest(defaultMaxInflight()) })
}

// inflightBaseline waits out any straggling worker from an earlier test and
// returns the in-flight count this test starts from. Same helper, same purpose,
// as internal/yara's: a test that is about to abandon a worker records where
// the counter stood so it can wait for its own worker's release.
func inflightBaseline(t *testing.T) int64 {
	t.Helper()
	return waitInflight(t, 0)
}

// waitInflight waits, bounded, for the counter to come back to want and returns
// what it last read, so a test never leaves a draining worker behind for the
// next one to trip over. The caller decides whether a mismatch is a failure.
func waitInflight(t *testing.T, want int64) int64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := Inflight()
		if got == want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(time.Millisecond)
	}
}

// waitFor polls cond until it holds or the deadline passes. Used only to wait
// out the handoff between a parent receiving its verdict and the worker's
// deferred release running — never to create the condition under test.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s (inflight=%d max=%d)", what, Inflight(), MaxInflight())
		}
		time.Sleep(time.Millisecond)
	}
}

// An abandoned worker keeps occupying the cap until its uninterruptible match
// actually returns. This is the whole point of the gate: before CHAOS-110 the
// abandoned population was unbounded and uncounted, so N concurrent scans that
// all timed out left N goroutines each holding a response body.
func TestChaos110_AbandonedWorkerStaysCountedUntilItsMatchReturns(t *testing.T) {
	withGate(t, 4)
	var entered atomic.Int64
	release := make(chan struct{})
	ps := gatedSet(&entered, release)

	pattern, hit := ps.scan([]byte("body"), 25*time.Millisecond)
	if !hit {
		t.Fatalf("scan over a blocked match must fail closed; got hit=false pattern=%q", pattern)
	}
	if got := AbandonedWorkers(); got != 1 {
		t.Errorf("AbandonedWorkers() = %d, want 1", got)
	}
	// The parent has returned, but the worker is still inside the match and
	// still keeping the body reachable, so it must still be charged.
	if got := Inflight(); got != 1 {
		t.Fatalf("Inflight() = %d after the parent abandoned, want 1 — an abandoned "+
			"worker that is not counted is the unbounded population CHAOS-110 closes", got)
	}
	close(release)
	waitFor(t, "the abandoned worker to release its slot", func() bool { return Inflight() == 0 })
}

// The cap is never exceeded, however many scans arrive at once, and scans that
// cannot get a slot within their wait budget fail CLOSED and are counted.
func TestChaos110_CapIsNeverExceededAndRefusalsFailClosed(t *testing.T) {
	const limit = 2
	withGate(t, limit)
	var entered atomic.Int64
	release := make(chan struct{})
	ps := gatedSet(&entered, release)

	// Occupy every slot with a match that will not return.
	var held sync.WaitGroup
	for i := 0; i < limit; i++ {
		held.Add(1)
		go func() { defer held.Done(); ps.scan([]byte("body"), time.Hour) }()
	}
	waitFor(t, "every slot to be occupied", func() bool { return entered.Load() == limit })
	if got := Inflight(); got != limit {
		t.Fatalf("Inflight() = %d, want %d", got, limit)
	}

	// A further scan must be refused rather than spawning worker number three.
	pattern, hit := ps.scan([]byte("body"), 25*time.Millisecond)
	if !hit || pattern != SaturatedReason {
		t.Errorf("saturated scan = (%q, %v), want (%q, true) — an uninspected body "+
			"must not be reported clean (S17)", pattern, hit, SaturatedReason)
	}
	if got := SaturationBlocks(); got != 1 {
		t.Errorf("SaturationBlocks() = %d, want 1", got)
	}
	if got := Inflight(); got != limit {
		t.Errorf("Inflight() = %d after a refusal, want %d — a refused scan must book nothing", got, limit)
	}
	if got := entered.Load(); got != limit {
		t.Errorf("match entered %d times, want %d — the refused scan must not have run a match", got, limit)
	}

	close(release)
	held.Wait()
	waitFor(t, "every worker to release", func() bool { return Inflight() == 0 })
}

// Negative control for the test above: the SAME workload against a cap large
// enough to hold it is not refused at all. Without this, a refusal count could
// come from anything; with it, the refusals are attributable to the cap.
func TestChaos110_NegativeControl_RoomyGateRefusesNothing(t *testing.T) {
	const scans = 8
	withGate(t, scans+1)
	var entered atomic.Int64
	release := make(chan struct{})
	ps := gatedSet(&entered, release)

	var wg sync.WaitGroup
	for i := 0; i < scans; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); ps.scan([]byte("body"), time.Hour) }()
	}
	waitFor(t, "all scans to be matching", func() bool { return entered.Load() == scans })
	if got := SaturationBlocks(); got != 0 {
		t.Errorf("SaturationBlocks() = %d with a cap above the offered load, want 0 — "+
			"the gate must not refuse traffic the engine has room for", got)
	}
	if got := Inflight(); got != scans {
		t.Errorf("Inflight() = %d, want %d", got, scans)
	}
	close(release)
	wg.Wait()
	waitFor(t, "every worker to release", func() bool { return Inflight() == 0 })
}

// An ordinary scan must give its slot back, so a busy gateway does not drift
// into permanent saturation. The slot is released by the WORKER, so this is the
// regression test for the release being wired to the worker's exit rather than
// the parent's return.
func TestChaos110_OrdinaryScansReleaseTheirSlots(t *testing.T) {
	withGate(t, 2)
	ps := &patternSet{raw: []string{"nope"}, compiled: []*regexp.Regexp{regexp.MustCompile("nope")}}
	for i := 0; i < 200; i++ {
		if _, hit := ps.scan([]byte("clean body"), time.Second); hit {
			t.Fatalf("scan %d: clean body reported as a hit", i)
		}
	}
	waitFor(t, "the last worker to release", func() bool { return Inflight() == 0 })
	if got := SaturationBlocks(); got != 0 {
		t.Errorf("SaturationBlocks() = %d over 200 sequential clean scans, want 0", got)
	}
	if got := AbandonedWorkers(); got != 0 {
		t.Errorf("AbandonedWorkers() = %d over 200 sequential clean scans, want 0", got)
	}
}

// A resize must not lose a slot held by the previous generation, nor let the old
// holder give its slot back to the new gate (which would over-admit).
func TestChaos110_ResizeKeepsOldHoldersOnTheOldGeneration(t *testing.T) {
	withGate(t, 1)
	var entered atomic.Int64
	release := make(chan struct{})
	ps := gatedSet(&entered, release)

	go ps.scan([]byte("body"), time.Hour)
	waitFor(t, "the first worker to occupy the only slot", func() bool { return entered.Load() == 1 })

	SetMaxInflight(3) // new generation, full capacity
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); ps.scan([]byte("body"), time.Hour) }()
	}
	waitFor(t, "the new generation to fill", func() bool { return entered.Load() == 4 })

	// A fifth scan is refused: the new gate holds 3 and the old holder is still
	// charged, so the cap is honoured across the resize.
	if _, hit := ps.scan([]byte("body"), 25*time.Millisecond); !hit {
		t.Error("scan past a full resized gate must fail closed")
	}
	close(release)
	wg.Wait()
	waitFor(t, "every worker across both generations to release", func() bool { return Inflight() == 0 })
}

// The default cap is two concurrent matches per available core. Sizing it off
// the CPU allowance is deliberate: the gate bounds CPU-bound regex work, and
// over-subscribing a core stretches each match's WALL-CLOCK elapsed time, which
// is what the per-pattern budget measures — so a cap that is too generous makes
// the gateway fail clean content closed for want of CPU.
func TestChaos110_DefaultCapIsTwoPerCore(t *testing.T) {
	withGate(t, defaultMaxInflight())
	if got, want := MaxInflight(), defaultMaxInflight(); got != want {
		t.Fatalf("MaxInflight() = %d, want %d", got, want)
	}
	if got := defaultMaxInflight(); got < inflightFloor {
		t.Errorf("defaultMaxInflight() = %d, want at least the floor %d", got, inflightFloor)
	}
	// SetMaxInflight clamps nonsense rather than publishing a gate that admits
	// nothing or panics on a zero-capacity channel.
	SetMaxInflight(0)
	if got := MaxInflight(); got != 1 {
		t.Errorf("MaxInflight() after SetMaxInflight(0) = %d, want 1", got)
	}
}

// A panic inside a match must be CONTAINED, not fatal. The worker runs
// attacker-supplied bytes through a compiled regexp on the response-scanning
// path, so an unrecovered panic there terminates an in-line gateway. Root's
// safeDPIScan is not the guard for it: its recover() runs on the calling
// goroutine and cannot see a panic in the worker's.
//
// Same contract internal/yara's TestChaos25_MatchPanic_FailsClosedByDefault
// holds: the process survives, the caller gets an ANSWER rather than waiting
// out the budget, and that answer is BLOCK — a scanner that cannot decide must
// not report "clean".
func TestChaos110_MatchPanicIsContainedAndFailsClosed(t *testing.T) {
	withGate(t, 2)
	ps := &patternSet{raw: []string{"p0"}, compiled: []*regexp.Regexp{regexp.MustCompile("p0")}}
	ps.matcher = func(*regexp.Regexp, []byte) bool {
		panic("simulated fault inside the regex match")
	}

	start := time.Now()
	pattern, hit := ps.scan([]byte("some response body"), 10*time.Second)
	elapsed := time.Since(start)

	if !hit {
		t.Errorf("scan over a panicking match = (%q, false), want a fail-closed hit — "+
			"a scanner that cannot decide must not report the body clean", pattern)
	}
	if pattern != PanicReason {
		t.Errorf("pattern = %q, want %q so the cause is distinguishable from a timeout", pattern, PanicReason)
	}
	if got := MatchPanics(); got != 1 {
		t.Errorf("MatchPanics() = %d, want 1", got)
	}
	// The answer must not wait out the 10s budget: the verdict is already known.
	if elapsed > 2*time.Second {
		t.Errorf("scan took %v, want prompt — a contained panic must answer at once, "+
			"not make the parent wait out a budget that will never be met", elapsed)
	}
	// The guard must not strand the slot either.
	waitFor(t, "the worker to release its slot after a contained panic", func() bool { return Inflight() == 0 })
}
