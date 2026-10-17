package reqlog

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// Contracts for the lock-free enqueue fast path (persistRunning, persist.go).
//
// The gates here are DETERMINISTIC — a held mutex, a flag comparison, an
// entry count — never a ns/op ratio. This repository has repeatedly had to
// abandon timing gates because one that can flake gets muted (see the notes
// in proxy_hopheaders_benchgate_test.go), and the property being protected
// here is structural anyway: enqueue must not acquire persistMu when there is
// no drain goroutine. The ns/op evidence lives in the benchmarks in
// persist_fastpath_bench_test.go, measured against the frozen pre-change
// shape below so the before/after is reproducible from the tree.

// legacyEnqueueDisabledProbe is the verbatim pre-change lock discipline of
// enqueue, frozen for the before/after benchmark: take the exclusive
// lifecycle mutex, read the two pointers, register on the WaitGroup when a
// channel is live, release.
//
// It stops at the point the arms diverge. The send, the backpressure wait and
// the shutdown-race accounting are untouched by this change and are exercised
// against the REAL enqueue by persist_test.go; duplicating them here would
// freeze a second copy of logic that must not drift.
func legacyEnqueueDisabledProbe(_ Entry) {
	persistMu.Lock()
	ch := persistCh
	if ch != nil {
		enqueueWG.Add(1)
	}
	persistMu.Unlock()
	if ch == nil {
		return
	}
	enqueueWG.Done()
}

// TestEnqueue_TakesNoLockWhenPersistenceIsOff is the regression gate, and it
// is exact rather than statistical: the test HOLDS persistMu and then calls
// enqueue. The fast path returns immediately; reintroducing the lock
// acquisition blocks until the test releases it, which the timeout reports as
// a failure on any hardware, at any load, with or without -race.
func TestEnqueue_TakesNoLockWhenPersistenceIsOff(t *testing.T) {
	isolate(t) // SwapPersistenceForTest ⇒ no drain goroutine, flag false

	if persistRunning.Load() {
		t.Fatal("precondition: persistRunning is true with persistence swapped out")
	}

	var once sync.Once
	persistMu.Lock()
	unlock := func() { once.Do(persistMu.Unlock) }
	t.Cleanup(unlock)

	done := make(chan struct{})
	go func() {
		enqueue(benchEntry(0))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		unlock() // let the blocked goroutine finish before the test ends
		t.Fatal("REGRESSION: enqueue blocked on persistMu while persistence was " +
			"disabled — the per-request path must answer \"nothing to enqueue\" " +
			"from the lock-free persistRunning read, not from inside the " +
			"exclusive lifecycle mutex every request goroutine shares")
	}
}

// TestPersistRunning_TracksTheChannel pins the flag to the pointer it
// mirrors across the whole lifecycle. A flag left true after a stop would
// only cost a wasted lock; a flag left FALSE while a drainer is live would
// silently stop persisting the durable audit record, so this asserts both
// directions.
func TestPersistRunning_TracksTheChannel(t *testing.T) {
	isolate(t)

	check := func(stage string) {
		t.Helper()
		persistMu.Lock()
		live := persistCh != nil
		persistMu.Unlock()
		if got := persistRunning.Load(); got != live {
			t.Fatalf("%s: persistRunning=%v but persistCh!=nil is %v", stage, got, live)
		}
	}

	check("swapped out")

	sink := &countingSink{}
	restore := SetWriterForTest(sink)
	check("after start")

	// Idempotent start must not disturb the flag.
	startPersist()
	check("after redundant start")

	restore() // stopPersist
	check("after stop")

	// Idempotent stop must not disturb it either.
	stopPersist()
	check("after redundant stop")
}

// TestEnqueue_FastPathStillPersistsWhenEnabled is the CONTROL. Every gate
// above is satisfied most cheaply by an enqueue that always returns early,
// which would silently discard the durable JSONL audit record — far worse
// than the lock it saves. So: with persistence running, every Add must still
// reach the file.
func TestEnqueue_FastPathStillPersistsWhenEnabled(t *testing.T) {
	isolate(t)

	sink := &countingSink{}
	restore := SetWriterForTest(sink)
	defer restore()

	const n = 64
	for i := 0; i < n; i++ {
		Add(benchEntry(i))
	}
	Sync()

	if got := sink.lines(); got != n {
		t.Fatalf("persisted %d lines, want %d — the fast path dropped entries that "+
			"a live drain goroutine was supposed to receive", got, n)
	}
	if body := string(sink.bytes()); !strings.Contains(body, "host-0.example.com:443") {
		t.Error("persisted body does not carry the first entry's host; entries reached " +
			"the file but not with their payload")
	}
}

// TestEnqueue_FastPathPersistsConcurrently is the same control under the
// shape production actually has: many request goroutines racing the flag read
// against each other while one drainer owns the file. Nothing may be lost.
func TestEnqueue_FastPathPersistsConcurrently(t *testing.T) {
	isolate(t)

	sink := &countingSink{}
	restore := SetWriterForTest(sink)
	defer restore()

	const goroutines, perGoroutine = 8, 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				Add(benchEntry(g*perGoroutine + i))
			}
		}(g)
	}
	wg.Wait()
	Sync()

	if got, want := sink.lines(), goroutines*perGoroutine; got != want {
		t.Fatalf("persisted %d lines, want %d", got, want)
	}
}
