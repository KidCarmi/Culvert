package reqlog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ── Test sinks ───────────────────────────────────────────────────────────────

// slowSink models a disk that is not instantaneous — a networked volume, an
// overlayfs under cgroup blkio throttling, or the remove/rename/open stall of
// a log rotation. fileutil.RotatingFile serializes every writer on one mutex
// held across the syscall, so the mutex here reproduces the real shape.
type slowSink struct {
	mu    sync.Mutex
	delay time.Duration
}

func (s *slowSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	time.Sleep(s.delay)
	return len(p), nil
}

// countingSink records every line written so loss can be asserted exactly.
type countingSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *countingSink) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *countingSink) lines() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Count(c.buf.Bytes(), []byte("\n"))
}

func (c *countingSink) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

// isolate gives a test a private ring, no history hook and no inherited
// persistence, restoring everything on cleanup.
func isolate(t *testing.T) {
	t.Helper()
	restoreRing := SwapRingForTest()
	t.Cleanup(restoreRing)
	restorePersist := SwapPersistenceForTest()
	t.Cleanup(restorePersist)
	oldHistory := history
	history = nil
	t.Cleanup(func() { history = oldHistory })
}

// ── Regression gates ─────────────────────────────────────────────────────────

// TestAdd_PreservesOrder pins the property the single drain goroutine buys:
// entries reach the JSONL file in the order Add was called, so the persisted
// log stays chronological and ReadPersistent's newest-first contract holds.
// A worker pool would break this; there must stay exactly one drainer.
func TestAdd_PreservesOrder(t *testing.T) {
	isolate(t)
	sink := &countingSink{}
	restoreWriter := SetWriterForTest(sink)
	defer restoreWriter()

	const n = 5000
	for i := 0; i < n; i++ {
		Add(Entry{TS: int64(i), Host: "h.example.com", Status: "OK"})
	}
	Sync()

	dec := json.NewDecoder(bytes.NewReader(sink.bytes()))
	for i := 0; i < n; i++ {
		var got Entry
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("decode entry %d: %v", i, err)
		}
		if got.TS != int64(i) {
			t.Fatalf("REGRESSION: entry %d has TS=%d — the persistence queue is no "+
				"longer FIFO; the JSONL log must stay chronologically ordered", i, got.TS)
		}
	}
}

// TestAdd_DoesNotBlockOnSlowSink is the behavioral gate: proxy request
// goroutines must not wait on the disk. Before the async split, N adds
// against a sink taking `delay` each cost at least N*delay on the caller
// (serialized on the writer's mutex); now the callers only enqueue.
//
// The bound is deliberately loose (a third of the synchronous cost) so it
// gates the architecture, not the runner's speed.
func TestAdd_DoesNotBlockOnSlowSink(t *testing.T) {
	isolate(t)
	const (
		burst = 500
		delay = 2 * time.Millisecond
	)
	sink := &slowSink{delay: delay}
	restoreWriter := SetWriterForTest(sink)
	defer restoreWriter()

	synchronousCost := burst * delay // what the caller paid before
	e := benchEntry(0)

	start := time.Now()
	for i := 0; i < burst; i++ {
		Add(e)
	}
	elapsed := time.Since(start)

	if elapsed > synchronousCost/3 {
		t.Errorf("REGRESSION: %d adds against a %v-per-write sink cost the caller %v; "+
			"the synchronous path cost %v and the async queue should cost a small "+
			"fraction of it — disk latency is leaking back onto the request goroutine",
			burst, delay, elapsed, synchronousCost)
	}
	t.Logf("caller cost %v for %d adds (synchronous equivalent %v)", elapsed, burst, synchronousCost)
}

// TestAdd_NoEntryLostUnderBackpressure pins the shock-absorber contract: the
// queue bounds memory, it does NOT shed load. The request log is the durable
// audit record of what the proxy allowed and blocked, so a burst several
// times the queue depth must still land in full — callers wait instead.
func TestAdd_NoEntryLostUnderBackpressure(t *testing.T) {
	isolate(t)
	sink := &countingSink{}
	restoreWriter := SetWriterForTest(sink)
	defer restoreWriter()

	total := persistQueueDepth * 3
	for i := 0; i < total; i++ {
		Add(benchEntry(i))
	}
	Sync()

	if got := sink.lines(); got != total {
		t.Errorf("REGRESSION: wrote %d of %d entries — the persistence queue is "+
			"shedding audit records; it must block, not drop", got, total)
	}
}

// TestAdd_ConcurrentNoEntryLost is the concurrency gate: many request
// goroutines enqueue at once, exactly as the proxy does, and every entry must
// still reach the sink.
func TestAdd_ConcurrentNoEntryLost(t *testing.T) {
	isolate(t)
	sink := &countingSink{}
	restoreWriter := SetWriterForTest(sink)
	defer restoreWriter()

	const (
		workers = 16
		perWork = 500
	)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWork; i++ {
				Add(benchEntry(w*perWork + i))
			}
		}(w)
	}
	wg.Wait()
	Sync()

	if got, want := sink.lines(), workers*perWork; got != want {
		t.Errorf("wrote %d of %d entries under %d concurrent callers", got, want, workers)
	}
}

// TestClose_DrainsQueue proves shutdown does not discard in-flight entries:
// the shutdown hook calls Close, which must flush the queue before releasing
// the file handle.
func TestClose_DrainsQueue(t *testing.T) {
	isolate(t)
	path := filepath.Join(t.TempDir(), "request.jsonl")
	if err := Init(path, 10); err != nil {
		t.Fatalf("Init: %v", err)
	}

	const n = 1000
	for i := 0; i < n; i++ {
		Add(benchEntry(i))
	}
	if err := Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got := bytes.Count(data, []byte("\n")); got != n {
		t.Errorf("REGRESSION: %d of %d entries survived Close — the shutdown hook "+
			"must drain the persistence queue before closing the file", got, n)
	}
}

// TestSync_NoopWhenPersistenceDisabled guards the common configuration: with
// no JSONL file wired, Sync must return immediately rather than block.
func TestSync_NoopWhenPersistenceDisabled(t *testing.T) {
	isolate(t)
	done := make(chan struct{})
	go func() { Sync(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Sync blocked with persistence disabled")
	}
}

// TestSync_TimesOutWhenDrainAcceptsButNeverCompletes is the regression gate
// for the two-phase Sync deadline.
//
// It reproduces the exact shape the drain goroutine has when a sink wedges
// inside bw.Flush: the handshake IS accepted (the loop was idle in its select
// when Sync arrived), and only then does the flush stall, so `done` is never
// closed. A deadline covering only the handshake send leaves the subsequent
// `<-done` unbounded and Sync never returns — and since ReadPersistent calls
// Sync, that hangs an admin API request on a bad log volume.
//
// The stand-in drain goroutine is used deliberately: driving the real loop
// into "handshake accepted, then flush wedges" depends on which case select
// picks, so a real-sink version of this test would be probabilistic and could
// pass against the bug. This one fails against it every run.
func TestSync_TimesOutWhenDrainAcceptsButNeverCompletes(t *testing.T) {
	oldTimeout := persistSyncTimeout
	persistSyncTimeout = 250 * time.Millisecond
	defer func() { persistSyncTimeout = oldTimeout }()

	persistMu.Lock()
	oldFlush := flushCh
	stall := make(chan chan struct{})
	flushCh = stall
	persistMu.Unlock()
	defer func() {
		persistMu.Lock()
		flushCh = oldFlush
		persistMu.Unlock()
	}()

	// Accept the handshake and then never signal completion — a drain
	// goroutine parked in a write(2) that never returns.
	accepted := make(chan struct{})
	go func() {
		<-stall
		close(accepted)
	}()

	returned := make(chan struct{})
	go func() { Sync(); close(returned) }()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("REGRESSION: Sync never returned after the drain goroutine accepted " +
			"the flush handshake but stalled before completing it. The deadline must " +
			"cover the wait for completion, not just the handshake send — ReadPersistent " +
			"calls Sync, so this hangs an admin API request on a wedged log volume.")
	}
	<-accepted // the handshake really was taken, i.e. we exercised phase two
}

// TestBackpressure_CountsSaturation checks the saturation gauge moves only
// when the queue actually fills, so a healthy deployment reports zero.
func TestBackpressure_CountsSaturation(t *testing.T) {
	isolate(t)
	sink := &countingSink{}
	restoreWriter := SetWriterForTest(sink)
	defer restoreWriter()

	before := Backpressure()
	for i := 0; i < 16; i++ { // far below persistQueueDepth
		Add(benchEntry(i))
	}
	Sync()
	if got := Backpressure(); got != before {
		t.Errorf("Backpressure() moved by %d on a %d-entry burst; the queue holds %d "+
			"— a healthy sink must report no saturation", got-before, 16, persistQueueDepth)
	}
}

// ── Benchmarks ───────────────────────────────────────────────────────────────

// benchPersist is the before/after comparison harness: the same Add the proxy
// calls, with a real rotating file wired, which is the production
// configuration BenchmarkAdd deliberately omits.
func benchPersist(b *testing.B, parallel bool) {
	restoreRing := SwapRingForTest()
	defer restoreRing()
	restorePersist := SwapPersistenceForTest()
	defer restorePersist()
	oldHistory := history
	history = nil
	defer func() { history = oldHistory }()

	if err := Init(filepath.Join(b.TempDir(), "requests.jsonl"), 4096); err != nil {
		b.Fatal(err)
	}
	defer ResetForTest()

	e := benchEntry(0)
	for i := 0; i < MaxRing; i++ {
		Add(e)
	}
	b.ReportAllocs()
	b.ResetTimer()
	if parallel {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				Add(e)
			}
		})
		return
	}
	for i := 0; i < b.N; i++ {
		Add(e)
	}
}

// BenchmarkAddPersist measures what one logged request costs the PROXY
// goroutine with JSONL persistence enabled — 2318 ns/op before the drain
// goroutine took over the marshal and the write(2).
//
// Note on B/op and allocs/op: the marshal still happens, just on the drain
// goroutine, and Go's allocation counters are process-wide. Those two columns
// are therefore expected to stay roughly flat; the column that moves — and
// the one this change is about — is ns/op on the caller.
func BenchmarkAddPersist(b *testing.B) { benchPersist(b, false) }

// BenchmarkAddPersistParallel is the contention benchmark. Before the split
// every caller serialized on fileutil.RotatingFile's mutex, so 8-way parallel
// Add measured 2127 ns/op — no better than serial. The queue removes that
// serialization from the request path entirely.
func BenchmarkAddPersistParallel(b *testing.B) { benchPersist(b, true) }

// benchSlowDisk is the stress benchmark: it holds the sink at a fixed latency
// and reports what one logged request costs the proxy goroutine. Before the
// split this tracked delay × concurrent-callers (100 µs × 8 measured 1.1 ms);
// it is now independent of the disk until the queue saturates, at which point
// it converges back to the sink rate — never worse than the old behavior.
func benchSlowDisk(b *testing.B, delay time.Duration) {
	restoreRing := SwapRingForTest()
	defer restoreRing()
	restorePersist := SwapPersistenceForTest()
	defer restorePersist()
	oldHistory := history
	history = nil
	defer func() { history = oldHistory }()

	restoreWriter := SetWriterForTest(&slowSink{delay: delay})
	defer restoreWriter()

	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Add(e)
		}
	})
}

func BenchmarkAddSlowDisk100us(b *testing.B) { benchSlowDisk(b, 100*time.Microsecond) }

// BenchmarkAddBurst measures a burst that fits the queue — the shape a real
// traffic spike has — reported as caller cost per entry.
func BenchmarkAddBurst(b *testing.B) {
	restoreRing := SwapRingForTest()
	defer restoreRing()
	restorePersist := SwapPersistenceForTest()
	defer restorePersist()
	oldHistory := history
	history = nil
	defer func() { history = oldHistory }()

	restoreWriter := SetWriterForTest(&slowSink{delay: 50 * time.Microsecond})
	defer restoreWriter()

	const burst = 1000
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < burst; j++ {
			Add(e)
		}
		b.StopTimer()
		Sync() // settle between iterations so each measures a cold burst
		b.StartTimer()
	}
	b.ReportMetric(float64(burst), "entries/burst")
}
