package logsink

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuf is a concurrency-safe sink for assertions.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// slowSink blocks for d on every Write, standing in for a stalled log volume.
type slowSink struct{ d time.Duration }

func (s *slowSink) Write(p []byte) (int, error) {
	time.Sleep(s.d)
	return len(p), nil
}

// errSink fails every Write.
type errSink struct{}

func (errSink) Write(p []byte) (int, error) { return 0, errors.New("sink failed") }

// wedgedSink never returns from Write.
type wedgedSink struct{ release chan struct{} }

func (s *wedgedSink) Write(p []byte) (int, error) { <-s.release; return len(p), nil }

// ── Contract: nothing is lost, order is preserved ────────────────────────────

func TestWriter_PreservesEveryLineInOrder(t *testing.T) {
	var sink syncBuf
	w := New(&sink)

	const n = 5000
	for i := 0; i < n; i++ {
		if _, err := w.Write([]byte(strconv.Itoa(i) + "\n")); err != nil {
			t.Fatalf("Write(%d): %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(sink.String(), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("got %d lines, want %d — the queue dropped lines (it is a shock absorber, not a load shedder)", len(lines), n)
	}
	for i, got := range lines {
		if got != strconv.Itoa(i) {
			t.Fatalf("line %d = %q, want %q — the single-drainer FIFO ordering guarantee is broken", i, got, strconv.Itoa(i))
		}
	}
}

// TestWriter_NoLossUnderSaturation drives far more lines than the queue can
// hold through a deliberately slow sink. Every line must still arrive: a full
// queue blocks the caller (the pre-change behavior) and never discards.
func TestWriter_NoLossUnderSaturation(t *testing.T) {
	var sink syncBuf
	w := New(&sink)

	const n = queueDepth * 3
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < n/8; i++ {
				_, _ = fmt.Fprintf(w, "g%d-%d\n", g, i)
			}
		}(g)
	}
	wg.Wait()
	_ = w.Close()

	if got := strings.Count(sink.String(), "\n"); got != n {
		t.Fatalf("got %d lines, want %d — lines were lost under saturation", got, n)
	}
}

// gatedSink parks the drain goroutine inside its first Write until the test
// releases it, which makes queue saturation deterministic rather than a race
// against the drainer's batching.
type gatedSink struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	buf     bytes.Buffer
}

func newGatedSink() *gatedSink {
	return &gatedSink{entered: make(chan struct{}), release: make(chan struct{})}
}

func (s *gatedSink) Write(p []byte) (int, error) {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *gatedSink) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.buf.String() }

// TestWriter_BackpressureCountedNotDropped pins the observability half of the
// saturation contract: a sink that cannot keep up must raise Backpressure()
// while still delivering every line.
func TestWriter_BackpressureCountedNotDropped(t *testing.T) {
	s := newGatedSink()
	w := New(s)

	// Park the drainer inside the sink, then overrun the queue from a goroutine
	// (the overrun blocks by design, so it cannot run on the test goroutine).
	const overrun = 500
	const n = queueDepth + overrun
	if _, err := w.Write([]byte("prime\n")); err != nil {
		t.Fatal(err)
	}
	<-s.entered

	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			_, _ = w.Write([]byte("x\n"))
		}
		close(done)
	}()

	// Wait for the queue to fill and callers to start waiting on it.
	deadline := time.Now().Add(5 * time.Second)
	for w.Backpressure() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(s.release)
	<-done
	_ = w.Close()

	if w.Backpressure() == 0 {
		t.Error("Backpressure() == 0 after overrunning the queue against a stalled sink — saturation is going unreported")
	}
	if w.WriteErrors() != 0 {
		t.Errorf("WriteErrors() = %d on a healthy (merely stalled) sink, want 0", w.WriteErrors())
	}
	if got := strings.Count(s.String(), "\n"); got != n+1 {
		t.Errorf("sink holds %d lines, want %d — saturation must delay lines, never drop them", got, n+1)
	}
}

// ── Contract: the caller is decoupled from the sink ──────────────────────────

// TestWriter_DoesNotBlockCallerBelowQueueDepth is the deterministic,
// hardware-independent form of the whole optimization: with a sink that takes
// 20ms per write, a burst that fits in the queue must return in far less than
// burst x 20ms. Synchronously, the same burst takes at least burst x 20ms.
func TestWriter_DoesNotBlockCallerBelowQueueDepth(t *testing.T) {
	const perWrite = 20 * time.Millisecond
	const burst = 64
	w := New(&slowSink{d: perWrite})
	t.Cleanup(func() { _ = w.Close() })

	start := time.Now()
	for i := 0; i < burst; i++ {
		_, _ = w.Write([]byte("line\n"))
	}
	elapsed := time.Since(start)

	// The synchronous floor is burst*perWrite (1.28s). Anything near that means
	// the request goroutine is still coupled to the sink. Generous bound so the
	// assertion is about the coupling, not about scheduler jitter.
	if limit := perWrite * 4; elapsed > limit {
		t.Fatalf("REGRESSION: %d writes against a %v sink took %v (limit %v) — "+
			"the caller is blocking on the log sink again; the drain goroutine is not decoupling it",
			burst, perWrite, elapsed, limit)
	}
}

// TestWriter_FlushesWhenQueueDrains pins the durability half: an idle process
// must not sit on a buffered line waiting for a batch to fill.
func TestWriter_FlushesWhenQueueDrains(t *testing.T) {
	var sink syncBuf
	w := New(&sink)
	t.Cleanup(func() { _ = w.Close() })

	_, _ = w.Write([]byte("single line\n"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(sink.String(), "single line") {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("a single line never reached the sink — the drain loop is holding it in the bufio buffer instead of flushing when the queue empties")
}

func TestWriter_SyncIsDeterministic(t *testing.T) {
	var sink syncBuf
	w := New(&sink)
	t.Cleanup(func() { _ = w.Close() })

	for i := 0; i < 100; i++ {
		_, _ = w.Write([]byte("pending\n"))
	}
	w.Sync()
	if got := strings.Count(sink.String(), "\n"); got != 100 {
		t.Fatalf("after Sync the sink holds %d lines, want 100 — Sync does not guarantee prior writes are flushed", got)
	}
}

// ── Contract: it composes with log.Logger exactly as the direct writer did ───

func TestWriter_LogLoggerBufferReuseIsSafe(t *testing.T) {
	var sink syncBuf
	w := New(&sink)
	l := log.New(w, "[Culvert] ", 0)

	for i := 0; i < 200; i++ {
		l.Printf("POLICY_ALLOW seq=%d", i)
	}
	_ = w.Close()

	out := sink.String()
	for i := 0; i < 200; i++ {
		want := fmt.Sprintf("[Culvert] POLICY_ALLOW seq=%d\n", i)
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q — log.Logger reuses its internal buffer, so Write must COPY p before queueing", want)
		}
	}
}

// ── Contract: failures are counted, never silent, never fatal ────────────────

func TestWriter_SinkErrorsAreCounted(t *testing.T) {
	w := New(errSink{})
	for i := 0; i < 10; i++ {
		n, err := w.Write([]byte("doomed\n"))
		if err != nil || n != len("doomed\n") {
			t.Fatalf("Write reported (%d, %v); it must always report success so log.Logger does not retry", n, err)
		}
	}
	_ = w.Close()
	if w.WriteErrors() == 0 {
		t.Error("WriteErrors() == 0 against a sink that fails every write — failures are silent")
	}
}

// TestWriter_RecoversAfterTransientSinkFailure pins the bufio.Reset behavior: a
// disk that recovers must resume logging rather than stay latched in error.
func TestWriter_RecoversAfterTransientSinkFailure(t *testing.T) {
	f := &flakySink{fail: true}
	w := New(f)
	t.Cleanup(func() { _ = w.Close() })

	_, _ = w.Write([]byte("lost\n"))
	w.Sync()
	f.setFail(false)
	_, _ = w.Write([]byte("recovered\n"))
	w.Sync()

	if !strings.Contains(f.String(), "recovered") {
		t.Fatal("no output after the sink recovered — bufio latched its error and was never reset")
	}
}

type flakySink struct {
	mu   sync.Mutex
	fail bool
	buf  bytes.Buffer
}

func (s *flakySink) setFail(v bool) { s.mu.Lock(); s.fail = v; s.mu.Unlock() }

func (s *flakySink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return 0, errors.New("transient")
	}
	return s.buf.Write(p)
}

func (s *flakySink) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.buf.String() }

// ── Contract: lifecycle ──────────────────────────────────────────────────────

func TestWriter_CloseIsIdempotent(t *testing.T) {
	w := New(io.Discard)
	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestWriter_CloseDoesNotHangOnWedgedSink pins that a hung log volume degrades
// shutdown rather than deadlocking it.
func TestWriter_CloseDoesNotHangOnWedgedSink(t *testing.T) {
	orig := closeTimeout
	closeTimeout = 150 * time.Millisecond
	t.Cleanup(func() { closeTimeout = orig })

	s := &wedgedSink{release: make(chan struct{})}
	t.Cleanup(func() { close(s.release) })
	w := New(s)
	_, _ = w.Write([]byte("wedged\n"))
	time.Sleep(20 * time.Millisecond) // let the drainer enter the wedged write

	done := make(chan struct{})
	go func() { _ = w.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close hung on a wedged sink — a hung log disk would hang shutdown")
	}
}

// TestWriter_SyncAfterCloseReturns pins that the shutdown-race path cannot
// deadlock a late Sync.
func TestWriter_SyncAfterCloseReturns(t *testing.T) {
	w := New(io.Discard)
	_ = w.Close()
	done := make(chan struct{})
	go func() { w.Sync(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Sync after Close hung")
	}
}

// TestWriter_WriteAfterCloseDoesNotHang pins the same for a late Write (a
// background goroutine still logging while shutdown runs).
func TestWriter_WriteAfterCloseDoesNotHang(t *testing.T) {
	w := New(&slowSink{d: 5 * time.Millisecond})
	_ = w.Close()
	done := make(chan struct{})
	go func() {
		for i := 0; i < queueDepth+500; i++ {
			_, _ = w.Write([]byte("late\n"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Write hung after Close — a shutdown-racing logger would deadlock")
	}
}

// TestWriter_ConcurrentWritesAreRaceFree is the -race exercise.
func TestWriter_ConcurrentWritesAreRaceFree(t *testing.T) {
	var sink syncBuf
	w := New(&sink)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_, _ = w.Write([]byte("concurrent\n"))
				if i%50 == 0 {
					_ = w.Backpressure()
					_ = w.WriteErrors()
				}
			}
		}()
	}
	wg.Wait()
	_ = w.Close()
	if got := strings.Count(sink.String(), "\n"); got != 16*200 {
		t.Fatalf("got %d lines, want %d", got, 16*200)
	}
}

// TestWriter_OversizedLinesAreNotPooled pins the pool-hygiene bound: a huge
// line must not pin a huge buffer in the pool.
func TestWriter_OversizedLinesAreNotPooled(t *testing.T) {
	var sink syncBuf
	w := New(&sink)
	big := append(bytes.Repeat([]byte("A"), maxPooledLine*4), '\n')
	_, _ = w.Write(big)
	_, _ = w.Write([]byte("small\n"))
	_ = w.Close()

	out := sink.String()
	if !strings.Contains(out, strings.Repeat("A", maxPooledLine*4)) {
		t.Error("oversized line was truncated or dropped")
	}
	if !strings.Contains(out, "small") {
		t.Error("line after an oversized line was lost")
	}
}
