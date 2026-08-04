package reqlog

// persist_panic_test.go — CHAOS-24: the drain goroutine must survive a
// panicking round.
//
// Why this one matters more than the other worker guards: Add BLOCKS the caller
// when the queue is full (persist.go — the JSONL file is the durable audit
// record, so a saturated queue parks the producer instead of discarding it).
// That makes the drain goroutine load-bearing for the PROXY REQUEST PATH, not
// just for logging. If it ever stops consuming, every request goroutine
// eventually parks in Add and the gateway wedges — no crash, no restart, no
// alert, just a proxy that stops answering. So the guard has to contain the
// round WITHOUT letting the goroutine exit, and these tests pin exactly that.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// panicOnceSink models a sink whose write path panics (a latent bug in a
// rotation/encoder path, reached by one particular entry) and then recovers.
type panicOnceSink struct {
	mu      sync.Mutex
	buf     []byte
	armed   atomic.Bool
	panics  atomic.Int64
	written atomic.Int64
}

func (p *panicOnceSink) Write(b []byte) (int, error) {
	if p.armed.CompareAndSwap(true, false) {
		p.panics.Add(1)
		panic("simulated sink fault during flush")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf = append(p.buf, b...)
	p.written.Add(1)
	return len(b), nil
}

func (p *panicOnceSink) lineCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.buf {
		if c == '\n' {
			n++
		}
	}
	return n
}

// TestDrain_SurvivesPanicAndKeepsConsuming is the anti-wedge gate. After a
// panicking flush the drain goroutine must still be consuming, so later entries
// reach the sink and Sync's flush handshake still completes.
func TestDrain_SurvivesPanicAndKeepsConsuming(t *testing.T) {
	isolate(t)
	sink := &panicOnceSink{}
	restore := SetWriterForTest(sink)
	defer restore()

	sink.armed.Store(true)
	Add(Entry{TS: 1, Host: "poison.example.com", Status: "OK"})
	Sync()

	if sink.panics.Load() != 1 {
		t.Fatalf("harness: expected exactly 1 induced panic, got %d", sink.panics.Load())
	}

	// The real assertion: the consumer is still alive.
	const after = 50
	for i := 0; i < after; i++ {
		Add(Entry{TS: int64(100 + i), Host: "ok.example.com", Status: "OK"})
	}
	Sync()

	if got := sink.lineCount(); got < after {
		t.Fatalf("REGRESSION: only %d of %d post-panic entries reached the sink — the drain "+
			"goroutine stopped consuming. A dead drain wedges every request goroutine in Add.",
			got, after)
	}
}

// TestDrain_SurvivesRepeatedPanics: containment must hold for a DETERMINISTIC
// fault, not just a one-shot. A bug reached by every entry of a given shape
// must degrade those entries, never the consumer.
func TestDrain_SurvivesRepeatedPanics(t *testing.T) {
	isolate(t)
	sink := &panicOnceSink{}
	restore := SetWriterForTest(sink)
	defer restore()

	for i := 0; i < 20; i++ {
		sink.armed.Store(true)
		Add(Entry{TS: int64(i), Host: "poison.example.com", Status: "OK"})
		Sync()
	}
	if sink.panics.Load() == 0 {
		t.Fatal("harness: no panic was induced")
	}

	// Queue must still drain afterwards.
	Add(Entry{TS: 999, Host: "final.example.com", Status: "OK"})
	Sync()
	if sink.lineCount() == 0 {
		t.Fatal("REGRESSION: drain goroutine did not survive repeated panicking rounds")
	}
}

// TestDrain_PanicDoesNotBlockProducers is the direct wedge probe: it fills the
// queue past its depth after inducing a panic, and requires the producers to
// complete. If the drain goroutine had exited, these Adds would park forever on
// the full channel and the test would time out.
func TestDrain_PanicDoesNotBlockProducers(t *testing.T) {
	isolate(t)
	sink := &panicOnceSink{}
	restore := SetWriterForTest(sink)
	defer restore()

	sink.armed.Store(true)
	Add(Entry{TS: 0, Host: "poison.example.com", Status: "OK"})

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Comfortably more than persistQueueDepth, so a stalled consumer
		// guarantees a block rather than merely risking one.
		for i := 0; i < persistQueueDepth*3; i++ {
			Add(Entry{TS: int64(i), Host: "flood.example.com", Status: "OK"})
		}
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("REGRESSION: producers blocked in Add after a drain-goroutine panic — " +
			"the proxy would wedge with no crash and no alert")
	}
}

// TestDrain_StopStillTerminatesAfterPanic: containment must not cost shutdown.
// The stop branch returns true; if a panic ever left `stopped` false, the next
// round still observes the closed channel, so Close/stopPersist must not hang.
func TestDrain_StopStillTerminatesAfterPanic(t *testing.T) {
	isolate(t)
	sink := &panicOnceSink{}
	restore := SetWriterForTest(sink)

	sink.armed.Store(true)
	Add(Entry{TS: 1, Host: "poison.example.com", Status: "OK"})

	done := make(chan struct{})
	go func() { defer close(done); restore() }() // stopPersist joins the drain goroutine

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("REGRESSION: shutdown did not join the drain goroutine after a panicking round")
	}
}
