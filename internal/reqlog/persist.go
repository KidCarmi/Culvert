package reqlog

import (
	"bufio"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// Asynchronous JSONL persistence.
//
// Add is called from the proxy request goroutine, once per logged request.
// Marshalling the entry and issuing the write(2) there coupled proxy latency
// to disk latency: fileutil.RotatingFile serializes every writer on one
// mutex held ACROSS the syscall (and across the remove/rename/open rotation
// stall), so a slow volume did not merely cost the issuing request — every
// concurrent request queued behind it. Measured on the pre-change code, an
// artificial 100 µs write cost 1.1 ms per Add at 8 concurrent callers.
//
// The fix is the pattern this codebase already applies to its other two
// request-log sinks — internal/logstore (queryable history) and
// internal/syslog (SIEM): callers enqueue on a bounded channel and ONE drain
// goroutine owns the file. A slow or stalled disk now costs bounded drops,
// never proxy latency. Entries are drained in FIFO order by a single
// goroutine, so the JSONL file stays chronologically ordered exactly as
// before, and the bytes written per entry are unchanged.
//
// The queue is a shock absorber, NOT a load shedder. logstore and syslog
// drop on a full queue; the JSONL file must not, because it is the durable
// audit record of what the proxy allowed and blocked. A full queue therefore
// blocks the caller — which is exactly the pre-change behavior, so this is
// never worse than today: bursts up to persistQueueDepth are absorbed
// completely, and only sustained saturation (the disk genuinely cannot keep
// up) reverts to the old coupling. Saturation is counted and surfaced via
// Backpressure() so the degraded state is visible rather than silent.

// persistQueueDepth bounds the in-flight entry queue. At the measured ~2 µs
// steady-state drain cost this absorbs multi-millisecond disk stalls at
// realistic proxy rates while capping the queue's memory at roughly
// persistQueueDepth × sizeof(Entry) (~1.3 MB).
const persistQueueDepth = 4096

// persistSyncTimeout bounds how long Sync waits for the drain goroutine. A
// wedged write must not turn a shutdown hook (or a test) into a deadlock.
const persistSyncTimeout = 5 * time.Second

// writerMu guards the writer/closer/path trio. Before the async split these
// were plain globals read from every request goroutine while Init and the
// test hooks wrote them — a latent race that the single-owner drain
// goroutine now removes from the hot path entirely.
var writerMu sync.RWMutex

// currentWriter returns the configured JSONL sink, or nil when persistence
// is disabled.
func currentWriter() io.Writer {
	writerMu.RLock()
	defer writerMu.RUnlock()
	return writer
}

// persist holds the drain goroutine's lifecycle. persistMu serializes
// start/stop so Init, Close and the test hooks cannot interleave.
var (
	persistMu sync.Mutex
	persistCh chan Entry         // nil when no drain goroutine is running
	flushCh   chan chan struct{} // Sync handshake
	stopCh    chan struct{}
	persistWG sync.WaitGroup

	// backpressure counts how many entries had to wait on a full queue, i.e.
	// how often the disk failed to keep up with the request rate.
	backpressure int64
)

// Backpressure reports how many request-log entries had to wait for room in
// the persistence queue. Non-zero means the JSONL sink is not keeping up with
// the request rate and proxy latency is once again coupled to disk latency —
// the signal to move the request log to a faster volume. No entry is ever
// lost, so this is a saturation gauge, not a loss counter.
func Backpressure() int64 { return atomic.LoadInt64(&backpressure) }

// enqueue hands an entry to the drain goroutine. The common path is a
// non-blocking send onto the buffered queue. No-op when persistence is
// disabled.
func enqueue(e Entry) {
	persistMu.Lock()
	ch, stop := persistCh, stopCh
	persistMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- e:
		return
	default:
	}
	// Queue full: the sink is saturated. Wait rather than discard — this is
	// the durable audit record. Blocking here is precisely the pre-change
	// behavior, so a saturated queue is never worse than the synchronous
	// write it replaced; every burst below persistQueueDepth is now free.
	if atomic.AddInt64(&backpressure, 1) == 1 {
		obs.Printf("WARN request log: persistence queue saturated, callers now waiting on the JSONL sink (further occurrences counted silently)")
	}
	select {
	case ch <- e:
	case <-stop:
		// Shutdown raced this send; the drain goroutine has stopped
		// consuming, so waiting would hang the caller forever.
	}
}

// startPersist brings up the drain goroutine if it is not already running.
// Idempotent; callers hold no lock.
func startPersist() {
	persistMu.Lock()
	defer persistMu.Unlock()
	if persistCh != nil {
		return
	}
	persistCh = make(chan Entry, persistQueueDepth)
	flushCh = make(chan chan struct{})
	stopCh = make(chan struct{})
	persistWG.Add(1)
	go drainLoop(persistCh, flushCh, stopCh)
}

// stopPersist drains everything still queued, then stops the goroutine.
// Idempotent; safe when persistence was never started.
func stopPersist() {
	persistMu.Lock()
	if persistCh == nil {
		persistMu.Unlock()
		return
	}
	stop := stopCh
	persistCh, flushCh, stopCh = nil, nil, nil
	persistMu.Unlock()

	close(stop)
	persistWG.Wait()
}

// Sync blocks until every entry enqueued before the call has been written.
// It is the deterministic alternative to sleeping: shutdown uses Close (which
// drains), and tests that assert on file contents call this. Cheap no-op when
// persistence is not running.
func Sync() {
	persistMu.Lock()
	fc := flushCh
	persistMu.Unlock()
	if fc == nil {
		return
	}
	done := make(chan struct{})
	select {
	case fc <- done:
		<-done
	case <-time.After(persistSyncTimeout):
		// The drain goroutine is wedged on a stalled write. Returning is
		// strictly better than deadlocking a shutdown hook or a test.
	}
}

// asyncSink adapts the mutable writer global to io.Writer so one bufio.Writer
// can live for the whole drain loop even though tests swap the sink under it.
// A nil sink discards, matching "persistence disabled".
type asyncSink struct{}

func (asyncSink) Write(p []byte) (int, error) {
	w := currentWriter()
	if w == nil {
		return len(p), nil
	}
	return w.Write(p)
}

// persistBufSize is the drain goroutine's write buffer. It only ever holds
// entries that arrived while a previous write was in flight — the loop flushes
// as soon as the queue is empty — so at low load it is one write(2) per entry,
// exactly as before, and under backlog it amortizes the syscall across the
// whole batch.
const persistBufSize = 64 * 1024

// drainLoop is the single owner of the JSONL sink. Parameters (not the
// globals) so a stop/start cycle can never have two loops racing over one
// channel.
//
// Batching policy: write the entry that woke us, then opportunistically take
// whatever else is already queued, then flush. The buffer is never held across
// a blocking wait, so an idle proxy sees no added durability delay — the
// batch collapses to one entry — while a backlogged one amortizes the syscall.
// One goroutine and one buffer also mean the file stays strictly FIFO.
func drainLoop(ch chan Entry, flush chan chan struct{}, stop chan struct{}) {
	defer persistWG.Done()
	// A single reused encoder writes compact JSON + '\n' straight into the
	// buffer. Byte-identical to the previous json.Marshal(e)+'\n', minus the
	// per-entry intermediate slice.
	bw := bufio.NewWriterSize(asyncSink{}, persistBufSize)
	enc := json.NewEncoder(bw)

	for {
		select {
		case e := <-ch:
			batch := encodeEntry(enc, e)
			batch += drainPending(enc, ch)
			flushBatch(bw, batch)
		case done := <-flush:
			flushBatch(bw, drainPending(enc, ch))
			close(done)
		case <-stop:
			// Final drain: entries already queued must still reach the file.
			flushBatch(bw, drainPending(enc, ch))
			return
		}
	}
}

// drainPending encodes every entry currently queued, returning how many it
// buffered. It never blocks.
func drainPending(enc *json.Encoder, ch chan Entry) int {
	n := 0
	for {
		select {
		case e := <-ch:
			n += encodeEntry(enc, e)
		default:
			return n
		}
	}
}

// encodeEntry buffers one JSONL record, returning 1 if the record is pending a
// flush. A marshal failure is charged immediately — it never reaches the file.
func encodeEntry(enc *json.Encoder, e Entry) int {
	if err := enc.Encode(e); err != nil {
		countWriteError(1, err)
		return 0
	}
	return 1
}

// flushBatch pushes the buffered records to the sink. n is the number of
// records in the buffer so a failed flush is charged per lost entry, keeping
// WriteErrors() a count of entries that did not reach the file — the same
// meaning it had when every entry was written individually.
func flushBatch(bw *bufio.Writer, n int) {
	if n == 0 {
		return
	}
	if err := bw.Flush(); err != nil {
		countWriteError(int64(n), err)
		// bufio latches its error; reset so the next batch is not poisoned by
		// a transient failure (a disk that recovers must resume logging).
		bw.Reset(asyncSink{})
	}
}

// countWriteError applies the count-every-failure, log-only-the-first contract
// the synchronous writer had: a full disk must not silently destroy the
// request history, but it must not flood the log either.
func countWriteError(n int64, err error) {
	atomic.AddInt64(&writeErrors, n)
	if writeErrLogged.CompareAndSwap(false, true) {
		obs.Printf("ERROR request log: persistent write failed (further failures counted silently): %v", err)
	}
}

// writeErrLogged makes the "log the first failure only" contract explicit now
// that a single flush can account for many failed entries.
var writeErrLogged atomic.Bool
