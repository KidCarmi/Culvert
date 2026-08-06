// Package logsink provides an asynchronous, batching io.Writer decorator for
// the process log.
//
// # Why
//
// Culvert's process logger is composed as
//
//	log.New(io.MultiWriter(os.Stdout, *fileutil.RotatingFile), "[Culvert] ", log.LstdFlags)
//
// and it is written from the proxy REQUEST goroutine: handleRequest emits one
// line per proxied request (POLICY_ALLOW / POLICY_BLOCK / POLICY_DROP /
// POLICY_DEFAULT_DENY / …). That coupled proxy latency to log-sink latency
// twice over:
//
//   - log.Logger holds its own mutex ACROSS the destination Write, and
//   - fileutil.RotatingFile holds a second mutex across its write(2) and across
//     the remove/rename/reopen rotation stall.
//
// Both writes are unbuffered, so every allowed request paid two syscalls inside
// a process-global critical section. Measured on the pre-change composition
// (4-core Xeon @2.10GHz, stdout redirected to a file, the verbatim POLICY_ALLOW
// format string):
//
//	sink               serial        4x parallel
//	format only        509 ns/op     155 ns/op      (scales: no shared state)
//	stdout+file        2798 ns/op    3204 ns/op     (does NOT scale: gets WORSE)
//
// A hot path that gets slower as cores are added is a throughput ceiling, not a
// constant cost: the sink capped the whole proxy at ~310k logged requests/sec
// regardless of how many cores the gateway has.
//
// # The fix
//
// This is the pattern the codebase already applies to its other per-request
// sinks — internal/reqlog (JSONL request log), internal/logstore (queryable
// history) and internal/syslog (SIEM): callers enqueue on a bounded channel and
// ONE drain goroutine owns the destination writer. The request goroutine's
// critical section becomes a buffer copy plus a channel send.
//
// # Contract
//
// The queue is a shock absorber, NOT a load shedder. logstore and syslog drop
// on a full queue; the process log must not — it is the operator's record of
// what the gateway did. A full queue therefore BLOCKS the caller, which is
// exactly the pre-change behavior, so this is never worse than the synchronous
// write it replaces: bursts up to queueDepth are absorbed completely, and only
// sustained saturation (the sink genuinely cannot keep up) reverts to the old
// coupling. Saturation is counted and surfaced via Backpressure() so the
// degraded state is visible rather than silent.
//
// Ordering is preserved: a single drain goroutine writes every line, so the log
// stays strictly FIFO and the bytes written per line are unchanged.
//
// Durability: the drain loop flushes as soon as the queue is empty, so an idle
// process still gets one write(2) per line and log visibility is not delayed.
// Only a backlog batches, and only for as long as the backlog lasts. What is
// genuinely new is that an abrupt process death (SIGKILL, OOM) can lose the
// in-flight batch; the orderly paths do not, because Close flushes and
// package main's fatal helper flushes before os.Exit.
//
// Re-entrancy: this package is the process log's sink, so it must never log
// through it. Its own diagnostics go straight to os.Stderr.
package logsink

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// queueDepth bounds the in-flight line queue. At the measured sub-microsecond
// steady-state drain cost this absorbs multi-millisecond sink stalls at
// realistic request rates while capping the queue's memory at roughly
// queueDepth x maxPooledLine (~1 MB).
const queueDepth = 4096

// bufSize is the drain goroutine's write buffer. It only ever holds lines that
// arrived while a previous write was in flight — the loop flushes as soon as
// the queue is empty — so at low load it is one write(2) per line, exactly as
// before, and under backlog it amortizes the syscall across the whole batch.
const bufSize = 64 * 1024

// maxPooledLine caps the capacity of a buffer returned to the pool. A single
// oversized line (a stack trace, a marshalled config) must not pin a large
// buffer in the pool for the life of the process.
const maxPooledLine = 4096

// closeTimeout bounds how long Close and Sync wait for the drain goroutine. A
// wedged sink (a hung NFS mount, a device that stops completing writes) must
// not turn a shutdown hook into a deadlock. A var, not a const, so the
// wedged-sink test can lower it instead of spending the full timeout.
var closeTimeout = 5 * time.Second

// Writer is an asynchronous, batching io.Writer decorator. Its Write is safe
// for concurrent use and does not touch the destination writer; a single
// background goroutine owns that. The zero value is not usable — call New.
type Writer struct {
	dst     io.Writer
	ch      chan *[]byte
	flushCh chan chan struct{}
	stop    chan struct{}
	done    chan struct{}
	pool    sync.Pool

	closeOnce sync.Once

	backpressure atomic.Int64
	writeErrors  atomic.Int64
	warnedOnce   atomic.Bool
	errLoggedOne atomic.Bool
}

// New returns a Writer that forwards to dst from a single background goroutine
// and starts that goroutine. The caller must Close it to flush and stop the
// goroutine; Close does not close dst.
func New(dst io.Writer) *Writer {
	w := &Writer{
		dst:     dst,
		ch:      make(chan *[]byte, queueDepth),
		flushCh: make(chan chan struct{}),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	w.pool.New = func() any { b := make([]byte, 0, 256); return &b }
	go w.drainLoop(bufio.NewWriterSize(dst, bufSize))
	return w
}

// Write copies p and hands it to the drain goroutine. It always reports the
// full length written and a nil error: log.Logger discards Write errors from
// Printf anyway, and reporting a short write would make it retry. Genuine sink
// failures are counted and surfaced via WriteErrors.
//
// The copy is mandatory, not defensive: log.Logger reuses one internal buffer
// across calls, so the bytes behind p are overwritten as soon as Write returns.
func (w *Writer) Write(p []byte) (int, error) {
	bp := w.pool.Get().(*[]byte)
	*bp = append((*bp)[:0], p...)

	select {
	case w.ch <- bp:
		return len(p), nil
	default:
	}

	// Queue full: the sink is saturated. Wait rather than discard — this is the
	// operator's record of what the gateway did. Blocking here is precisely the
	// pre-change behavior, so a saturated queue is never worse than the
	// synchronous write it replaced; every burst below queueDepth is now free.
	w.backpressure.Add(1)
	if w.warnedOnce.CompareAndSwap(false, true) {
		// Straight to stderr: routing this through the process logger would
		// re-enter the very queue that is saturated.
		fmt.Fprintln(os.Stderr, "WARN logsink: log queue saturated, callers now waiting on the log sink (further occurrences counted silently)")
	}
	select {
	case w.ch <- bp:
	case <-w.stop:
		// Shutdown raced this send; the drain goroutine has stopped consuming,
		// so waiting would hang the caller forever.
	}
	return len(p), nil
}

// Backpressure reports how many lines had to wait for room in the queue.
// Non-zero means the sink is not keeping up with the log rate and request
// latency is once again coupled to sink latency — the signal to move the log to
// a faster volume or raise the log level. No line is ever dropped, so this is a
// saturation gauge, not a loss counter.
func (w *Writer) Backpressure() int64 { return w.backpressure.Load() }

// WriteErrors reports how many lines failed to reach the destination writer.
func (w *Writer) WriteErrors() int64 { return w.writeErrors.Load() }

// Sync blocks until every line enqueued before the call has been flushed to the
// destination. It is the deterministic alternative to sleeping: shutdown uses
// Close (which drains), the fatal-exit path uses Sync, and tests that assert on
// sink contents call it.
//
// ONE deadline covers BOTH phases — reaching the drain goroutine and waiting for
// it to finish flushing — so a sink that wedges inside Flush cannot hang the
// caller forever. Returning without the guarantee is strictly better than
// deadlocking a shutdown hook.
func (w *Writer) Sync() {
	done := make(chan struct{})
	timer := time.NewTimer(closeTimeout)
	defer timer.Stop()
	select {
	case w.flushCh <- done:
	case <-w.done:
		return // drain goroutine already stopped; nothing can be pending
	case <-timer.C:
		return
	}
	select {
	case <-done:
	case <-w.done:
	case <-timer.C:
	}
}

// Close drains everything still queued, flushes it, and stops the drain
// goroutine. It does NOT close the destination writer — the caller owns that.
// Idempotent and safe to call concurrently with Write.
func (w *Writer) Close() error {
	w.closeOnce.Do(func() { close(w.stop) })
	// Bounded wait, for the same reason Sync's is bounded: the drain goroutine
	// may be parked inside a write(2) on a wedged volume, where closing stop
	// cannot reach it. Close runs from a shutdown hook, so an unbounded wait
	// would turn a hung log disk into a hung shutdown. On timeout we abandon the
	// goroutine — it is blocked on a sink we are done with.
	timer := time.NewTimer(closeTimeout)
	defer timer.Stop()
	select {
	case <-w.done:
	case <-timer.C:
		fmt.Fprintf(os.Stderr, "WARN logsink: drain did not stop within %v (sink wedged); abandoning it\n", closeTimeout)
	}
	return nil
}

// drainLoop is the single owner of the destination writer.
//
// Batching policy: write the line that woke us, then opportunistically take
// whatever else is already queued, then flush. The buffer is never held across
// a blocking wait, so an idle process sees no added visibility delay — the
// batch collapses to one line — while a backlogged one amortizes the syscall.
// One goroutine and one buffer also mean the sink stays strictly FIFO.
func (w *Writer) drainLoop(bw *bufio.Writer) {
	defer close(w.done)
	for {
		select {
		case bp := <-w.ch:
			w.buffer(bw, bp)
			w.flushBatch(bw, 1+w.drainPending(bw))
		case done := <-w.flushCh:
			w.flushBatch(bw, w.drainPending(bw))
			close(done)
		case <-w.stop:
			// Final drain: lines already queued must still reach the sink.
			w.flushBatch(bw, w.drainPending(bw))
			return
		}
	}
}

// drainPending buffers every line currently queued, returning how many it
// buffered. It never blocks.
func (w *Writer) drainPending(bw *bufio.Writer) int {
	n := 0
	for {
		select {
		case bp := <-w.ch:
			w.buffer(bw, bp)
			n++
		default:
			return n
		}
	}
}

// buffer copies one line into the write buffer and recycles its carrier.
// bufio.Writer latches errors, so a failure here is accounted at flush time and
// the line still counts as pending.
func (w *Writer) buffer(bw *bufio.Writer, bp *[]byte) {
	_, _ = bw.Write(*bp)
	if cap(*bp) <= maxPooledLine {
		w.pool.Put(bp)
	}
}

// flushBatch pushes the buffered lines to the sink. n is the number of lines in
// the buffer so a failed flush is charged per lost line, keeping WriteErrors a
// count of lines that did not reach the sink — the same meaning it had when
// every line was written individually.
func (w *Writer) flushBatch(bw *bufio.Writer, n int) {
	if n == 0 {
		return
	}
	if err := bw.Flush(); err != nil {
		w.writeErrors.Add(int64(n))
		if w.errLoggedOne.CompareAndSwap(false, true) {
			fmt.Fprintf(os.Stderr, "ERROR logsink: log write failed (further failures counted silently): %v\n", err)
		}
		// bufio latches its error; reset so the next batch is not poisoned by a
		// transient failure (a disk that recovers must resume logging).
		bw.Reset(w.dst)
	}
}
