// Package syslog forwards log lines to a remote syslog server over UDP or TCP.
// It is a self-contained leaf (stdlib only, no Culvert coupling) extracted from
// the flat package main per ADR-0002. The structured-entry writers take `any`
// (the entry is only JSON-marshalled) so the forwarder needn't know the
// concrete audit/request-log struct types.
//
// Two formats are supported:
//
//	RFC 3164 (BSD syslog) — legacy, accepted everywhere.
//	RFC 5424 (IETF syslog) — modern SIEMs prefer this for structured data,
//	  microsecond timestamps, and proper UTF-8 BOM handling.
//
// Priority: facility=1 (user-level), severity=6 (informational) → PRI=14.
// Audit events are sent at severity=5 (notice) → PRI=13.
//
// Delivery is ASYNCHRONOUS: senders format the line and enqueue it on a
// bounded channel; a single drain goroutine (started by NewWriter) owns the
// connection, the reconnect/backoff state machine, and every network write.
// The request path therefore never takes the connection mutex and never
// blocks on a socket — a slow or wedged TCP collector costs the caller a
// channel send, with overflow counted in Drops rather than propagated as
// proxy latency. Ordering is preserved (one drain goroutine).
package syslog

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Writer forwards log lines to a remote syslog server over UDP or TCP.
//
// A Writer built by NewWriter delivers asynchronously via queue/drainLoop; a
// zero-value Writer (tests build these directly) has a nil queue and falls
// back to the synchronous writeMsg path, so the delivery state machine stays
// directly testable.
type Writer struct {
	mu            sync.Mutex
	network       string
	addr          string
	conn          net.Conn
	host          string
	tag           string
	format        string    // "rfc3164" (default) or "rfc5424"
	pid           string    // cached PID string for RFC 5424 PROCID
	lastReconnErr time.Time // backoff: suppress reconnect attempts for 5s after failure
	drops         atomic.Uint64
	panics        atomic.Uint64
	panicObserver atomic.Pointer[func(recovered any)] // optional; see SetPanicObserver
	dialFunc      func() (net.Conn, error)            // test seam; nil = real dialer

	// CHAOS-72 delivery evidence. Drops alone is a CUMULATIVE counter with no
	// time axis: an operator reading "drops: 40213" cannot tell a collector
	// that is dark right now from one that healed last Tuesday, and every
	// health surface that wanted to answer "is the SIEM feed delivering?" had
	// nothing to read. These are the freshness half.
	//
	// All atomics, written only by the drain goroutine (or, for the queue-full
	// and post-Close cases, by the enqueuing caller), read by any surface.
	// There is deliberately NO combined snapshot lock: Stats reads them in the
	// order that can only ever UNDERSTATE health (failures before successes),
	// so a torn read never reports a dark feed as delivering.
	delivered       atomic.Uint64
	consecutiveFail atomic.Uint64
	lastSuccessNano atomic.Int64
	lastFailureNano atomic.Int64
	lastFailReason  atomic.Pointer[string]
	// failSinceNano stamps the FIRST loss of the current unresolved failure
	// episode (the drop that took consecutiveFail from 0 to 1). It is never
	// cleared; Stats reports it only while an episode is open, and never
	// earlier than the last success, so a stale stamp from a healed episode
	// cannot leak into a new one.
	failSinceNano atomic.Int64

	// deliveryObserver is the freshness seam; see SetDeliveryObserver.
	deliveryObserver atomic.Pointer[func(delivered bool)]

	// Async delivery plumbing (nil/zero on a zero-value Writer → synchronous).
	queue     chan queuedLine // formatted lines awaiting delivery (bounded at queueCap)
	stop      chan struct{}   // closed by Close; tells drainLoop to flush and exit
	done      chan struct{}   // closed by drainLoop on exit (conn released)
	closed    atomic.Bool     // post-Close sends drop (or hand off) instead of enqueueing
	closeOnce sync.Once

	// sendMu makes "check closed, then enqueue" atomic with respect to Close.
	// Senders hold it SHARED for that check-and-enqueue only (never across a
	// network write); Close takes it EXCLUSIVELY to flip closed. Without it a
	// caller that loaded this Writer just before a runtime re-point could pass
	// the closed check, lose the CPU, and enqueue after the drain goroutine's
	// final flush had already returned — a line stranded in a queue nobody
	// reads, not even counted as a drop.
	sendMu sync.RWMutex

	// successor is the Writer that replaced this one (HandOffTo). Once set, a
	// line that arrives after Close, and every line still queued when the
	// drain goroutine stops, is re-routed to it rather than dropped against —
	// or delivered to — the collector the operator has just replaced. That
	// keeps the loss accounting on the LIVE writer every health surface reads.
	successor atomic.Pointer[Writer]
}

// maxHandoffHops bounds how far a line follows successor links (a run of
// back-to-back re-points). Past it the line is dropped and counted.
const maxHandoffHops = 8

// enqueueResult is the outcome of one tryEnqueue.
type enqueueResult int

const (
	enqAccepted enqueueResult = iota // queued for the drain goroutine
	enqDropped                       // queue full; already counted as a drop
	enqClosed                        // writer closed; NOT counted — caller decides
)

// queuedLine is one formatted line awaiting delivery.
//
// ack is nil for ordinary traffic — the overwhelmingly common case, and the
// reason this is a struct rather than a parallel channel. When non-nil (a
// connectivity probe) the drain goroutine reports the outcome of THIS line on
// it, exactly once. Inferring a probe's outcome from writer-wide counters is
// not equivalent and was the pre-review shape: on a gateway with concurrent
// traffic another line's delivery lands between the before-snapshot and the
// read, so the probe reports success for someone else's line while its own is
// still queued behind a collector that is about to drop it.
//
// format, hdr and at let a HANDOFF re-encode the line: a runtime re-point may
// also change the wire format, and a line formatted for the displaced writer
// (RFC 3164) must not reach a successor configured for RFC 5424 — or vice
// versa — where the collector would reject or misparse it while the successor
// counted it delivered (Codex review, PR #1494). The message body is recovered
// as line[hdr:len(line)-1], a substring sharing the line's memory, so the
// queue's footprint does not double; at preserves the EVENT time across the
// re-encode.
type queuedLine struct {
	line   string
	ack    chan bool // buffered(1) when set; receives true iff THIS line was delivered
	format string    // the format line is encoded in
	pri    int
	hdr    int       // byte offset of the message body within line
	at     time.Time // event time the line was stamped with
}

// forWriter returns the line re-encoded for w when w's wire format differs
// from the one it was formatted in; otherwise the item unchanged.
func (item queuedLine) forWriter(w *Writer) queuedLine {
	wf := w.format
	if wf != "rfc5424" {
		wf = "rfc3164"
	}
	if item.format == "" || item.format == wf || item.hdr <= 0 || item.hdr >= len(item.line) {
		return item
	}
	msg := item.line[item.hdr : len(item.line)-1]
	re := w.formatLine(item.pri, msg, item.at)
	re.ack = item.ack
	return re
}

// queueCap bounds the async delivery queue. At a formatted line of ~0.5 KB the
// worst-case queue memory is ~1 MB; past this the collector is slower than the
// entry rate and lines drop (counted) rather than backpressure the proxy.
const queueCap = 2048

// flushTimeout bounds the final drain on Close: queued lines are delivered
// while within the window, then counted as drops. Keeps shutdown from paying
// queueCap × writeTimeout against a wedged collector.
const flushTimeout = 1 * time.Second

// closeWait bounds how long Close waits for the drain goroutine to finish its
// flush. Generous enough for the flush window plus one in-flight write; a
// fully wedged collector cycle can outlast it, in which case Close returns and
// the goroutine releases the connection itself when the write deadline fires.
const closeWait = flushTimeout + writeTimeout + time.Second

// NewWriter dials the syslog server and returns a ready Writer.
// format selects the wire format: "rfc3164" (default) or "rfc5424".
func NewWriter(network, addr, format string) (*Writer, error) {
	host, err := os.Hostname()
	if err != nil {
		host = "culvert"
	}
	if format == "" {
		format = "rfc3164"
	}
	sw := &Writer{
		network: network,
		addr:    addr,
		host:    host,
		tag:     "culvert",
		format:  format,
		pid:     fmt.Sprintf("%d", os.Getpid()),
	}
	if err := sw.connect(); err != nil {
		return nil, fmt.Errorf("syslog connect %s://%s: %w", network, addr, err)
	}
	sw.startAsync()
	return sw, nil
}

// startAsync arms the bounded queue and starts the drain goroutine. Split from
// NewWriter so tests can build a Writer with an injected conn/dialFunc and
// still exercise the production async path.
func (s *Writer) startAsync() {
	s.queue = make(chan queuedLine, queueCap)
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	go s.drainLoop()
}

// drainLoop is the single delivery goroutine: it owns every network write (and
// therefore every s.mu hold of meaningful duration). On stop it flushes what
// is already queued within flushTimeout, counts the remainder as drops, and
// releases the connection.
func (s *Writer) drainLoop() {
	defer func() {
		s.mu.Lock()
		if s.conn != nil {
			s.conn.Close() //nolint:errcheck // best-effort release on exit
			s.conn = nil
		}
		s.mu.Unlock()
		close(s.done)
	}()
	for {
		select {
		case item := <-s.queue:
			// Once a successor is named, a dequeued line belongs to it even on
			// this branch: Close readies `stop` while lines are still queued and
			// select picks uniformly, so without this check queued events could
			// still reach the collector being replaced (Codex review, PR #1494).
			if s.successor.Load() != nil && s.handOffQueued(item) {
				continue
			}
			s.deliverTracked(item)
		case <-s.stop:
			deadline := time.Now().Add(flushTimeout)
			for {
				select {
				case item := <-s.queue:
					if s.handOffQueued(item) {
						continue
					}
					if time.Now().Before(deadline) {
						s.deliverTracked(item)
					} else {
						s.noteDrop(&reasonFlushTimeout)
						ackQueued(item, false)
					}
				default:
					return
				}
			}
		}
	}
}

// send formats one message and hands it to the drain goroutine without ever
// blocking: a full queue (collector slower than the entry rate) or a closed
// Writer counts a drop instead. Formatting happens here so the syslog
// timestamp is the EVENT time, not the (possibly later) delivery time. A
// zero-value Writer (no queue) delivers synchronously — the pre-async
// behavior, kept for the direct writeMsg tests.
//
// A caller that loaded this Writer just before a runtime re-point may reach
// here after it was closed; the line then follows the successor link to the
// Writer that replaced it (formatted in THAT writer's format) instead of being
// dropped invisibly against a displaced writer no surface reads any more.
func (s *Writer) send(pri int, msg string) {
	if s.queue == nil {
		s.writeMsg(pri, msg)
		return
	}
	w := s
	for hop := 0; hop < maxHandoffHops; hop++ {
		if w.tryEnqueue(w.formatLine(pri, msg, time.Now())) != enqClosed {
			return
		}
		nx := w.successor.Load()
		if nx == nil || nx.queue == nil {
			break
		}
		w = nx
	}
	w.noteDrop(&reasonClosed)
}

// tryEnqueue hands one formatted line to the drain goroutine without
// blocking. A full queue is counted here; a closed writer is NOT, so the
// caller can hand the line off instead.
func (s *Writer) tryEnqueue(item queuedLine) enqueueResult {
	s.sendMu.RLock()
	defer s.sendMu.RUnlock()
	if s.closed.Load() {
		return enqClosed
	}
	select {
	case s.queue <- item:
		return enqAccepted
	default:
		s.noteDrop(&reasonQueueFull)
		return enqDropped
	}
}

// enqueue hands one formatted line to the drain goroutine without blocking.
// Reports whether it was accepted; a rejected line is already counted.
func (s *Writer) enqueue(item queuedLine) bool {
	switch s.tryEnqueue(item) {
	case enqAccepted:
		return true
	case enqClosed:
		s.noteDrop(&reasonClosed)
	}
	return false
}

// handOffQueued re-routes one line still queued on a displaced Writer to its
// successor chain. Reports whether the line has been DEALT WITH — accepted by
// some successor, or lost and counted on the way. A line no successor accepts
// is counted (on the last writer tried) and its prober, if any, told it was
// not delivered.
//
// It reports false for exactly one reason: this Writer names no successor at
// all, so the line is still the caller's to deliver.
//
// It must never report false once a successor IS named. Both drainLoop
// callers read false as "no handoff" and fall through to deliverTracked,
// which writes through THIS writer's own connection — the collector the
// operator has already replaced. The hop bound used to exit that way, so a
// queue surviving more than maxHandoffHops rapid re-points sent security
// events to the displaced collector while the bound's stated contract was to
// drop and count them (Codex P2, PR #1494). Exhausting the bound is a LOSS,
// and a loss is recorded, not quietly redirected backwards.
func (s *Writer) handOffQueued(item queuedLine) bool {
	w := s.successor.Load()
	if w == nil {
		return false
	}
	for hop := 0; w != nil && w.queue != nil && hop < maxHandoffHops; hop++ {
		switch w.tryEnqueue(item.forWriter(w)) {
		case enqAccepted:
			return true
		case enqDropped:
			ackQueued(item, false)
			return true // counted on the live writer by tryEnqueue
		}
		nx := w.successor.Load()
		if nx == nil {
			w.noteDrop(&reasonClosed)
			ackQueued(item, false)
			return true
		}
		w = nx
	}
	// The chain was named but could not be walked to a writer that would take
	// the line — the hop bound, or a successor with no queue. Charged to this
	// writer under the existing `closed` class rather than a new one: the
	// outcome and the operator's remedy are identical to the end-of-chain
	// branch above (events were lost across a re-point and are not replayed),
	// and the reason vocabulary is a closed set on a published API enum that
	// should not grow to name an internal walk limit.
	s.noteDrop(&reasonClosed)
	ackQueued(item, false)
	return true
}

// HandOffTo records next as the Writer that replaces s. Call it BEFORE Close:
// from then on a send that races the close, and every line still queued when
// the drain goroutine stops, goes to next rather than being dropped against
// (or delivered to) the collector being replaced. nil or s itself is ignored.
func (s *Writer) HandOffTo(next *Writer) {
	if next == nil || next == s {
		return
	}
	s.successor.Store(next)
}

// ackQueued reports one line's outcome to a waiting prober. The channel is
// buffered(1) and written exactly once, so this never blocks the drain
// goroutine even if the prober has already given up and stopped listening.
func ackQueued(item queuedLine, delivered bool) {
	if item.ack == nil {
		return
	}
	select {
	case item.ack <- delivered:
	default:
	}
}

// deliverTracked delivers one queued line and, when the line carries an ack,
// reports the outcome OF THAT LINE.
//
// The delivered-counter delta is exact here and only here: the drain goroutine
// is the sole writer of that counter, and it is inside this call that the one
// line is attempted. The same comparison made by a caller OUTSIDE this
// goroutine is not exact, which is precisely the defect this replaces.
func (s *Writer) deliverTracked(item queuedLine) {
	if item.ack == nil {
		s.deliverGuarded(item.line)
		return
	}
	before := s.delivered.Load()
	s.deliverGuarded(item.line)
	ackQueued(item, s.delivered.Load() > before)
}

// WriteProbe enqueues one message and returns a channel that receives the
// delivery outcome OF THAT MESSAGE, once, from the drain goroutine.
//
// Returns ok=false when the line could not even be queued (writer closed, or
// the collector is so far behind that the queue is full) — already counted as
// a drop, and an outcome in its own right. A zero-value Writer has no drain
// goroutine, so it reports the synchronous result directly.
//
// The caller must bound its own wait: a wedged collector can hold the drain in
// a write deadline, and nothing here promises when the answer arrives.
func (s *Writer) WriteProbe(msg string) (<-chan bool, bool) {
	ack := make(chan bool, 1)
	if s.queue == nil { // zero-value Writer: synchronous path
		before := s.delivered.Load()
		s.writeMsg(14, msg)
		ack <- s.delivered.Load() > before
		return ack, true
	}
	item := s.formatLine(14, msg, time.Now())
	item.ack = ack
	if !s.enqueue(item) {
		return nil, false
	}
	return ack, true
}

func (s *Writer) connect() error {
	if s.dialFunc != nil {
		conn, err := s.dialFunc()
		if err != nil {
			return err
		}
		s.conn = conn
		return nil
	}
	// Background context + 5s Timeout is equivalent to the prior DialTimeout,
	// in the DialContext form the house lint rules require (CLAUDE.md).
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(context.Background(), s.network, s.addr)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// Write implements io.Writer. Each call is a single syslog message at PRI=14.
func (s *Writer) Write(p []byte) (int, error) {
	s.send(14, strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

// WriteAudit sends a structured audit entry as a JSON syslog message at
// severity=5 (notice), which most SIEMs map to a security-relevant priority.
// The entry is only JSON-marshalled, so any serializable value is accepted.
func (s *Writer) WriteAudit(e any) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.send(13, string(b)) // PRI=13: facility=1 severity=5 (notice)
}

// WriteRequest sends a structured request-log entry as a JSON syslog message at
// PRI=14 (facility=1 user-level, severity=6 informational).
func (s *Writer) WriteRequest(e any) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.send(14, string(b)) // PRI=14: facility=1 severity=6 (informational)
}

// formatMsg builds a syslog line in the configured format.
func (s *Writer) formatMsg(pri int, msg string) string {
	return s.formatLine(pri, msg, time.Now()).line
}

// formatLine builds a syslog line in the configured format, stamped with the
// event time at, and records where the message body starts so a handoff can
// re-encode it for a successor with a different format.
func (s *Writer) formatLine(pri int, msg string, at time.Time) queuedLine {
	var hdr string
	format := s.format
	switch format {
	case "rfc5424":
		// RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
		hdr = fmt.Sprintf("<%d>1 %s %s %s %s - - ", pri, at.Format(time.RFC3339Nano), s.host, s.tag, s.pid)
	default: // rfc3164
		format = "rfc3164"
		hdr = fmt.Sprintf("<%d>%s %s %s: ", pri, at.Format("Jan 02 15:04:05"), s.host, s.tag)
	}
	return queuedLine{line: hdr + msg + "\n", format: format, pri: pri, hdr: len(hdr), at: at}
}

// writeTimeout bounds each conn write: a TCP collector that accepts but stops
// draining (SIEM overload, half-open peer) would otherwise fill the kernel
// send buffer and block fmt.Fprint forever — while holding s.mu, stalling
// every request/audit-log caller proxy-wide.
const writeTimeout = 5 * time.Second

// writeLine sends one formatted line on the current conn with the write
// deadline armed. Caller must hold s.mu and guarantee s.conn is non-nil.
func (s *Writer) writeLine(line string) error {
	s.conn.SetWriteDeadline(time.Now().Add(writeTimeout)) //nolint:errcheck // best-effort; a failed deadline set surfaces on the write itself
	_, err := fmt.Fprint(s.conn, line)
	return err
}

// writeMsg formats and delivers one message synchronously. Production traffic
// reaches deliverLine via the drain goroutine instead; this remains the
// zero-value-Writer path and the unit under the deadline/backoff tests.
func (s *Writer) writeMsg(pri int, msg string) {
	s.deliverLine(s.formatMsg(pri, msg))
}

// deliverLine sends one pre-formatted line, holding s.mu across the write and
// the reconnect/backoff state machine. Only the drain goroutine (or a
// zero-value Writer's caller) enters here, so the mutex no longer serializes
// request goroutines — it now only fences deliverLine against Close/Format.
// deliverGuarded contains a panic raised while delivering one line.
//
// CHAOS-24: this drain goroutine is the sole owner of the collector socket, so
// an unrecovered panic here would terminate the whole in-line gateway over a
// SIEM write. Containment is per LINE, never per goroutine — an exited drain
// would silently strand every subsequent line in the queue. A panicked line is
// counted as a drop, which is exactly what it is (the line never reached the
// collector) and keeps it visible through the existing Drops() surface, plus a
// dedicated Panics() counter so a recurring formatting bug is distinguishable
// from ordinary collector-down drops.
//
// The guard is deliberately local (no obs import): this package is a
// self-contained stdlib-only leaf per its header contract, and deliverLine
// releases s.mu through a defer, so unwinding never leaves the mutex held.
// The recovered value is forwarded to the optional panicObserver (see
// SetPanicObserver) rather than logged here, for the same no-obs-import
// reason — without an observer wired, a recovered panic is visible only
// through Panics().
func (s *Writer) deliverGuarded(line string) {
	defer func() {
		if r := recover(); r != nil {
			s.panics.Add(1)
			s.noteDrop(&reasonPanic)
			if p := s.panicObserver.Load(); p != nil {
				func() {
					defer func() { _ = recover() }() // an observer must never crash the drain goroutine
					(*p)(r)
				}()
			}
		}
	}()
	s.deliverLine(line)
}

// SetPanicObserver publishes an optional observer notified synchronously, on
// the drain goroutine, whenever deliverGuarded recovers a panic. This package
// is a stdlib-only leaf with no logging dependency (see the package doc), so
// without an observer a recovered panic is visible only through Panics() —
// package main wires this to the process log (mirrors fileutil's and
// internal/audit's SetWriteFailureObserver, the same leaf-package-can't-log
// seam applied to a second chokepoint). A nil fn clears it. The observer runs
// AFTER deliverLine's own deferred mutex unlock has already fired during
// unwind, so it never needs s.mu, and is itself panic-contained so a bad
// observer can never take down delivery.
func (s *Writer) SetPanicObserver(fn func(recovered any)) {
	if fn == nil {
		s.panicObserver.Store(nil)
		return
	}
	s.panicObserver.Store(&fn)
}

func (s *Writer) deliverLine(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		// Backoff: don't retry more often than every 5 seconds.
		if time.Since(s.lastReconnErr) < 5*time.Second {
			s.noteDrop(&reasonBackoff)
			return
		}
		if err := s.connect(); err != nil {
			s.lastReconnErr = time.Now()
			s.noteDrop(&reasonConnectFail)
			return // syslog down — swallow, never block the proxy
		}
		s.lastReconnErr = time.Time{} // reset on success
	}
	// The instant the write is ATTEMPTED, not the instant noteDelivered runs.
	// A queue-full drop lands on the CALLER's goroutine, so one can be stamped
	// between the write returning and the success being recorded; stamping the
	// success at the later instant made it NEWER than that drop, and Stats
	// refuses to date an episode whose start predates the last success — so
	// the surviving failure became permanently undatable and the row printed
	// "FAILING NOW ... failing for 0s" forever (Codex P1, PR #1494).
	//
	// Taken before the write, any concurrent drop's own timestamp necessarily
	// exceeds it, which is what makes the re-date in noteDelivered race-free.
	// Under-stating a success by the duration of one write is the fail-SAFE
	// direction: it can only make the feed look staler than it is.
	successAt := now().UnixNano()
	if err := s.writeLine(line); err != nil {
		s.conn.Close() //nolint:errcheck // best-effort release of a conn we are discarding
		s.conn = nil
		if time.Since(s.lastReconnErr) < 5*time.Second {
			s.noteDrop(&reasonBackoff)
			return
		}
		if err2 := s.connect(); err2 != nil {
			s.lastReconnErr = time.Now()
			s.noteDrop(&reasonConnectFail)
			return
		}
		successAt = now().UnixNano()
		if err3 := s.writeLine(line); err3 != nil {
			// A collector that ACCEPTS connections but never drains would
			// otherwise reset the backoff on every call (connect succeeds,
			// write times out), taxing every log caller up to
			// writeTimeout + dial (5s) + writeTimeout — three serialized
			// network ops (~15s worst case) under s.mu. Arm the backoff so
			// subsequent calls fast-drop for the window instead.
			s.conn.Close() //nolint:errcheck // best-effort release of a conn we are discarding
			s.conn = nil
			s.lastReconnErr = time.Now()
			s.noteDrop(&reasonWriteFail)
			return
		}
		s.lastReconnErr = time.Time{}
	}
	// Reached only when a write returned without error: the first attempt, or
	// the retry after a successful reconnect. Recorded LAST so no path can
	// report a delivery it did not make.
	//
	// The failure count is read HERE, after the write COMPLETED, and not at
	// function entry. noteDelivered clears exactly this count and no more, so
	// the boundary decides which losses a delivery is allowed to resolve:
	//
	//   - a drop recorded BEFORE this write completed happened while the
	//     collector was demonstrably still accepting bytes. It is a real
	//     compliance loss and stays counted in Drops, but it is NOT evidence
	//     the feed is down, and letting it survive made a node that then went
	//     idle report DOWN five minutes later off the back of a delivery that
	//     had SUCCEEDED (Codex P1, PR #1494).
	//   - a drop recorded AFTER completion is not resolved by this delivery,
	//     so the compare-and-swap inside noteDelivered fails and it survives —
	//     the round-6 property, unchanged.
	//
	// Reading at entry instead was justified by "retaining it costs nothing,
	// the delivery resets the age half of the predicate either way". That was
	// true until round 7 made a surviving failure DATABLE: a datable failure
	// can outlast the window on its own, so retaining one now costs a false
	// page. A later change can invalidate an earlier change's stated
	// rationale — when it does, the rationale has to be re-read, not inherited.
	//
	// RESIDUAL, recorded rather than closed (SL-4, Codex P2 round 9). The few
	// instructions between writeLine RETURNING and this Load are an
	// unsynchronised window: a drop landing there is counted in failuresBefore
	// and therefore resolved, although by the rule above it arrived after
	// completion and should survive. Three facts make that acceptable:
	//
	//   - only ONE drop class can land there. deliverLine holds s.mu for its
	//     whole body, so every drain-goroutine drop (connect_failed,
	//     write_failed, backoff) is serialised with this read. Only a
	//     queue-full drop from a caller goroutine (tryEnqueue holds sendMu
	//     alone) can race it.
	//   - a queue-full drop microseconds after a successful write is LOCAL
	//     backpressure, not a dark collector — so "resolved" is the correct
	//     verdict for it, the same one this boundary deliberately assigns to a
	//     drop during the write.
	//   - closing it needs the queue-full path to take s.mu, which would park
	//     request goroutines behind this goroutine's blocking write. That is
	//     the latency coupling the whole async design exists to prevent: a
	//     slow SIEM must cost drops, not proxy latency.
	//
	// A genuine outage is unaffected: its drops come from FAILED writes on the
	// drain goroutine, there is no success to resolve them, and degradation
	// proceeds normally.
	failuresBefore := s.consecutiveFail.Load()
	s.noteDelivered(failuresBefore, successAt)
}

// Bounded reason classes for a delivery failure.
//
// A reason reaches an alert Detail and an operator-contract row, so it must be
// a CLOSED SET, never a raw error string: the transport error embeds the
// collector address (and for a dial failure the ephemeral local port), and the
// alert store dedups on event+Detail — a per-failure-unique reason defeats the
// dedup window by construction and evicts real alerts from the bounded retry
// queue. That is the WK-12/RS-5 defect, recorded twice already in this tree.
// The verbose cause stays in the process log.
const (
	ReasonQueueFull    = "queue_full"     // the collector is slower than the entry rate
	ReasonClosed       = "closed"         // send after Close
	ReasonConnectFail  = "connect_failed" // dial to the collector failed
	ReasonWriteFail    = "write_failed"   // the socket write failed or timed out
	ReasonBackoff      = "backoff"        // fast-dropped inside the reconnect backoff window
	ReasonPanic        = "panic"          // a recovered panic in the drain goroutine
	ReasonFlushTimeout = "flush_timeout"  // still queued when Close's flush window expired
)

// Pre-allocated so noteDrop stores a pointer to an existing string rather than
// boxing one per failure: this runs on the drain goroutine while the collector
// is down, which is exactly when the line rate is highest.
var (
	reasonQueueFull    = ReasonQueueFull
	reasonClosed       = ReasonClosed
	reasonConnectFail  = ReasonConnectFail
	reasonWriteFail    = ReasonWriteFail
	reasonBackoff      = ReasonBackoff
	reasonPanic        = ReasonPanic
	reasonFlushTimeout = ReasonFlushTimeout
)

// now is the clock seam; tests drive freshness deterministically.
//
// Held atomically rather than as a plain var: it is read on the DRAIN
// GOROUTINE (noteDelivered / noteDrop) while a test replaces it from the test
// goroutine, which as a bare function value is a data race the delivery-plane
// gate catches under -race. The nil case is the production path and costs one
// atomic load.
var nowFn atomic.Pointer[func() time.Time]

func now() time.Time {
	if p := nowFn.Load(); p != nil {
		return (*p)()
	}
	return time.Now()
}

// noteDrop charges one lost line against the cumulative counter AND the
// freshness axis. Every drop site goes through here so a future one cannot be
// added that moves Drops() without moving the reason and the timestamp — the
// split that made the cumulative counter unreadable in the first place.
func (s *Writer) noteDrop(reason *string) {
	s.drops.Add(1)
	t := now().UnixNano()
	if s.consecutiveFail.Add(1) == 1 {
		s.failSinceNano.Store(t)
	} else if s.failSinceNano.Load() <= s.lastSuccessNano.Load() {
		// The count was already non-zero, so this is not the 0->1 edge — but
		// the recorded start predates the last delivery, which means it
		// belongs to an episode a delivery already ENDED and is being carried
		// by a failure that survived noteDelivered's compare-and-swap (a drop
		// that raced a successful write). Without this branch that episode can
		// never be dated: Stats refuses a start older than the last success,
		// and no later drop takes the 0->1 edge, so a real outage beginning at
		// that instant would stay undatable and therefore un-degradable
		// FOREVER. Re-stamping to now is accurate to within the race window
		// and is the only write-side place with enough information to do it.
		s.failSinceNano.Store(t)
	}
	s.lastFailureNano.Store(t)
	s.lastFailReason.Store(reason)
	s.notifyDelivery(false)
}

// noteDelivered records one line that reached the socket.
//
// On TCP that means the collector's kernel accepted the bytes. On UDP it means
// only that THIS kernel accepted them for transmission — a connected UDP socket
// surfaces an ICMP port-unreachable on a LATER write, and a collector that is
// silently discarding datagrams surfaces nothing at all. Every surface built on
// this counter therefore makes a strictly weaker claim on UDP, and says so.
// failuresBefore is the consecutive-failure count observed BEFORE this
// delivery was attempted, and it is what makes the clear safe.
//
// An unconditional Swap(0) erased any failure recorded while the write was in
// flight: queue-full drops run `noteDrop` on the CALLER's goroutine (see
// tryEnqueue, which holds only sendMu), so one can land between this
// delivery's write and its clear. The swap then discarded a loss that happened
// AFTER the successful write and emitted a recovery notification for an
// episode that had not ended — and if traffic then stopped, the watchdog saw
// zero consecutive failures forever, so the lost event could never degrade the
// feed (Codex P1, PR #1494).
//
// A compare-and-swap clears only the exact count this delivery observed, so a
// concurrent drop makes the CAS fail and the failure survives — the fail-SAFE
// direction. The recovery notification fires only when the CAS succeeded,
// which is what makes it mean "this delivery ended that episode" rather than
// "a delivery happened".
//
// successAt is when the write was ATTEMPTED (see deliverLine). Recording a
// surviving failure is only half the job: its episode START must also remain
// datable, or the failure is retained as a number nobody can act on. Two
// separate interleavings leave a start that predates this success —
//
//   - the racing drop took the 0->1 edge, so it stamped its own start while
//     this delivery was in flight; and
//   - the CAS FAILED against an older, ongoing episode, which this delivery
//     has just ended — the survivor belongs to a new episode, not that one.
//
// Stats refuses to date either (a start older than the last success is, by
// construction, not this episode's), and no later drop takes the 0->1 edge to
// correct it, so without the re-date below a real outage beginning at that
// instant would stay undatable and therefore un-degradable FOREVER: the
// contract row prints "FAILING NOW ... failing for 0s" for as long as the
// node stays quiet, and the watchdog can never escalate it (Codex P1,
// PR #1494).
//
// Re-dating to successAt is the honest answer — the loss is known to have
// happened after this write — and it is race-free BECAUSE successAt precedes
// the write: a concurrent drop's own timestamp is necessarily later, so
// whichever of the two stores lands last leaves a datable start.
func (s *Writer) noteDelivered(failuresBefore uint64, successAt int64) {
	s.delivered.Add(1)
	s.lastSuccessNano.Store(successAt)
	// CAS, not Swap: see above. It also keeps the property the Swap was
	// chosen for — two deliveries racing one episode cannot both observe it
	// as non-zero, so a recovery signal can never fire twice.
	if failuresBefore > 0 && s.consecutiveFail.CompareAndSwap(failuresBefore, 0) {
		s.notifyDelivery(true)
		return
	}
	if s.consecutiveFail.Load() > 0 && s.failSinceNano.Load() <= successAt {
		s.failSinceNano.Store(successAt)
	}
}

// SetDeliveryObserver publishes an optional observer notified on the drain
// goroutine whenever a line is DROPPED, and once more when a delivery ends a
// failure episode. A nil fn clears it.
//
// This is the same seam, for the same reason, as SetPanicObserver above: this
// package is a stdlib-only leaf per its header contract and cannot log, alert
// or hold a timer, so the freshness plane lives in package main
// (syslog_health.go) and is driven from here.
//
// The asymmetry is deliberate and is a cost decision. The observer is NOT
// called on an ordinary successful delivery: that is the steady state of a
// gateway forwarding one request-log line per proxied request, and a callback
// there would tax the happy path to observe a fault that is not happening. On
// the failure side the cost is irrelevant — the line is already lost — and
// per-drop notification is what lets the plane decide degradation on a
// DURATION without polling and without a goroutine of its own.
//
// An observer must be cheap, must not block, and must never call back into
// this Writer (send, Close, Stats are all reachable from the drain goroutine's
// own stack) — the rule audit.SetWriteFailureObserver carries for the same
// reason. It is panic-contained so a bad observer can never take down
// delivery.
func (s *Writer) SetDeliveryObserver(fn func(delivered bool)) {
	if fn == nil {
		s.deliveryObserver.Store(nil)
		return
	}
	s.deliveryObserver.Store(&fn)
}

func (s *Writer) notifyDelivery(ok bool) {
	p := s.deliveryObserver.Load()
	if p == nil {
		return
	}
	defer func() { _ = recover() }() // an observer must never crash the drain goroutine
	(*p)(ok)
}

// Stats is a point-in-time snapshot of delivery health.
type Stats struct {
	Delivered           uint64
	Drops               uint64
	Panics              uint64
	ConsecutiveFailures uint64
	QueueDepth          int
	QueueCap            int
	// LastSuccess is zero when no line has EVER been delivered by this Writer.
	// That case is distinct from "delivered a while ago" and the surfaces
	// treat it as such: a feed that has never delivered was misconfigured or
	// pointed at a dead collector from the start.
	LastSuccess time.Time
	LastFailure time.Time
	// FailingSince is when the CURRENT unresolved failure episode began — the
	// first loss after the last delivery. Zero when ConsecutiveFailures is 0.
	// A duration-based degradation predicate must be timed from here, not
	// from LastSuccess: a feed idle for an hour whose next line happens to
	// drop has been failing for zero seconds, not for an hour.
	FailingSince time.Time
	// LastFailureReason is one of the Reason* constants, or "" before the
	// first failure. Never a raw error.
	LastFailureReason string
}

// DeliveryProvable reports whether this Writer's transport can give evidence
// that the collector received a line.
//
// TCP can: a write that returns without error means the peer's kernel accepted
// the bytes. UDP cannot — a write to a connected UDP socket almost always
// succeeds whether or not anything is listening — so a `Delivered` on a UDP
// Writer means only "this host sent the datagram" (register row SL-1).
//
// It is a property of the WRITER, read off the transport it was constructed
// with, deliberately not re-derived from an address string held elsewhere. The
// probe used to classify its own acknowledged send by re-reading the health
// record's `target` AFTER the Writer had been passed in, so an admin re-point
// landing between the two made it describe a UDP send with TCP wording — "the
// collector accepted the test event" — for a datagram nothing may have
// received (Codex P2, PR #1494). The writer that served the line is the only
// thing that knows how it was sent.
func (s *Writer) DeliveryProvable() bool { return s.network == "tcp" }

// Stats snapshots the delivery counters.
//
// Read order is deliberate and is the only consistency guarantee offered: the
// FAILURE side is read before the SUCCESS side, so a snapshot taken across a
// concurrent delivery can report a stale failure next to a fresh success
// (harmless — reports healthy slightly late) but can never report a fresh
// success next to a stale failure (which would report a dark feed as
// delivering). A lock is deliberately not taken: Stats is reached from
// /metrics, /healthz and the diagnostics row, and none of them may contend
// with the drain goroutine's socket writes.
func (s *Writer) Stats() Stats {
	st := Stats{
		Drops:               s.drops.Load(),
		Panics:              s.panics.Load(),
		ConsecutiveFailures: s.consecutiveFail.Load(),
		QueueCap:            cap(s.queue),
		QueueDepth:          len(s.queue),
	}
	if p := s.lastFailReason.Load(); p != nil {
		st.LastFailureReason = *p
	}
	if n := s.lastFailureNano.Load(); n > 0 {
		st.LastFailure = time.Unix(0, n)
	}
	fs := s.failSinceNano.Load()
	st.Delivered = s.delivered.Load()
	ls := s.lastSuccessNano.Load()
	if ls > 0 {
		st.LastSuccess = time.Unix(0, ls)
	}
	// An episode's start is never earlier than the delivery that ENDED the
	// previous one, because noteDelivered resets the failure count. So
	// observing `ConsecutiveFailures > 0` together with `failSince < lastSuccess`
	// means the start belongs to an episode that is already over, and the
	// CURRENT episode's start has not been published yet.
	//
	// noteDrop is called from the CALLER's goroutine on a queue-full drop, so
	// several request goroutines reach it at once: the one whose increment
	// returns 1 can be descheduled between `consecutiveFail.Add(1)` and
	// `failSinceNano.Store(t)` while another increments to 2 and invokes the
	// observer, which lands here.
	//
	// This used to CLAMP the stale start up to lastSuccess, which is where the
	// harm was: on a node that had been quiet since its last delivery, a
	// brand-new episode was then dated from that delivery and could be older
	// than the degradation window on its very first drop — an immediate false
	// DOWN page (Codex P1, PR #1494). Refusing to date the episode at all is
	// the fail-SAFE reading of the same evidence: we genuinely do not know when
	// it started, and the consumer's predicate requires a known start, so it
	// declines to page. The real start lands microseconds later, and the
	// watchdog re-evaluates every 30s regardless, so nothing is suppressed
	// beyond that window.
	if st.ConsecutiveFailures > 0 && fs > 0 && fs >= ls {
		st.FailingSince = time.Unix(0, fs)
	}
	return st
}

// Drops reports the number of messages dropped because the collector was
// unreachable or not draining, the delivery queue overflowed, or the Writer
// was already closed. Monotonic per Writer.
//
// This is a CUMULATIVE count with no time axis and is therefore not, on its
// own, an answer to "is the feed delivering right now?" — use Stats, which
// pairs it with the last-success timestamp and the bounded failure reason.
func (s *Writer) Drops() uint64 { return s.drops.Load() }

// Panics reports how many lines were lost to a recovered panic in the drain
// goroutine (CHAOS-24). Always 0 in a healthy process; a non-zero value means
// a delivery bug is being contained rather than crashing the gateway.
func (s *Writer) Panics() uint64 { return s.panics.Load() }

// Close stops the drain goroutine (flushing already-queued lines within
// flushTimeout) and releases the connection. Idempotent; concurrent sends
// after Close count as drops. On an async Writer the connection is owned and
// released by the drain goroutine; Close waits up to closeWait for it — if a
// wedged collector outlasts even that, Close returns and the goroutine
// releases the conn when its write deadline fires.
func (s *Writer) Close() error {
	if s.queue == nil { // zero-value Writer: no goroutine, close directly
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.conn != nil {
			err := s.conn.Close()
			s.conn = nil
			return err
		}
		return nil
	}
	// Exclusive: once this returns, no sender can be between its closed
	// check and its enqueue, so nothing lands in the queue after the drain
	// goroutine's final flush.
	s.sendMu.Lock()
	s.closed.Store(true)
	s.sendMu.Unlock()
	s.closeOnce.Do(func() { close(s.stop) })
	select {
	case <-s.done:
	case <-time.After(closeWait):
	}
	return nil
}

// Format returns the syslog message format ("rfc3164" or "rfc5424").
func (s *Writer) Format() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.format
}
