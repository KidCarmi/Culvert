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
	// deliveryObserver is notified EDGE-WISE about delivery outcomes; see
	// SetDeliveryObserver. Separate from panicObserver because the two answer
	// different questions (a panicked line is a code defect, a dropped line is
	// an infrastructure fault) and an operator acts on them differently.
	deliveryObserver atomic.Pointer[func(ok bool, reason string, consecutive int64)]
	dialFunc         func() (net.Conn, error) // test seam; nil = real dialer

	// Delivery accounting (CHAOS-66). Drops() alone answers "how many lines
	// were lost" and nothing else: it cannot distinguish a collector that is
	// down from a queue that overflowed, it has no denominator, and it never
	// moves at all on UDP — where a write to a blackholed collector succeeds
	// forever. These fields are what a health plane needs to say whether the
	// feed is DELIVERING, not merely whether it once connected.
	//
	// All atomics, all read through Health(): the drain goroutine writes them
	// and every reader is a scrape or an admin request, so no reader may take
	// s.mu (deliverLine holds it across up to two dials and two writes).
	delivered        atomic.Uint64
	dropsQueueFull   atomic.Uint64
	dropsCollector   atomic.Uint64
	dropsClosed      atomic.Uint64
	dropsFlush       atomic.Uint64
	lastDeliveryNano atomic.Int64
	consecutiveFails atomic.Int64
	// lastFailure is a bounded ENUM, never a string. A raw error here would
	// embed the collector address and the ephemeral local port, which is the
	// WK-12/RS-5 defect: alert dedup keys on event+Detail, so a per-attempt
	// unique reason defeats the suppression window by construction. Making it
	// an int32 code makes that unrepresentable rather than merely discouraged.
	lastFailure atomic.Int32

	// Async delivery plumbing (nil/zero on a zero-value Writer → synchronous).
	queue     chan string   // formatted lines awaiting delivery (bounded at queueCap)
	stop      chan struct{} // closed by Close; tells drainLoop to flush and exit
	done      chan struct{} // closed by drainLoop on exit (conn released)
	closed    atomic.Bool   // post-Close sends drop instead of enqueueing
	closeOnce sync.Once
}

// failureReason is the BOUNDED class of a delivery failure. It is an integer
// code rather than a string on purpose: the only other candidate value is the
// underlying net error, which embeds the collector address and the ephemeral
// local port, and alert dedup keys on event+Detail. Encoding the class as an
// enum makes an unbounded reason unrepresentable instead of merely
// discouraged. The verbose cause belongs in a rate-limited log line.
type failureReason int32

const (
	reasonNone failureReason = iota
	reasonDialFailed
	reasonWriteFailed
	reasonQueueFull
	reasonClosed
	reasonFlushTimeout
	reasonPanic
)

// String renders the reason class for metric labels and operator text. The
// value set is closed; an unrecognised code degrades to "unknown" rather than
// formatting the integer, so a future code added without a name here can never
// widen the label cardinality.
func (r failureReason) String() string {
	switch r {
	case reasonNone:
		return ""
	case reasonDialFailed:
		return "dial_failed"
	case reasonWriteFailed:
		return "write_failed"
	case reasonQueueFull:
		return "queue_full"
	case reasonClosed:
		return "closed"
	case reasonFlushTimeout:
		return "flush_timeout"
	case reasonPanic:
		return "panic"
	default:
		return "unknown"
	}
}

// SetDeliveryObserver publishes an optional observer notified about delivery
// outcomes, on the drain goroutine. This package is a stdlib-only leaf with no
// logging or metrics dependency (see the package doc), so without an observer
// the only delivery signal is a Health() poll — which nothing pushes.
//
// It is deliberately NOT called once per line. It fires:
//
//   - on every collector-attributable FAILURE, so a health plane can evaluate
//     how long the feed has been failing without owning a timer; and
//   - on the first success AFTER a failure run — the recovery edge.
//
// In the healthy steady state it therefore costs nothing at all, which is what
// makes it safe to hang a mutex-taking health plane off it: the callback only
// happens when something is already wrong. A nil fn clears it. The observer is
// panic-contained, so a bad observer can never take down delivery — the same
// rule SetPanicObserver carries.
func (s *Writer) SetDeliveryObserver(fn func(ok bool, reason string, consecutive int64)) {
	if fn == nil {
		s.deliveryObserver.Store(nil)
		return
	}
	s.deliveryObserver.Store(&fn)
}

// notifyDelivery invokes the delivery observer, contained.
func (s *Writer) notifyDelivery(ok bool, reason string, consecutive int64) {
	p := s.deliveryObserver.Load()
	if p == nil {
		return
	}
	defer func() { _ = recover() }() // an observer must never crash the drain goroutine
	(*p)(ok, reason, consecutive)
}

// noteFailure records one lost line under its bounded class and advances the
// consecutive-failure run. Every path that increments s.drops goes through
// here or through noteDelivered's counterpart, so the aggregate Drops() can
// never disagree with the sum of the per-reason counters.
func (s *Writer) noteFailure(r failureReason) {
	s.drops.Add(1)
	s.lastFailure.Store(int32(r))
	switch r {
	case reasonQueueFull:
		s.dropsQueueFull.Add(1)
	case reasonClosed:
		s.dropsClosed.Add(1)
	case reasonFlushTimeout:
		s.dropsFlush.Add(1)
	case reasonPanic:
		// A panicked line never reached the socket, but the socket is not what
		// failed; it is counted as a loss without being attributed to the
		// collector, so a formatting bug is never reported as a SIEM outage.
	default:
		s.dropsCollector.Add(1)
	}
	// Only a collector-attributable loss advances the consecutive run: that run
	// is what the health plane verdicts on, and a queue overflow means the
	// collector is too SLOW, not absent — a different remediation.
	if r == reasonDialFailed || r == reasonWriteFailed {
		s.notifyDelivery(false, r.String(), s.consecutiveFails.Add(1))
	}
}

// noteDelivered records one line accepted by the socket. This is the only
// EVIDENCE the process ever has that the feed is working, and it is what
// clears a failure episode — never elapsed time, which is the mistake
// ca_health.go and storage_health.go both call out by name.
//
// On UDP "accepted by the socket" means accepted by the local kernel and
// nothing more; Health().DeliveryVerifiable reports that honestly rather than
// letting a caller read this counter as proof of receipt.
func (s *Writer) noteDelivered(at time.Time) {
	s.delivered.Add(1)
	s.lastDeliveryNano.Store(at.UnixNano())
	// Swap rather than Store so the recovery EDGE is detected without a second
	// read that could race another failure in between.
	recovered := s.consecutiveFails.Swap(0) > 0
	s.lastFailure.Store(int32(reasonNone))
	if recovered {
		s.notifyDelivery(true, "", 0)
	}
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
	s.queue = make(chan string, queueCap)
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
		case line := <-s.queue:
			s.deliverGuarded(line)
		case <-s.stop:
			deadline := time.Now().Add(flushTimeout)
			for {
				select {
				case line := <-s.queue:
					if time.Now().Before(deadline) {
						s.deliverGuarded(line)
					} else {
						s.noteFailure(reasonFlushTimeout)
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
func (s *Writer) send(pri int, msg string) {
	if s.queue == nil {
		s.writeMsg(pri, msg)
		return
	}
	if s.closed.Load() {
		s.noteFailure(reasonClosed)
		return
	}
	select {
	case s.queue <- s.formatMsg(pri, msg):
	default:
		s.noteFailure(reasonQueueFull)
	}
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
	switch s.format {
	case "rfc5424":
		// RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
		ts := time.Now().Format(time.RFC3339Nano)
		return fmt.Sprintf("<%d>1 %s %s %s %s - - %s\n", pri, ts, s.host, s.tag, s.pid, msg)
	default: // rfc3164
		ts := time.Now().Format("Jan 02 15:04:05")
		return fmt.Sprintf("<%d>%s %s %s: %s\n", pri, ts, s.host, s.tag, msg)
	}
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
			s.noteFailure(reasonPanic)
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
			s.noteFailure(reasonDialFailed)
			return
		}
		if err := s.connect(); err != nil {
			s.lastReconnErr = time.Now()
			s.noteFailure(reasonDialFailed)
			return // syslog down — swallow, never block the proxy
		}
		s.lastReconnErr = time.Time{} // reset on success
	}
	if err := s.writeLine(line); err != nil {
		s.conn.Close()
		s.conn = nil
		if time.Since(s.lastReconnErr) < 5*time.Second {
			s.noteFailure(reasonWriteFailed)
			return
		}
		if err2 := s.connect(); err2 != nil {
			s.lastReconnErr = time.Now()
			s.noteFailure(reasonDialFailed)
			return
		}
		if err3 := s.writeLine(line); err3 != nil {
			// A collector that ACCEPTS connections but never drains would
			// otherwise reset the backoff on every call (connect succeeds,
			// write times out), taxing every log caller up to
			// writeTimeout + dial (5s) + writeTimeout — three serialized
			// network ops (~15s worst case) under s.mu. Arm the backoff so
			// subsequent calls fast-drop for the window instead.
			s.conn.Close()
			s.conn = nil
			s.lastReconnErr = time.Now()
			s.noteFailure(reasonWriteFailed)
			return
		}
		s.lastReconnErr = time.Time{}
		s.noteDelivered(time.Now())
		return
	}
	s.noteDelivered(time.Now())
}

// Drops reports the number of messages dropped because the collector was
// unreachable or not draining, the delivery queue overflowed, or the Writer
// was already closed. Monotonic per Writer; delivery is otherwise
// silent-best-effort, so this is the only loss signal.
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
	s.closed.Store(true)
	s.closeOnce.Do(func() { close(s.stop) })
	select {
	case <-s.done:
	case <-time.After(closeWait):
	}
	return nil
}

// Format returns the syslog message format ("rfc3164" or "rfc5424").
//
// Deliberately LOCK-FREE. s.format is assigned once, in NewWriter, before the
// Writer is published to any other goroutine, and is never written again — so
// the mutex protected nothing, while coupling this accessor to the collector
// socket: deliverLine holds s.mu across up to two dials (5s each) and two
// writes (5s each), so every caller of Format() could block for ~15s behind a
// wedged SIEM collector. The callers are GET /api/syslog and, by way of the
// settings snapshot, adminSettingsSave() — which every mutating admin handler
// reaches. A management plane must not stall on a log sink (CHAOS-66; the same
// direction as CHAOS-57's rule that the admin plane and the data plane may not
// take each other down).
//
// Network() is lock-free for the same reason.
func (s *Writer) Format() string { return s.format }

// Network returns the transport the collector is addressed over ("udp" or
// "tcp"). Immutable after construction; see Format.
//
// This is load-bearing for the health plane rather than cosmetic: on UDP a
// successful write proves only that the LOCAL kernel accepted the datagram, so
// no counter this package keeps can distinguish a healthy collector from one
// that has not existed for a week. Health().DeliveryVerifiable derives from it.
func (s *Writer) Network() string { return s.network }

// Health is a point-in-time snapshot of delivery evidence. Every field is read
// from an atomic, so a caller never takes s.mu and therefore can never block
// behind the collector socket (see Format).
//
// The snapshot is not atomic ACROSS fields — the counters are independent — and
// deliberately so: a combined lock would reintroduce exactly the coupling this
// type exists to avoid, and the only consumers are a scrape, an admin read and
// a verdict, none of which need cross-field consistency finer than one line.
type Health struct {
	// Network and Format are the transport and wire format in effect.
	Network string
	Format  string

	// Delivered counts lines the socket accepted. On TCP this is meaningful
	// evidence of reachability; on UDP see DeliveryVerifiable.
	Delivered uint64

	// Drops is the aggregate loss count (== the sum of the four per-reason
	// counters below plus panic losses).
	Drops              uint64
	DropsCollectorDown uint64
	DropsQueueFull     uint64
	DropsClosed        uint64
	DropsFlushTimeout  uint64
	Panics             uint64

	// LastDelivery is when the socket last accepted a line; zero means never.
	LastDelivery time.Time

	// ConsecutiveFailures counts collector-attributable losses since the last
	// delivery. A queue overflow does NOT advance it — that says the collector
	// is too slow, not that it is gone, and the two have different remedies.
	ConsecutiveFailures int64

	// LastFailureReason is the bounded class of the most recent loss ("" when
	// none). Never carries an address or an error string.
	LastFailureReason string

	// DeliveryVerifiable is false on UDP. It is the honest answer to "does a
	// green reading here mean anything?": for a connectionless transport the
	// process cannot observe delivery at all, so a health surface must say so
	// rather than report the absence of observed failures as success.
	DeliveryVerifiable bool
}

// Health returns the current delivery snapshot.
func (s *Writer) Health() Health {
	var last time.Time
	if n := s.lastDeliveryNano.Load(); n > 0 {
		last = time.Unix(0, n)
	}
	return Health{
		Network:             s.network,
		Format:              s.format,
		Delivered:           s.delivered.Load(),
		Drops:               s.drops.Load(),
		DropsCollectorDown:  s.dropsCollector.Load(),
		DropsQueueFull:      s.dropsQueueFull.Load(),
		DropsClosed:         s.dropsClosed.Load(),
		DropsFlushTimeout:   s.dropsFlush.Load(),
		Panics:              s.panics.Load(),
		LastDelivery:        last,
		ConsecutiveFailures: s.consecutiveFails.Load(),
		LastFailureReason:   failureReason(s.lastFailure.Load()).String(),
		DeliveryVerifiable:  s.network != "udp",
	}
}
