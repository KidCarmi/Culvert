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
	lastReconnErr time.Time // backoff: suppress reconnect attempts for reconnectBackoff after failure
	lastCause     string    // most recent delivery error text; LOG only (see noteCause)
	drops         atomic.Uint64
	queueDrops    atomic.Uint64
	lastQueueDrop atomic.Int64 // UnixNano of the most recent queue-full drop; see QueueSaturatedSince
	panics        atomic.Uint64
	panicObserver atomic.Pointer[func(recovered any)] // optional; see SetPanicObserver
	stateObserver atomic.Pointer[func(up bool, reason string, changed bool)]
	up            atomic.Bool              // last OBSERVED delivery outcome; see noteOutcome
	stateKnown    atomic.Bool              // false until the first outcome is observed
	dialFunc      func() (net.Conn, error) // test seam; nil = real dialer

	// Async delivery plumbing (nil/zero on a zero-value Writer → synchronous).
	queue     chan string   // formatted lines awaiting delivery (bounded at queueCap)
	stop      chan struct{} // closed by Close; tells drainLoop to flush and exit
	done      chan struct{} // closed by drainLoop on exit (conn released)
	closed    atomic.Bool   // post-Close sends drop instead of enqueueing
	closeOnce sync.Once
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
	sw.up.Store(true)
	sw.stateKnown.Store(true)
	sw.startAsync()
	return sw, nil
}

// NewWriterDeferred returns a ready Writer WITHOUT requiring the first dial to
// succeed. The connection is established lazily by deliverLine's existing
// reconnect path (bounded to one attempt per reconnectBackoff), so a collector
// that is unreachable at construction self-heals the moment it returns.
//
// CHAOS-66: NewWriter fails CLOSED on the first dial, and the only boot-path
// callers (loadObservability, applyAdminServices) log-and-continue with a nil
// writer. Nothing ever constructs a second one, so a SIEM that happened to be
// down — or merely slower to start than the proxy beside it in the same
// compose file — turned into SIEM forwarding being OFF for the entire life of
// the process, recoverable only by an operator re-saving the target or
// restarting. This constructor is the recovery path: the engine already owns a
// reconnect state machine, it was simply never reachable from a failed start.
//
// The dial error is returned for logging; the Writer is valid either way. A
// caller that wants to REJECT an unreachable target (validating operator
// input) should use Probe instead of inferring it from construction.
func NewWriterDeferred(network, addr, format string) (*Writer, error) {
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
	dialErr := sw.connect()
	if dialErr != nil {
		// Arm the backoff so the first delivery does not immediately re-dial a
		// target we already know is refusing.
		sw.lastReconnErr = time.Now()
	}
	sw.up.Store(dialErr == nil)
	sw.stateKnown.Store(true)
	sw.startAsync()
	return sw, dialErr
}

// Network reports the transport ("udp" or "tcp") this Writer forwards over.
func (s *Writer) Network() string { return s.network }

// Target reports the collector address this Writer forwards to.
func (s *Writer) Target() string { return s.addr }

// DeliveryVerifiable reports whether a delivery failure to this collector is
// OBSERVABLE by this process.
//
// It is false for UDP, and that is a protocol fact, not an implementation gap:
// a connected UDP socket's write succeeds locally whether or not anything is
// listening, so Drops() stays 0, Up() stays true and every surface above them
// reports a healthy feed while nothing is received. (Linux may surface a
// returned ICMP port-unreachable on a LATER write, so a UDP failure is
// sometimes visible — never reliably, and never through a firewall that drops
// ICMP.) UDP is also the DEFAULT transport when the operator's address carries
// no scheme, so this is the posture most deployments are in.
//
// Callers must not upgrade a UDP feed's reported state to "delivering"; they
// report that lines are being SENT and that delivery is unverifiable. The
// operator remedy is to use tcp:// when the SIEM feed is a compliance control.
func (s *Writer) DeliveryVerifiable() bool { return s.network != "udp" }

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
						s.drops.Add(1)
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
		s.drops.Add(1)
		s.queueDrops.Add(1)
		return
	}
	select {
	case s.queue <- s.formatMsg(pri, msg):
	default:
		// CHAOS-66: charged to BOTH counters. Drops() stays the single
		// "lines that never reached the collector" total; QueueDrops()
		// separates the cause, because the two point at different operator
		// actions — an unreachable collector is a network/host fault, a full
		// queue is a collector that accepts but is slower than this node's
		// entry rate.
		//
		// The TIMESTAMP is what makes this loss visible as a LIVE fault
		// rather than a counter nobody re-reads (Codex review, PR #1461).
		// A collector that stays writable but drains slower than producers
		// discards entries here continuously while the drain goroutine keeps
		// succeeding — so Up() stays true, the health record stays clean, the
		// contract row reads "delivering" and reports the loss as having
		// happened "earlier", and neither the degradation gauge nor the alert
		// ever fires. That is the same reporting error this sweep exists to
		// remove (SL-2), for the "collector too slow" case instead of the
		// "collector unreachable" one — and a slow SIEM is the commoner
		// fault of the two.
		//
		// Still no callback: send() is on the request path (store.go's
		// recordRequest and the audit SIEM hook), so the drop path stays
		// three atomic ops, and the HEALTHY path is untouched. The drain
		// goroutine reads this stamp on its next outcome and folds it into
		// the state, which is where an observer may legitimately run.
		s.drops.Add(1)
		s.queueDrops.Add(1)
		s.lastQueueDrop.Store(time.Now().UnixNano())
	}
}

// QueueSaturatedSince reports whether the bounded delivery queue has dropped a
// line since t — i.e. whether this Writer is losing entries RIGHT NOW because
// the collector drains slower than this node produces.
//
// Distinct from Up(), which reports whether the last line the drain goroutine
// attempted reached the collector. Both can be true at once, and that
// combination is exactly the fault this answers: delivery is working and
// entries are being lost anyway.
func (s *Writer) QueueSaturatedSince(t time.Time) bool {
	n := s.lastQueueDrop.Load()
	return n != 0 && n >= t.UnixNano()
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
	ok, reason := s.deliverLine(s.formatMsg(pri, msg))
	s.noteOutcome(ok, reason)
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
			s.drops.Add(1)
			s.noteOutcome(false, ReasonPanic)
			if p := s.panicObserver.Load(); p != nil {
				func() {
					defer func() { _ = recover() }() // an observer must never crash the drain goroutine
					(*p)(r)
				}()
			}
		}
	}()
	ok, reason := s.deliverLine(line)
	s.noteOutcome(ok, reason)
}

// Bounded delivery-state reason classes. These reach an alert's dedup key and
// an operator-contract row, so they are a FIXED vocabulary, never a raw
// error: net errors embed the collector address and the ephemeral local port,
// which gives Store.Dispatch's `event + ":" + Detail` key one value per
// failure and lets a SIEM outage evict real threat alerts from the retry
// queue (the WK-12/RS-5 defect). The cause itself goes to a rate-limited log
// line, not to the alert.
const (
	ReasonConnectFailed = "connect_failed"
	ReasonWriteFailed   = "write_failed"
	ReasonPanic         = "panic"
	// ReasonQueueFull is delivery SUCCEEDING while entries are lost anyway:
	// the collector accepts but drains slower than this node produces, so the
	// bounded queue sheds. Its operator action is capacity, not reachability.
	ReasonQueueFull = "queue_full"
)

// SetStateObserver publishes an optional observer notified of every delivery
// OUTCOME on this Writer: up=true when the line reached the collector,
// up=false with a bounded reason class when it did not, and changed=true on
// the calls that flipped the state. Mirrors SetPanicObserver (this package is
// a stdlib-only leaf and cannot log or alert for itself).
//
// Per-outcome rather than per-transition, deliberately. A transition-only
// seam cannot answer "has this feed been down long enough to page", because
// the only call it makes is the one at the start of the episode — and the
// house rule for every other subsystem here is that degradation is a
// DURATION, not a count, so the observer has to be re-entered while the fault
// persists for the duration to be evaluated at all. `changed` is what keeps
// the LOG one line per transition rather than one per dropped line.
//
// It runs on the drain goroutine, never on a request goroutine, and with s.mu
// RELEASED so it may call back into the Writer. It is panic-contained: a bad
// observer can never take down delivery.
func (s *Writer) SetStateObserver(fn func(up bool, reason string, changed bool)) {
	if fn == nil {
		s.stateObserver.Store(nil)
		return
	}
	s.stateObserver.Store(&fn)
}

// noteOutcome records one delivery outcome and publishes it. Must be called
// with s.mu RELEASED.
func (s *Writer) noteOutcome(up bool, reason string) {
	known := s.stateKnown.Swap(true)
	prev := s.up.Swap(up)
	changed := !known || prev != up
	o := s.stateObserver.Load()
	if o == nil {
		return
	}
	func() {
		defer func() { _ = recover() }() // an observer must never crash the drain goroutine
		(*o)(up, reason, changed)
	}()
}

// Up reports the last OBSERVED delivery outcome: true when the most recent
// line reached the collector, false when it did not.
//
// For a UDP Writer this is nearly always true and means only "the local send
// succeeded" — see DeliveryVerifiable. Evaluated, never latched: recovery
// needs no clearing path and a wedged feed keeps reporting the truth (the
// ca_health.go Usable() discipline).
func (s *Writer) Up() bool { return s.up.Load() }

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

// deliverLine sends one pre-formatted line and reports the outcome: (true, "")
// when the line reached the collector, (false, <bounded reason class>) when it
// did not. The caller publishes that outcome via noteOutcome once s.mu is
// released — never from in here, because an observer runs arbitrary caller
// code and this mutex fences every delivery in the process.
func (s *Writer) deliverLine(line string) (delivered bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		// Backoff: don't retry more often than every reconnectBackoff.
		if time.Since(s.lastReconnErr) < reconnectBackoff {
			s.drops.Add(1)
			return false, ReasonConnectFailed
		}
		if err := s.connect(); err != nil {
			s.lastReconnErr = time.Now()
			s.drops.Add(1)
			s.noteCause(err)
			return false, ReasonConnectFailed // syslog down — swallow, never block the proxy
		}
		s.lastReconnErr = time.Time{} // reset on success
	}
	if err := s.writeLine(line); err != nil {
		s.conn.Close()
		s.conn = nil
		if time.Since(s.lastReconnErr) < reconnectBackoff {
			s.drops.Add(1)
			return false, ReasonWriteFailed
		}
		if err2 := s.connect(); err2 != nil {
			s.lastReconnErr = time.Now()
			s.drops.Add(1)
			s.noteCause(err2)
			return false, ReasonConnectFailed
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
			s.drops.Add(1)
			s.noteCause(err3)
			return false, ReasonWriteFailed
		}
		s.lastReconnErr = time.Time{}
	}
	return true, ""
}

// reconnectBackoff bounds how often a down collector is re-dialled. Bounded in
// RATE and unbounded in COUNT, deliberately: a feed that stopped retrying
// would stay dark for the life of the process, which is the CHAOS-66 defect
// this engine's recovery path exists to prevent. The retry is never silent —
// every failure is counted in Drops() and the first of each episode reaches
// the state observer.
const reconnectBackoff = 5 * time.Second

// lastCause holds the most recent delivery error string for the operator LOG
// only. Never for an alert Detail or an unauthenticated surface: a net error
// embeds the collector address and the ephemeral local port. Guarded by s.mu.
func (s *Writer) noteCause(err error) {
	if err == nil {
		return
	}
	s.lastCause = err.Error()
}

// LastCause returns the most recent delivery error text, for the process log.
func (s *Writer) LastCause() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCause
}

// QueueDrops reports the subset of Drops() lost because the bounded delivery
// queue was full (collector slower than this node's entry rate) or the Writer
// was already closed — as opposed to the collector being unreachable.
func (s *Writer) QueueDrops() uint64 { return s.queueDrops.Load() }

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
func (s *Writer) Format() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.format
}

// probeTimeout bounds one Probe end to end (dial + write). Deliberately the
// same order as writeTimeout so an operator's connectivity check cannot park
// an admin request longer than one ordinary delivery attempt would.
const probeTimeout = 5 * time.Second

// Probe performs a SYNCHRONOUS one-shot connectivity check against this
// Writer's collector on a FRESH connection and reports what was actually
// observed. It never touches s.conn, so a probe can neither disturb live
// delivery nor be answered by a connection that is already wedged.
//
// CHAOS-66: this exists because `POST /api/syslog/test` used to answer
// `{"ok":true,"message":"test message sent"}` by calling Write — which, since
// delivery became asynchronous, only enqueues a line on a bounded channel and
// returns. A collector that does not exist produced exactly the same 200 as a
// healthy one, while `checkSyslogFeed`'s own operator-action text told the
// operator to "use POST /api/syslog/test to confirm connectivity". The
// documented way to verify the remedy could not fail.
//
// verified reports whether the answer MEANS anything: it is false for UDP,
// where a local send succeeds regardless (see DeliveryVerifiable). A caller
// must not render an unverified probe as proof of delivery.
func (s *Writer) Probe(ctx context.Context) (verified bool, err error) {
	return probeTarget(ctx, s.network, s.addr, s.format, s.host, s.pid, s.tag, s.dialFunc)
}

// ProbeTarget performs the same one-shot connectivity check as
// (*Writer).Probe against a target NO Writer has been built for.
//
// This is what lets an admin endpoint VALIDATE an operator-typed target
// without installing it: the caller can refuse a typo up front and still
// leave a working forwarder untouched. Building a throwaway Writer to find
// out would start a drain goroutine and a queue for a target that may be
// about to be rejected.
func ProbeTarget(ctx context.Context, network, addr, format string) (verified bool, err error) {
	host, herr := os.Hostname()
	if herr != nil {
		host = "culvert"
	}
	if format == "" {
		format = "rfc3164"
	}
	return probeTarget(ctx, network, addr, format, host, fmt.Sprintf("%d", os.Getpid()), "culvert", nil)
}

func probeTarget(ctx context.Context, network, addr, format, host, pid, tag string, dial func() (net.Conn, error)) (verified bool, err error) {
	line := (&Writer{network: network, addr: addr, format: format, host: host, pid: pid, tag: tag}).formatMsg(14, probeMessage)
	conn, derr := probeDialTarget(ctx, network, addr, dial)
	// A UDP dial is a local operation and a UDP write succeeds locally
	// regardless, so nothing a UDP probe observes is evidence of delivery.
	// The line is still SENT (a working UDP path carries the operator's test
	// message to their SIEM), and verified=false says the result proves
	// nothing — a caller must not render it as confirmation.
	verified = network != "udp"
	if derr != nil {
		return verified, derr
	}
	defer conn.Close() //nolint:errcheck // best-effort release of a one-shot probe conn
	if dl, ok := ctx.Deadline(); ok {
		conn.SetWriteDeadline(dl) //nolint:errcheck // best-effort; a failed deadline set surfaces on the write itself
	} else {
		conn.SetWriteDeadline(time.Now().Add(probeTimeout)) //nolint:errcheck // as above
	}
	_, werr := fmt.Fprint(conn, line)
	return verified, werr
}

// probeMessage is the line a Probe delivers. Fixed text: it reaches the
// operator's SIEM, so it must be recognisable there and must carry nothing
// caller-supplied.
const probeMessage = "Culvert syslog connectivity probe"

// probeDialTarget opens a one-shot connection for a probe. Honours the test
// dialFunc seam so a probe is drivable without a real collector.
func probeDialTarget(ctx context.Context, network, addr string, dial func() (net.Conn, error)) (net.Conn, error) {
	if dial != nil {
		return dial()
	}
	d := net.Dialer{Timeout: probeTimeout}
	return d.DialContext(ctx, network, addr)
}
