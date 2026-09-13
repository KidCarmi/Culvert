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
	"errors"
	"fmt"
	mrand "math/rand/v2"
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
	mu      sync.Mutex
	network string
	addr    string
	conn    net.Conn

	// host/tag/format/pid are written once before the Writer is published and
	// never again, so every reader takes them WITHOUT s.mu. That is not a
	// micro-optimisation: the drain goroutine holds s.mu across dial + write +
	// write against a wedged collector (~15 s worst case), so any accessor that
	// took the mutex would stall for that long — Format() did, which made
	// GET /api/syslog hang for the duration of a SIEM outage (CHAOS-66).
	// Everything an operator surface reads is therefore either one of these
	// immutable fields or an atomic below.
	host   string
	tag    string
	format string // "rfc3164" (default) or "rfc5424"
	pid    string // cached PID string for RFC 5424 PROCID

	// retryAfter/backoff are the reconnect schedule; guarded by s.mu because
	// only the single delivery path touches them. A MIRROR of backoff is
	// published to backoffNanos for the lock-free Stats() view.
	retryAfter time.Time
	backoff    time.Duration

	drops         atomic.Uint64
	panics        atomic.Uint64
	panicObserver atomic.Pointer[func(recovered any)] // optional; see SetPanicObserver
	dialFunc      func() (net.Conn, error)            // test seam; nil = real dialer

	// Delivery evidence (CHAOS-66). Written under s.mu by the single delivery
	// path, read WITHOUT it by Stats(), for the stall reason above.
	//
	// The whole point of these is that "the feed is up" must be a claim about
	// OBSERVED DELIVERY, not about a dial that succeeded once at boot. The
	// syslog_feed operator-contract row used to report the boot dial and
	// nothing else, which is green for every failure mode that starts after
	// boot — and, on UDP, green unconditionally.
	delivered       atomic.Uint64          // lines the socket accepted
	queueFull       atomic.Uint64          // drops caused by the queue, not the collector
	consecFail      atomic.Int64           // consecutive failed delivery attempts; 0 = last one landed
	lastSuccessNano atomic.Int64           // 0 = nothing has EVER been delivered
	firstFailNano   atomic.Int64           // start of the current failing run; 0 = not failing
	lastFailNano    atomic.Int64           //
	backoffNanos    atomic.Int64           //
	lastReason      atomic.Pointer[string] // BOUNDED class, never a raw error string

	deliveryObserver atomic.Pointer[func(DeliveryOutcome)] // optional; see SetDeliveryObserver

	// Async delivery plumbing (nil/zero on a zero-value Writer → synchronous).
	queue     chan string   // formatted lines awaiting delivery (bounded at queueCap)
	stop      chan struct{} // closed by Close; tells drainLoop to flush and exit
	done      chan struct{} // closed by drainLoop on exit (conn released)
	closed    atomic.Bool   // post-Close sends drop instead of enqueueing
	closeOnce sync.Once
}

// Bounded failure classes. A raw error is never published: it embeds the
// collector address and, on the write path, the ephemeral local port, which
// would give the alert dedup key one distinct value per failure (the WK-12/RS-5
// defect) and put an operator-supplied endpoint on a viewer-role surface. The
// full error stays in the caller's rate-limited log line.
const (
	ReasonDNS            = "dns_failure"
	ReasonConnectTimeout = "connect_timeout"
	ReasonConnectFailed  = "connect_failed"
	ReasonWriteTimeout   = "write_timeout"
	ReasonWriteFailed    = "write_failed"
)

// DeliveryOutcome is handed to the optional delivery observer.
type DeliveryOutcome struct {
	OK bool
	// Recovered is true on the first delivery that lands after a run of
	// failures. It is the ONLY evidence of recovery this package emits —
	// elapsed time never clears a failing state, per the house rule in
	// storage_health.go / ca_health.go.
	Recovered   bool
	Reason      string // bounded class; empty when OK
	Consecutive int64
	Backoff     time.Duration
	// FailingFor is how long the current uninterrupted run of failures has
	// lasted, and Drops the cumulative loss. Both are carried ON the outcome so
	// an observer can judge severity from the event alone, without reading back
	// through the Writer (or, in package main's case, through process globals
	// that the admin goroutine mutates) from the drain goroutine.
	FailingFor time.Duration
	Drops      uint64
}

// classifyErr maps a delivery error to one of the bounded classes above.
// connectPhase distinguishes a failed dial from a failed write, which have
// different operator actions (reachability vs. a collector that accepts and
// then stops draining).
func classifyErr(err error, connectPhase bool) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ReasonDNS
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		if connectPhase {
			return ReasonConnectTimeout
		}
		return ReasonWriteTimeout
	}
	if connectPhase {
		return ReasonConnectFailed
	}
	return ReasonWriteFailed
}

// queueCap bounds the async delivery queue. At a formatted line of ~0.5 KB the
// worst-case queue memory is ~1 MB; past this the collector is slower than the
// entry rate and lines drop (counted) rather than backpressure the proxy.
const queueCap = 2048

// Reconnect schedule (CHAOS-66). The pre-CHAOS-66 shape was a FLAT 5 s window
// with no growth and no jitter, so every node in a fleet re-dialled a collector
// that was by hypothesis already overloaded at a fixed, identical cadence, for
// as long as the outage lasted — the closed loop CHAOS-59 recorded for the
// intelligence feeds, one subsystem over. This is the schedule the rest of the
// tree already uses: bounded exponential with jitter, reset by OBSERVED
// delivery.
//
// The initial delay is deliberately SHORTER than the 5 s it replaces (a brief
// collector restart now recovers in ~1 s instead of up to 5), and the ceiling
// longer (a sustained outage costs one dial a minute instead of twelve). The
// ceiling also bounds recovery latency: a collector that comes back is picked
// up within reconnectBackoffMax at worst.
const (
	reconnectBackoffInitial = 1 * time.Second
	reconnectBackoffMax     = 60 * time.Second
	// reconnectBackoffJitter is the fraction applied in BOTH directions, so a
	// fleet that started together does not stay in phase. Drawn from
	// math/rand/v2's per-P generator: this package is a stdlib-only leaf and
	// the value is a retry delay, never a secret.
	reconnectBackoffJitter = 0.2
)

// nextReconnectBackoff doubles the current delay up to the ceiling.
func nextReconnectBackoff(cur time.Duration) time.Duration {
	if cur <= 0 {
		return reconnectBackoffInitial
	}
	next := cur * 2
	if next > reconnectBackoffMax {
		return reconnectBackoffMax
	}
	return next
}

// jitterBackoff spreads d by ±reconnectBackoffJitter.
func jitterBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	span := float64(d) * reconnectBackoffJitter
	out := time.Duration(float64(d) + (mrand.Float64()*2-1)*span)
	if out < time.Millisecond {
		return time.Millisecond
	}
	return out
}

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
		// Sweep whatever a sender buffered between its s.closed check and the
		// flush loop observing an empty queue. Without this those lines are
		// silently lost: nothing reads the channel once this goroutine exits,
		// and a buffered send never blocks, so the drop was invisible even to
		// the Drops() counter. Shutdown is exactly when the last audit lines
		// matter, so an uncounted loss there is the worst place to have one.
		s.sweepQueue()
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
		return
	}
	select {
	case s.queue <- s.formatMsg(pri, msg):
	default:
		// Counted separately from a delivery failure: a full queue means the
		// collector is slower than the entry rate, which is a different
		// operator action (SIEM throughput/ingest sizing) from a collector that
		// is unreachable. Deliberately does NOT reach the delivery observer —
		// this branch runs on the CALLER's goroutine, which for a request-log
		// line is the request goroutine, and the whole contract of this package
		// is that the request path never pays for the SIEM.
		s.queueFull.Add(1)
		s.drops.Add(1)
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
	s.notifyDelivery(s.deliverLine(s.formatMsg(pri, msg)))
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
			if p := s.panicObserver.Load(); p != nil {
				func() {
					defer func() { _ = recover() }() // an observer must never crash the drain goroutine
					(*p)(r)
				}()
			}
		}
	}()
	s.notifyDelivery(s.deliverLine(line))
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

// noteFailureLocked records one undelivered line. reason is a bounded class;
// an EMPTY reason means "keep the previously recorded cause", which is what a
// fast-drop inside the backoff window passes — the window is a consequence of
// the failure, not a separate cause, and overwriting the real reason with
// "backoff" would tell the operator nothing about why the feed is dark.
//
// Caller must hold s.mu.
func (s *Writer) noteFailureLocked(reason string, now time.Time) DeliveryOutcome {
	s.drops.Add(1)
	n := s.consecFail.Add(1)
	s.lastFailNano.Store(now.UnixNano())
	if s.firstFailNano.Load() == 0 {
		s.firstFailNano.Store(now.UnixNano())
	}
	if reason != "" {
		r := reason
		s.lastReason.Store(&r)
	} else if p := s.lastReason.Load(); p != nil {
		reason = *p
	}
	return DeliveryOutcome{
		Reason:      reason,
		Consecutive: n,
		Backoff:     s.backoff,
		FailingFor:  now.Sub(time.Unix(0, s.firstFailNano.Load())),
		Drops:       s.drops.Load(),
	}
}

// noteSuccessLocked records one line the socket accepted and clears the failing
// run. Caller must hold s.mu.
func (s *Writer) noteSuccessLocked(now time.Time) DeliveryOutcome {
	s.delivered.Add(1)
	s.lastSuccessNano.Store(now.UnixNano())
	recovered := s.consecFail.Swap(0) > 0
	s.firstFailNano.Store(0)
	s.lastFailNano.Store(0)
	s.clearBackoffLocked()
	return DeliveryOutcome{OK: true, Recovered: recovered, Drops: s.drops.Load()}
}

// armBackoffLocked grows the reconnect delay and stamps the next permitted
// attempt. Caller must hold s.mu.
func (s *Writer) armBackoffLocked(now time.Time) {
	s.backoff = nextReconnectBackoff(s.backoff)
	s.backoffNanos.Store(int64(s.backoff))
	s.retryAfter = now.Add(jitterBackoff(s.backoff))
}

// clearBackoffLocked resets the reconnect delay. Only ever called from
// noteSuccessLocked — i.e. on OBSERVED delivery, never on elapsed time.
// Caller must hold s.mu.
func (s *Writer) clearBackoffLocked() {
	s.backoff = 0
	s.backoffNanos.Store(0)
	s.retryAfter = time.Time{}
}

func (s *Writer) deliverLine(line string) DeliveryOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.conn == nil {
		if now.Before(s.retryAfter) {
			return s.noteFailureLocked("", now)
		}
		if err := s.connect(); err != nil {
			s.armBackoffLocked(now)
			return s.noteFailureLocked(classifyErr(err, true), now) // syslog down — never block the proxy
		}
		// The backoff is deliberately NOT cleared here. A successful DIAL is not
		// delivery, and clearing on it resets the schedule to its initial 1 s
		// against precisely the collector that most needs to be left alone: one
		// that ACCEPTS connections and then stops draining dials successfully on
		// every cycle, so a dial-cleared backoff can never grow past its first
		// step. Only a line the collector accepted clears it (noteSuccessLocked).
	}
	err := s.writeLine(line)
	if err == nil {
		return s.noteSuccessLocked(time.Now())
	}
	s.conn.Close() //nolint:errcheck // best-effort; the conn is being discarded
	s.conn = nil
	now = time.Now()
	if now.Before(s.retryAfter) {
		return s.noteFailureLocked(classifyErr(err, false), now)
	}
	if err2 := s.connect(); err2 != nil {
		s.armBackoffLocked(now)
		return s.noteFailureLocked(classifyErr(err2, true), now)
	}
	if err3 := s.writeLine(line); err3 != nil {
		// A collector that ACCEPTS connections but never drains would otherwise
		// reset the backoff on every call (connect succeeds, write times out),
		// taxing the drain goroutine up to writeTimeout + dial (5s) +
		// writeTimeout — three serialized network ops (~15s worst case) under
		// s.mu. Arm the backoff so subsequent lines fast-drop for the window.
		s.conn.Close() //nolint:errcheck // best-effort; the conn is being discarded
		s.conn = nil
		now = time.Now()
		s.armBackoffLocked(now)
		return s.noteFailureLocked(classifyErr(err3, false), now)
	}
	return s.noteSuccessLocked(time.Now())
}

// notifyDelivery hands an outcome to the optional observer.
//
// The healthy steady state costs NOTHING beyond the branch: a delivery that
// landed while nothing was failing is not an event, so the common case (one
// line per proxied request on a working collector) never reaches the observer,
// never loads the pointer and never allocates. Only a FAILURE or the FIRST
// success after a failing run is reported, which is exactly the transition
// evidence the health plane needs.
//
// The observer runs on the drain goroutine with s.mu already released, and is
// panic-contained for the same reason the panic observer is: a bad observer
// must never take down SIEM delivery, let alone the gateway.
func (s *Writer) notifyDelivery(out DeliveryOutcome) {
	if out.OK && !out.Recovered {
		return
	}
	p := s.deliveryObserver.Load()
	if p == nil {
		return
	}
	defer func() { _ = recover() }()
	(*p)(out)
}

// SetDeliveryObserver publishes an optional observer notified synchronously, on
// the drain goroutine, whenever a line FAILS to reach the collector or the
// first line lands after a failing run. This package is a stdlib-only leaf with
// no logging or alerting dependency (see the package doc), so package main
// wires this the same way it wires SetPanicObserver — the seam exists so the
// health plane learns about a dead SIEM from the EVENT rather than from
// whoever happens to scrape next. A nil fn clears it.
func (s *Writer) SetDeliveryObserver(fn func(DeliveryOutcome)) {
	if fn == nil {
		s.deliveryObserver.Store(nil)
		return
	}
	s.deliveryObserver.Store(&fn)
}

// sweepQueue counts every still-buffered line as a drop. Called once, from the
// drain goroutine's exit path, after the flush window has closed.
//
// The residual is bounded and documented: a sender that read s.closed as false
// before Close set it can still land a line after this sweep. That sender
// necessarily started before Close did, so the window is one goroutine's
// scheduling delay rather than anything open-ended, and it costs at most the
// lines already in flight at the instant of shutdown.
func (s *Writer) sweepQueue() {
	for {
		select {
		case <-s.queue:
			s.drops.Add(1)
		default:
			return
		}
	}
}

// Drops reports the number of messages dropped because the collector was
// unreachable or not draining, the delivery queue overflowed, or the Writer
// was already closed. Monotonic per Writer; delivery is otherwise
// silent-best-effort, so this is the only loss signal.
func (s *Writer) Drops() uint64 { return s.drops.Load() }

// Delivered reports how many lines the collector socket ACCEPTED. Together with
// LastSuccess it is the only positive evidence this package can offer that the
// feed is alive — a successful dial proves nothing after the instant it
// happened, and on UDP it proves nothing at all.
func (s *Writer) Delivered() uint64 { return s.delivered.Load() }

// Stats is a consistent-enough, LOCK-FREE snapshot of the delivery record.
//
// Lock-free is a requirement, not a convenience: the drain goroutine holds s.mu
// across dial + write + write, so a mutex-guarded accessor would make every
// operator surface that reads it — the diagnostics row, /metrics, /healthz,
// GET /api/syslog — hang for as long as the collector is wedged. A health plane
// that stalls on the fault it is reporting is worse than no health plane.
//
// The fields are independent atomics written by a single goroutine under s.mu,
// so a snapshot can straddle one delivery. Every consumer is a report, and no
// verdict is derived from two fields whose skew could change it.
type Stats struct {
	Network     string        // "udp" or "tcp"; immutable
	Delivered   uint64        // lines the socket accepted
	Drops       uint64        // lines that never reached the collector
	QueueFull   uint64        // subset of Drops caused by the queue, not the collector
	Panics      uint64        // lines lost to a recovered delivery panic
	Consecutive int64         // consecutive failures; 0 = the last line landed
	LastReason  string        // bounded class of the most recent failure
	LastSuccess time.Time     // zero = NOTHING has ever been delivered
	FirstFail   time.Time     // zero = not currently failing
	LastFail    time.Time     //
	Backoff     time.Duration // current reconnect delay; 0 when healthy
}

// Stats returns the delivery record. Safe to call from any goroutine.
func (s *Writer) Stats() Stats {
	st := Stats{
		Network:     s.network,
		Delivered:   s.delivered.Load(),
		Drops:       s.drops.Load(),
		QueueFull:   s.queueFull.Load(),
		Panics:      s.panics.Load(),
		Consecutive: s.consecFail.Load(),
		Backoff:     time.Duration(s.backoffNanos.Load()),
	}
	if p := s.lastReason.Load(); p != nil {
		st.LastReason = *p
	}
	if n := s.lastSuccessNano.Load(); n != 0 {
		st.LastSuccess = time.Unix(0, n)
	}
	if n := s.firstFailNano.Load(); n != 0 {
		st.FirstFail = time.Unix(0, n)
	}
	if n := s.lastFailNano.Load(); n != 0 {
		st.LastFail = time.Unix(0, n)
	}
	return st
}

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
// Deliberately LOCK-FREE. format is written once before the Writer is published
// and never again, so the mutex bought nothing — while costing everything: the
// drain goroutine holds s.mu across dial + write + write, so this accessor
// blocked for up to ~15 s against a wedged collector, and its only caller is
// GET /api/syslog, the admin surface an operator opens BECAUSE the SIEM looks
// wrong (CHAOS-66). A management-plane read must never queue behind the fault
// it is being used to diagnose.
func (s *Writer) Format() string { return s.format }

// Network returns the transport ("udp" or "tcp"). Immutable, so lock-free for
// the same reason as Format.
func (s *Writer) Network() string { return s.network }
