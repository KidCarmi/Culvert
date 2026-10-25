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
	"runtime"
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

	// CHAOS-81 delivery evidence. Drops alone is a CUMULATIVE counter with no
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
	// finalStats is published by the drain goroutine, under sendMu held
	// EXCLUSIVELY, as the last thing it does before closing done. It is the
	// cumulative snapshot as of the instant this Writer stopped being the
	// only thing moving its counters, which is what lets a consumer folding
	// those totals into a process-lifetime accumulator take a FINAL value.
	//
	// The counters THEMSELVES keep moving after it — a caller holding a stale
	// handle still records its loss on the Writer, so anything reading the
	// Writer's own episode state (is it failing NOW, since when, why) keeps
	// seeing the truth. Only the CUMULATIVE totals have a second home, and
	// only those are frozen here, because only those are folded elsewhere and
	// could therefore be counted twice.
	finalStats atomic.Pointer[Stats]

	// retired is set by the owner when it stops reading this Writer's
	// cumulative counters and folds them into its own accumulator. Together
	// with finalStats it is what decides where a late loss is counted: see
	// chargeTerminalDrop. It must be set BEFORE Close, or a loss landing
	// between the seal and the mark is counted nowhere.
	retired atomic.Bool

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

	// inFlight counts senders between registering and finishing their enqueue.
	// Close waits for it to reach zero BEFORE telling drainLoop to stop, which
	// is what stops a sender that already passed the closed check from
	// enqueueing into a queue whose drain goroutine has since exited. Without
	// it such a line is neither delivered nor counted in Drops — silent loss,
	// invisible on every surface (CHAOS-78, Codex round 1).
	// sendMu (above) now provides the same exclusion; the registration is
	// kept so Close's bounded waitForSenders still observes every sender.
	inFlight atomic.Int64
}

// DialTimeout bounds the ONE blocking step in NewWriter: the connect. It is
// exported because the health plane has to know how long a caller's
// synchronous NewWriter/InitSyslog can take before it has a verdict — a
// recorded intent whose dial is still in flight is not yet an unmet one, and
// deriving that window from this constant is what stops the two drifting
// (Codex P2, PR #1494). Everything else NewWriter does is a hostname lookup
// and a channel allocation.
const DialTimeout = 5 * time.Second

// maxHandoffHops bounds how far a line follows successor links (a run of
// back-to-back re-points). Past it the line is dropped and counted.
const maxHandoffHops = 8

// enqueueResult is the outcome of one tryEnqueue.
type enqueueResult int

const (
	enqAccepted  enqueueResult = iota // queued for the drain goroutine
	enqDropped                        // queue full on the writer in service; already counted as a drop
	enqClosed                         // writer closed; NOT counted — caller decides
	enqDisplaced                      // queue full on a REPLACED writer; NOT counted — caller follows the successor
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
// lateDrops counts losses charged to a Writer that no surface reads any more.
//
// The health plane's process-lifetime total is `retiredDrops` (each displaced
// Writer's finals, folded at the moment it is displaced) plus the LIVE
// Writer's own counters. A drop recorded against an intermediate Writer AFTER
// its finals were folded therefore lands nowhere: it is real compliance loss
// that `culvert_syslog_drops_total` and `/healthz` never report.
//
// Two sites can produce one, both of them the terminal branch of a bounded
// successor walk — `send` and `handOffQueued` past `maxHandoffHops`. Each
// needs a chain longer than the bound, i.e. more rapid re-points than that
// while a caller still holds a stale Writer, so it is rare; it is counted
// rather than argued away because "did not reach the SIEM" is the one series
// this plane exists to keep honest, and a rare undercount there is still an
// undercount (Codex P2, PR #1494).
//
// The boundary is SEALING, not displacement, and that distinction is the whole
// of it. The first version keyed on "this Writer was displaced, so its finals
// were folded" — but the fold is taken when the Writer is displaced, while its
// drain is still flushing, so every loss the final flush records lands after
// the fold and is held by no counter any surface reads. Measured against the
// real disable path with a dead collector: of 2000 events the Writer itself
// counted all 2000 (1999 drops + 1 delivered) and the exported total reported
// between 32 and 1999 fewer — in one trial `culvert_syslog_drops_total` read
// ZERO for a feed that had just lost everything, which is the loss-history
// erasure P2-4 exists to prevent, arriving through the WRITE side after P2-4
// closed the read side.
//
// So the two accountings are made disjoint by construction rather than by
// argument. The owner FOLDS a Writer's cumulative totals from the snapshot
// the drain publishes as it exits (Sealed/FinalStats), never from the live
// counters, and a loss is charged here only once the owner has RETIRED the
// Writer and that snapshot exists. chargeTerminalDrop decides both halves
// under one lock, so a loss can never be counted twice and never nowhere.
var lateDrops atomic.Uint64

func noteLateDrop() { lateDrops.Add(1) }

// Sealed reports whether the drain goroutine has exited and published this
// Writer's cumulative snapshot. It does NOT mean the counters stop moving: a
// caller holding a stale handle still records its losses here, which is what
// keeps the episode state (is it failing NOW, since when, why) honest. What
// it means is that FinalStats is available, and that a consumer folding these
// totals elsewhere must switch to it.
//
// A zero-value (synchronous) Writer has no drain goroutine and is never
// sealed; nothing folds its totals either.
func (s *Writer) Sealed() bool { return s.finalStats.Load() != nil }

// FinalStats returns the cumulative snapshot taken when this Writer sealed,
// and whether it has sealed at all. A consumer that folds this Writer's
// totals into a process-lifetime accumulator must use THIS once it is
// available: the live counters keep moving afterwards, and every one of those
// later losses is already charged to LateDrops, so folding the live value
// instead would count them twice.
func (s *Writer) FinalStats() (Stats, bool) {
	if p := s.finalStats.Load(); p != nil {
		return *p, true
	}
	return Stats{}, false
}

// CumulativeStats returns the snapshot a FOLDING consumer must use — the
// sealed finals once this Writer has sealed, the live counters until then —
// together with whether it has sealed.
//
// A consumer that instead calls FinalStats() and then falls back to Stats()
// has the two reads in the WRONG ORDER, and the Writer can seal between them.
// Its live counters keep moving after the seal (deliberately — see
// chargeTerminalDrop), and every post-seal loss is ALREADY charged to
// lateDrops, so folding that live value counts the same loss twice. Worse, the
// next settle reads the sealed snapshot, which is SMALLER than the live value
// already folded, so the delta goes negative and the exported
// culvert_syslog_drops_total DECREASES — the one thing a Prometheus counter
// may not do, and precisely the contract the sealing boundary exists to keep
// (Codex P2, PR #1494).
//
// The order below is what makes the pair safe, and it needs no lock:
//
//   - If the seal is present, the finals ARE the answer, exactly.
//   - If it is absent, the Writer had not sealed at the LATER of the two
//     reads, so it had not sealed at the earlier one either. The live value
//     therefore predates the seal and cannot exceed the finals that follow —
//     so a folded value is never succeeded by a smaller one, which is the
//     whole guarantee.
//
// Reading both under sendMu would also be exact, and it was the first shape.
// It deadlocks, and the ordering argument is what replaces it. Both folding
// consumers run with syslogHealth.mu held, while a line refused by tryEnqueue
// charges its drop holding sendMu.RLock and notifies the delivery observer
// from there — which takes syslogHealth.mu. That is a lock-order inversion,
// and with a Close() blocked on sendMu.Lock in between (which stops any new
// reader barging in) it is a three-way cycle, not a window: measured, with
// TestChaos81_WriterHandleIsSafeUnderConcurrentRepointAndTraffic hanging to
// the test timeout and the dump naming all three edges.
//
// So no lock may be taken here at all, however briefly: this is called from
// under the very mutex that this Writer's delivery observer goes on to take.
func (s *Writer) CumulativeStats() (Stats, bool) {
	live := s.Stats()
	if p := s.finalStats.Load(); p != nil {
		return *p, true
	}
	return live, false
}

// chargeTerminalDrop records a loss against a Writer that refused a line and
// could not hand it on, and reports whether that loss must ALSO be charged to
// the process-lifetime late-drop counter.
//
// Both halves are decided under the SHARED side of sendMu, which the drain
// goroutine takes exclusively to publish its final snapshot. That is what
// makes the split exact: a charge either wins the race and is inside the
// snapshot, or loses it and is routed to lateDrops instead — never both.
//
// The Writer's own counters move either way. Freezing them was the first
// shape and it was wrong in a way worth recording: a Writer that is sealed
// but still INSTALLED (a drain that exits under a still-published handle)
// would then stop reporting that it is failing at all, so the degradation
// predicate — which reads ConsecutiveFailures and FailingSince off the live
// Writer — went blind on exactly the feed that had just lost its drain.
//
// A loss is late only when BOTH are true: the owner has RETIRED this Writer
// (so it no longer reads these counters) and the Writer has SEALED (so the
// owner's final fold is already taken and cannot include this loss). Either
// alone gets it wrong in one direction — an unretired sealed Writer's losses
// are still read live, so charging them late would count them twice, while a
// retired unsealed Writer's losses are still inside the fold to come.
func (s *Writer) chargeTerminalDrop(reason *string) (late bool) {
	s.sendMu.RLock()
	defer s.sendMu.RUnlock()
	s.noteDrop(reason)
	return s.retired.Load() && s.finalStats.Load() != nil
}

// MarkRetired records that the owner has folded this Writer's cumulative
// counters into its own accumulator and will stop reading them.
//
// Call it BEFORE Close. Sealing is what ends the fold, so a loss landing
// after the seal but before this mark is in neither the fold nor the late
// counter — the one ordering that loses a loss outright.
func (s *Writer) MarkRetired() { s.retired.Store(true) }

// LateDrops returns the process-lifetime count of losses that were charged to
// a displaced Writer whose totals had already been retired. The health plane
// folds it into the exported drop total; see lateDrops.
func LateDrops() uint64 { return lateDrops.Load() }

// ProbeOutcome is the result of one probed line, reported by the drain
// goroutine of the Writer that ACTUALLY SENT IT.
//
// Provable is that sending Writer's DeliveryProvable(), never the one the
// caller handed to WriteProbe. The two differ: handOffQueued moves a queued
// line — its ack channel included — to a successor that may speak a different
// transport, so a probe queued on a TCP writer and handed off to a UDP one was
// reported with the TCP sentence ("the collector accepted the test event") for
// a datagram nothing may have received (Codex P2, PR #1494). Binding the
// transport to the Writer the caller holds was the previous round's fix and
// was correct exactly one hop short: the acknowledgement has to carry the
// transport, because only the sender knows it.
type ProbeOutcome struct {
	Delivered bool
	Provable  bool
	// Reason is the bounded failure class for THIS line, stamped by the
	// Writer that actually attempted (or refused) the send. Empty when
	// Delivered.
	//
	// It travels on the acknowledgement for the same reason Provable does: a
	// handoff moves a queued line and its ack together to a successor, so the
	// Writer the prober called is one hop short of the sender and its
	// writer-wide LastFailureReason can be `unknown` or an unrelated line's
	// class. Reading that field at ack time would ALSO repeat the defect the
	// per-line ack was introduced to fix, since a concurrent line's failure
	// can overwrite it between the drop and the read (Codex P2, PR #1494).
	Reason string
}

type queuedLine struct {
	line   string
	ack    chan ProbeOutcome // buffered(1) when set; receives the outcome of THIS line
	format string            // the format line is encoded in
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

// senderDrainTimeout bounds Close's wait for in-flight senders to finish
// enqueueing (see waitForSenders). Senders in that window do CPU work and a
// non-blocking send only, so this is a safety bound and not an expected cost.
const senderDrainTimeout = 1 * time.Second

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
		// Seal BEFORE done is closed, and under sendMu held exclusively, so a
		// caller's terminal charge cannot interleave: chargeTerminalDrop reads
		// the seal and increments the counters under the SHARED side of the
		// same lock, so every loss is either inside this snapshot or routed to
		// lateDrops — never both, and never neither. Ordering it before
		// close(s.done) means a caller that observes done closed also observes
		// Sealed().
		s.sendMu.Lock()
		final := s.Stats()
		s.finalStats.Store(&final)
		s.sendMu.Unlock()
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
						ackQueued(item, nil, false, &reasonFlushTimeout)
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
	for hop := 0; ; hop++ {
		switch w.tryEnqueue(w.formatLine(pri, msg, time.Now())) {
		case enqClosed, enqDisplaced:
			// Both mean "this writer is not the one to use": sealed, or
			// replaced and already backed up. Neither is counted here, so
			// the walk below charges the loss exactly once if nobody takes it.
		default:
			return
		}
		nx := w.successor.Load()
		if nx == nil || nx.queue == nil {
			break
		}
		// Advance only when there is a hop left to SPEND on the successor.
		// The bound used to be checked at the top, so on exhaustion `w` held
		// a writer that was assigned and never tried — the line was charged
		// to a writer that had not refused it, and if that writer was the
		// live one the caller lost a line it would have accepted (Codex P2,
		// PR #1494). `w` is now always the last writer that actually refused.
		//
		// `hop` counts successor links already FOLLOWED, so this permits
		// exactly maxHandoffHops of them — the same budget handOffQueued
		// spends. Comparing hop+1 here stopped one short: with eight links
		// the eighth (often the live writer) was never offered the line
		// (Codex P2, PR #1494).
		if hop >= maxHandoffHops {
			break
		}
		w = nx
	}
	// Both terminals — the hop bound and the end of the chain — go through one
	// charge, because whether the loss is countable on `w` is a property of
	// `w`, not of which branch reached it. The end-of-chain writer is usually
	// the LIVE one, whose counters are read; after a disable it is a sealed
	// one, whose counters are not. Branching on the reason for stopping got
	// that second case wrong. See lateDrops.
	if w.chargeTerminalDrop(&reasonClosed) {
		noteLateDrop()
	}
}

// tryEnqueue hands one formatted line to the drain goroutine without
// blocking. A full queue on the writer in SERVICE is counted here; a closed or
// REPLACED writer is not, so the caller can hand the line off instead.
//
// A full queue is terminal backpressure only on a writer that is still the one
// in SERVICE. A writer that has been REPLACED answers enqDisplaced instead:
// uncounted, so the caller follows the successor chain exactly as it does for
// a closed writer. The two cases are one rule — a loss is only a loss once
// nobody better is available — and separating them is what stops a line dying
// on a wedged collector the operator has already moved off.
//
// The window is not narrow: releaseReplacedSyslogWriter names the successor
// BEFORE it closes the predecessor, and that close is ASYNCHRONOUS, so
// `successor != nil && !closed` is the ordinary state of a just-displaced
// writer — and its queue being full is the ordinary REASON for the re-point.
// Charging the drop there also accused the plane of a compliance loss that a
// healthy replacement was sitting idle to prevent (Codex P2, PR #1494).
//
// Order matters: the enqueue is attempted FIRST, so a displaced writer whose
// queue still has room keeps taking the line (its drain hands it on). Only a
// REFUSAL consults the successor. A successor published between the failed
// send and this load is simply not seen, which charges the drop as before —
// fail-safe, because the line was lost either way.
func (s *Writer) tryEnqueue(item queuedLine) enqueueResult {
	s.sendMu.RLock()
	defer s.sendMu.RUnlock()
	// Register BEFORE reading closed, and hold the registration across the
	// enqueue (CHAOS-78). sendMu above is what makes the check-and-enqueue
	// atomic with Close; the registration is what Close's waitForSenders
	// reads. Close stores closed, then waits for inFlight to drain, then
	// closes stop — so a sender visible to that wait either loses the race and
	// is refused below (its caller hands the line off or counts it), or wins
	// it and has its line already on the queue when drainLoop is told to
	// flush. Either way the line is accounted for.
	s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	if s.closed.Load() {
		return enqClosed
	}
	select {
	case s.queue <- item:
		return enqAccepted
	default:
	}
	if s.successor.Load() != nil {
		return enqDisplaced
	}
	s.noteDrop(&reasonQueueFull)
	return enqDropped
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
			ackQueued(item, w, false, &reasonQueueFull)
			return true // counted on the live writer by tryEnqueue
		}
		// enqClosed or enqDisplaced: this writer is not the one to use, so
		// keep walking. enqDisplaced reaches here when a run of rapid
		// re-points leaves an intermediate both replaced and backed up; its
		// full queue is no more terminal than its being closed would be.
		nx := w.successor.Load()
		if nx == nil {
			if w.chargeTerminalDrop(&reasonClosed) {
				noteLateDrop()
			}
			ackQueued(item, w, false, &reasonClosed)
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
	// From the drain loop, s is that drain's OWN Writer, so it is displaced
	// but cannot yet be sealed (sealing is the last thing that goroutine
	// does) and the charge lands on counters the health plane still folds.
	// WriteProbe also calls this for a writer that may already be sealed;
	// chargeTerminalDrop routes that case to the late-drop count.
	if s.chargeTerminalDrop(&reasonClosed) {
		noteLateDrop()
	}
	ackQueued(item, s, false, &reasonClosed)
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
// ackQueued reports one line's outcome. `by` is the Writer that performed (or
// failed) the send — NOT necessarily the one WriteProbe was called on, since a
// handoff moves the line and its ack together. It supplies the transport the
// outcome is about; nil means no Writer ever sent it, which cannot be
// provable.
// reasonOrEmpty dereferences a bounded reason pointer, yielding "" for none.
func reasonOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func ackQueued(item queuedLine, by *Writer, delivered bool, reason *string) {
	if item.ack == nil {
		return
	}
	out := ProbeOutcome{Delivered: delivered, Provable: by != nil && by.DeliveryProvable()}
	if !delivered {
		out.Reason = reasonOrEmpty(reason)
	}
	select {
	case item.ack <- out:
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
		_ = s.deliverGuarded(item.line)
		return
	}
	before := s.delivered.Load()
	reason := s.deliverGuarded(item.line)
	ackQueued(item, s, s.delivered.Load() > before, reason)
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
func (s *Writer) WriteProbe(msg string) (<-chan ProbeOutcome, bool) {
	ack := make(chan ProbeOutcome, 1)
	if s.queue == nil { // zero-value Writer: synchronous path
		before := s.delivered.Load()
		s.writeMsg(14, msg)
		delivered := s.delivered.Load() > before
		out := ProbeOutcome{Delivered: delivered, Provable: s.DeliveryProvable()}
		if !delivered {
			out.Reason = reasonOrEmpty(s.lastFailReason.Load())
		}
		ack <- out
		return ack, true
	}
	item := s.formatLine(14, msg, time.Now())
	item.ack = ack
	switch s.tryEnqueue(item) {
	case enqAccepted:
		return ack, true
	case enqDropped:
		return nil, false // queue full: already counted on s by tryEnqueue
	}
	// enqClosed or enqDisplaced: s is not the writer to probe. It was sealed
	// by a re-point after the caller captured it, or it has been replaced and
	// its own queue has backed up behind the collector the operator moved off.
	//
	// This used to call a single-writer `enqueue` helper that dropped straight
	// onto s. That helper is now gone rather than left unused: it was a second
	// caller-side enqueue path with DIFFERENT semantics from the one send
	// walks, and WriteProbe picking the wrong one is precisely how this defect
	// arose. A dead duplicate of a path that must not be chosen is an invitation
	// to choose it.
	// Follow the successor chain exactly as an ordinary line does, so the
	// REPLACEMENT collector is the one probed and a loss is charged where the
	// health plane can read it. Dropping directly on s instead reported a
	// healthy replacement as "dropped" and, once s was sealed, left the loss
	// out of the exported totals (Codex P2, PR #1494). The ack then arrives
	// from whichever writer dealt with the line.
	if s.handOffQueued(item) {
		return ack, true
	}
	if s.chargeTerminalDrop(&reasonClosed) {
		noteLateDrop()
	}
	return nil, false
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
	// Background context + DialTimeout is equivalent to the prior DialTimeout,
	// in the DialContext form the house lint rules require (CLAUDE.md).
	d := net.Dialer{Timeout: DialTimeout}
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
func (s *Writer) deliverGuarded(line string) (reason *string) {
	defer func() {
		if r := recover(); r != nil {
			s.panics.Add(1)
			s.noteDrop(&reasonPanic)
			reason = &reasonPanic
			if p := s.panicObserver.Load(); p != nil {
				func() {
					defer func() { _ = recover() }() // an observer must never crash the drain goroutine
					(*p)(r)
				}()
			}
		}
	}()
	return s.deliverLine(line)
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

// deliverLine returns the bounded reason it charged, or nil when the line was
// delivered. Returning it rather than leaving the caller to read
// LastFailureReason keeps a probe's answer about ITS OWN line: that field is
// writer-wide and a concurrent line's failure can overwrite it.
func (s *Writer) deliverLine(line string) *string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		// Backoff: don't retry more often than every 5 seconds.
		if time.Since(s.lastReconnErr) < 5*time.Second {
			s.noteDrop(&reasonBackoff)
			return &reasonBackoff
		}
		if err := s.connect(); err != nil {
			s.lastReconnErr = time.Now()
			s.noteDrop(&reasonConnectFail)
			return &reasonConnectFail // syslog down — swallow, never block the proxy
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
			return &reasonBackoff
		}
		if err2 := s.connect(); err2 != nil {
			s.lastReconnErr = time.Now()
			s.noteDrop(&reasonConnectFail)
			return &reasonConnectFail
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
			return &reasonWriteFail
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
	return nil
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
	// SUBTRACT the observed prefix; do not clear all-or-nothing.
	//
	// The first shape was CompareAndSwap(failuresBefore, 0), which resolves
	// the episode only when NOTHING raced it — and when something did, it
	// kept every failure, including the failuresBefore that this delivery had
	// just proved resolved. Those losses preceded the write's completion, so
	// by the rule above they are resolved; retaining them made every later
	// snapshot report them as losses SINCE this delivery, inflating the
	// current episode's count on the contract row and the admin surface (an
	// operator asking "how much have I lost since the feed last worked?" was
	// told the whole backlog). The degradation predicate is a boolean over
	// this count, so the page was never wrong — only the number an operator
	// acts on (Codex P2, PR #1494).
	//
	// Subtracting resolves exactly the prefix this delivery observed and
	// leaves exactly the failures recorded after it, which is round 6's
	// property stated precisely instead of all-or-nothing: a drop that raced
	// the write still survives, and now it survives ALONE.
	//
	// The loop is a CAS loop rather than a bare Add(-failuresBefore) because
	// an underflow here is not a smaller error, it is a catastrophic one: a
	// wrapped uint64 is a permanently non-zero failure count, i.e. a feed
	// reported as failing for the life of the process. Today it cannot
	// happen — only this function decreases the counter, and its sole
	// production caller is deliverLine on the single drain goroutine, holding
	// s.mu — but that is an argument about a CALLER, and the standing lesson
	// of this file is that such arguments are invalidated by later changes
	// without anyone noticing. The clamp makes the invariant local.
	if failuresBefore > 0 {
		for {
			cur := s.consecutiveFail.Load()
			next := uint64(0)
			if cur > failuresBefore {
				next = cur - failuresBefore
			}
			if !s.consecutiveFail.CompareAndSwap(cur, next) {
				continue
			}
			if next == 0 {
				// The episode ended. Recovery fires at most once per episode:
				// the next one starts at noteDrop's 0->1 edge.
				s.notifyDelivery(true)
				return
			}
			break
		}
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
//
// The comparison is exact rather than a prefix test, so any network this
// package does not construct today — "tcp4", "tcp6", a unix socket — reports
// FALSE and carries the caveat. That is the fail-safe direction: claiming a
// transport cannot prove delivery when it can costs an operator one
// unnecessary sentence, while the reverse tells them their SIEM has events it
// may never have received. A new provable transport must be added here
// deliberately.
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
	s.waitForSenders()
	s.closeOnce.Do(func() { close(s.stop) })
	select {
	case <-s.done:
	case <-time.After(closeWait):
	}
	return nil
}

// waitForSenders blocks until no sender sits between its registration and its
// enqueue, so closing stop cannot strand a line on an abandoned queue. closed
// is already true when this runs, so no NEW sender can reach the enqueue; the
// ones being waited for do only CPU work (formatMsg) and a non-blocking select,
// never a syscall, so this settles in microseconds.
//
// It is nonetheless bounded: a wait that cannot finish must not be able to hang
// shutdown. On expiry the pre-CHAOS-78 behavior resumes for whatever is still
// in flight, which is a line that may go unaccounted — strictly better than
// hanging, and recorded as the residual.
func (s *Writer) waitForSenders() {
	deadline := time.Now().Add(senderDrainTimeout)
	for s.inFlight.Load() > 0 {
		if time.Now().After(deadline) {
			return
		}
		runtime.Gosched()
	}
}

// Format returns the syslog message format ("rfc3164" or "rfc5424").
func (s *Writer) Format() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.format
}
