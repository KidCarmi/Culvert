package syslog

// observability.go — what the SIEM feed can say about its own losses.
//
// # Why this file exists
//
// Delivery in this package is best-effort by design: a slow or wedged
// collector must cost a counter, never proxy latency. That posture is correct
// and is unchanged here. What was missing is the other half of it — a
// best-effort sink is only acceptable when the "effort" that failed is
// VISIBLE, and this one's was not.
//
// Before this file, the entire loss surface of the SIEM feed was a single
// monotonic Drops() counter with exactly one reader in the whole tree: the
// admin-only GET /api/syslog JSON blob. There was no /metrics series, no
// /healthz field, no alert, and not one log line. The feed carries BOTH the
// audit trail (WriteAudit) and the request log (WriteRequest) to the
// customer's SIEM, so that is the centralized security record going silently
// missing — CWE-778 / OWASP A09:2021, the same finding internal/audit closed
// for its local file (ST-8) and internal/audit's cluster push queue closed for
// the DP→CP path (CL-21). The one sink that had neither was the one that
// leaves the appliance.
//
// # What this file adds, and what it deliberately does not
//
// It adds CLASSIFICATION and EVIDENCE, and no posture change whatsoever:
//
//   - Every drop is charged to a BOUNDED reason class as well as the total, so
//     an operator is told which of four different remediations applies. The
//     rule is CHAOS-65's: a counter an operator is told to act on is charged
//     only from evidence supporting the specific claim its runbook makes.
//     "The collector is unreachable" and "the collector is slower than this
//     gateway's line rate" are different faults with different fixes, and they
//     were the same number.
//
//   - A successful delivery stamps lastDeliveryNano, and a failure episode
//     stamps failingSinceNano. These are the OBSERVED EVIDENCE the health
//     plane keys recovery on — never elapsed time, per the standing rule in
//     ca_health.go and storage_health.go.
//
//   - A delivery observer seam (SetDeliveryObserver), shaped exactly like the
//     existing SetPanicObserver, so package main can log and alert without
//     this package acquiring a logging dependency. It fires on TRANSITIONS
//     only — the first failure after health, the first success after failure —
//     so it can never run per line on the request path.
//
// # Two invariants that are load-bearing
//
// **(1) Every accessor here is an ATOMIC read and must stay one.** It is
// tempting to guard the delivery state with s.mu, which already protects conn
// and format. That mutex is held by the drain goroutine across the whole
// reconnect/backoff state machine — up to writeTimeout + dial + writeTimeout,
// about 15 seconds against a collector that accepts and never drains. A
// /metrics scrape or a /healthz probe that took it would therefore BLOCK for
// fifteen seconds on precisely the fault it exists to report, turning a SIEM
// outage into a monitoring outage. The health plane must be readable when the
// delivery path is wedged, which is the only time anyone needs to read it.
// Pinned by TestObservability_AccessorsDoNotTakeTheDeliveryMutex.
//
// **(2) An idle Writer is not a failing Writer.** Degradation must never be
// derived from "time since the last successful delivery": a gateway with no
// traffic sends no lines, so that clock advances with no fault present and
// every quiet appliance would eventually page. failingSinceNano is armed by an
// OBSERVED failure and cleared by an OBSERVED success, so silence reports
// nothing in either direction. This is CHAOS-57's lesson (the evidence must
// match the claim) applied before it could be made again.
//
// # The limit of what any of this can prove, on UDP
//
// UDP is this package's DEFAULT transport (InitSyslog picks it when the
// address carries no scheme). A connected UDP socket to a collector that does
// not exist accepts every write: there is no handshake to refuse and, as
// measured on the reference container, no ICMP error surfaces on a subsequent
// send either. So on UDP, `NewWriter` SUCCEEDS against a dead collector, every
// line is written successfully into the void, and Drops() stays at zero
// forever.
//
// Nothing in this file changes that, and no signal it exports should be read
// as claiming otherwise. DeliveryConfirmable() reports it honestly — false for
// UDP — so the operator surfaces can say, in the one place an operator looks,
// that "active" means "the socket is open", never "the collector received it".
// An operator who needs delivery assurance must use tcp://. That is a property
// of the protocol, not a defect this sweep can close, and it is recorded
// rather than papered over.

import (
	"math/rand/v2"
	"sync/atomic"
	"time"
)

// DropReason is the bounded classification of why one line never reached the
// collector. It is BOUNDED on purpose: these values reach an alert Detail, and
// alerts.Store.Dispatch dedups on event+Detail, so an unbounded reason gives
// the dedup key one value per failure and lets a SIEM outage evict real threat
// alerts from the retry queue (the WK-12/RS-5 defect).
type DropReason string

const (
	// DropCollectorUnreachable — the connection was down and could not be
	// re-established, or the reconnect backoff window was still open.
	// Operator action: fix the collector or the network path to it.
	DropCollectorUnreachable DropReason = "collector_unreachable"

	// DropWriteFailed — a connection existed and the write failed, and the
	// reconnect-and-retry behind it failed too. Typically a collector that
	// accepts connections and then stops draining, or a peer reset.
	DropWriteFailed DropReason = "write_failed"

	// DropQueueFull — delivery is slower than the rate at which this gateway
	// produces lines, so the bounded queue overflowed. Distinct from the two
	// above because the remediation is capacity, not reachability: either the
	// collector is under-provisioned for this node's traffic, or delivery is
	// stalled and the queue is the symptom rather than the cause.
	DropQueueFull DropReason = "queue_full"

	// DropWriterClosed — a send raced Close. Benign; counted so the totals
	// reconcile rather than quietly disagreeing.
	DropWriterClosed DropReason = "writer_closed"

	// DropDeliveryPanic — a panic was contained in the drain goroutine and the
	// line was lost with it (CHAOS-24). Always zero in a healthy process; a
	// non-zero value is a bug being contained rather than crashing the
	// gateway.
	DropDeliveryPanic DropReason = "delivery_panic"
)

// dropReasons is the iteration order for DropsByReason. Fixed and exhaustive:
// a new reason added to the constants above without a slot here would be
// counted and never reported, which is the silent-loss defect this file
// exists to close, one level up. Pinned by TestDropReasons_AreExhaustive.
var dropReasons = [...]DropReason{
	DropCollectorUnreachable,
	DropWriteFailed,
	DropQueueFull,
	DropWriterClosed,
	DropDeliveryPanic,
}

// dropIndex maps a reason to its counter slot.
func dropIndex(r DropReason) int {
	for i, known := range dropReasons {
		if known == r {
			return i
		}
	}
	return -1
}

// DeliveryState is the transition reported to a delivery observer.
type DeliveryState int

const (
	// DeliveryFailing is reported once when a healthy feed starts failing.
	DeliveryFailing DeliveryState = iota
	// DeliveryRecovered is reported once when a failing feed delivers again.
	DeliveryRecovered
)

// DeliveryEvent describes one delivery-state transition.
type DeliveryEvent struct {
	// State is the direction of the transition.
	State DeliveryState

	// Reason is the bounded class of the failure that opened the episode. Empty
	// on DeliveryRecovered.
	Reason DropReason

	// Drops is the cumulative drop total at the moment of the transition. On
	// DeliveryRecovered this lets the observer report the magnitude of the
	// episode without keeping its own counter.
	Drops uint64

	// FailingFor is how long the episode lasted, on DeliveryRecovered. Zero on
	// DeliveryFailing.
	FailingFor time.Duration
}

// deliveryObs holds the observability state for one Writer. Embedded by value
// in Writer; every field is an atomic so that reads never touch s.mu (see
// invariant (1) in the file header).
type deliveryObs struct {
	byReason [len(dropReasons)]atomic.Uint64

	// lastDeliveryNano is the wall time of the last line the transport
	// accepted, as UnixNano. Zero until the first successful delivery.
	lastDeliveryNano atomic.Int64

	// failingSinceNano is the wall time at which the CURRENT uninterrupted
	// failure episode began, as UnixNano. Zero when the feed is healthy or
	// merely idle — never set by the passage of time, only by an observed
	// failure (invariant (2)).
	failingSinceNano atomic.Int64

	// lastFailureReason is the bounded class that opened the current episode,
	// stored as a string so it fits an atomic.Value-free int-indexed slot.
	lastFailureIdx atomic.Int64

	// deliveryObserver is notified on transitions only. Same seam shape as
	// panicObserver.
	deliveryObserver atomic.Pointer[func(DeliveryEvent)]

	// pending holds a transition observed while s.mu was held, waiting to be
	// delivered once it is released. See stageDelivery.
	pending atomic.Pointer[DeliveryEvent]
}

// noteDrop charges one lost line to the total and to its bounded reason class,
// and arms the failure episode if this is the first failure after health.
//
// DropQueueFull and DropWriterClosed deliberately do NOT arm a delivery
// episode. Neither is evidence about the COLLECTOR: a full queue says the
// drain could not keep up (which, when the cause is an unreachable collector,
// is already reported by the reachability drops the drain itself charges), and
// a post-Close send says only that the process is shutting down. Arming on
// them would let an ordinary shutdown race, or a burst on a healthy but
// under-provisioned link, page as a SIEM outage.
func (s *Writer) noteDrop(reason DropReason) {
	s.drops.Add(1)
	if i := dropIndex(reason); i >= 0 {
		s.byReason[i].Add(1)
	}
	switch reason {
	case DropCollectorUnreachable, DropWriteFailed:
		s.noteDeliveryFailure(reason)
	case DropQueueFull, DropWriterClosed, DropDeliveryPanic:
		// Not collector evidence — see the doc comment.
	}
}

// noteDeliveryFailure opens a failure episode if one is not already open, and
// notifies the observer exactly once per episode.
func (s *Writer) noteDeliveryFailure(reason DropReason) {
	now := time.Now()
	idx := int64(dropIndex(reason))
	// CompareAndSwap from zero is what makes this once-per-episode: a
	// concurrent second failure loses the swap and reports nothing. Only the
	// drain goroutine reaches here today, but the guarantee is structural
	// rather than by convention, so a future second caller cannot double-page.
	if !s.failingSinceNano.CompareAndSwap(0, now.UnixNano()) {
		return
	}
	s.lastFailureIdx.Store(idx)
	s.stageDelivery(DeliveryEvent{
		State:  DeliveryFailing,
		Reason: reason,
		Drops:  s.drops.Load(),
	})
}

// noteDeliverySuccess records OBSERVED evidence that the transport accepted a
// line, and closes any open failure episode.
//
// This is the only thing that clears a degradation anywhere in this feed's
// health plane. Elapsed time never does: a feed that stopped reporting
// failures because nothing is being sent looks identical to a healthy one.
func (s *Writer) noteDeliverySuccess() {
	now := time.Now()
	s.lastDeliveryNano.Store(now.UnixNano())
	since := s.failingSinceNano.Swap(0)
	if since == 0 {
		return // was already healthy; nothing to report
	}
	failingFor := now.Sub(time.Unix(0, since))
	if failingFor < 0 {
		failingFor = 0 // clock stepped backwards under us; report no negative span
	}
	s.stageDelivery(DeliveryEvent{
		State:      DeliveryRecovered,
		Drops:      s.drops.Load(),
		FailingFor: failingFor,
	})
}

// stageDelivery records a transition for delivery once the caller has released
// s.mu.
//
// It does NOT invoke the observer inline, and that is the whole point.
// noteDeliverySuccess and the reachability branches of noteDrop are reached
// from deliverLine, which holds s.mu across the entire reconnect/backoff state
// machine. Calling an observer from there hands control to arbitrary caller
// code while the delivery mutex is held, so an observer that touches ANY
// mutex-guarded API — Format(), Close(), a status readback for the log line it
// is building — SELF-DEADLOCKS the drain goroutine permanently, taking down
// all SIEM delivery for the life of the process.
//
// That is not hypothetical: the first version of this file called the observer
// inline and was caught by exactly that probe (an observer calling Format()
// deadlocked on the recovery transition). It is also the invariant the
// SetPanicObserver comment had already written down for the OTHER observer on
// this path — "runs AFTER deliverLine's own deferred mutex unlock has already
// fired during unwind, so it never needs s.mu" — which was true for that one
// because a panic unwinds through the unlock, and was quietly broken for this
// one because a normal return does not.
//
// A convention ("observers must not take the mutex") would have been the
// cheaper fix and the wrong one: the constraint is invisible at the call site,
// and the failure mode is a permanently wedged delivery goroutine. So the
// staging is structural instead.
func (s *Writer) stageDelivery(ev DeliveryEvent) {
	if s.deliveryObserver.Load() == nil {
		return // nothing to deliver to; do not accumulate
	}
	s.pending.Store(&ev)
}

// flushPendingDelivery invokes the observer for any staged transition. Callers
// MUST have released s.mu.
//
// Contained so a bad observer can never take down the drain goroutine — the
// same containment SetPanicObserver's callback gets, for the same reason.
func (s *Writer) flushPendingDelivery() {
	ev := s.pending.Swap(nil)
	if ev == nil {
		return
	}
	p := s.deliveryObserver.Load()
	if p == nil {
		return
	}
	defer func() { _ = recover() }()
	(*p)(*ev)
}

// SetDeliveryObserver publishes an optional observer notified on the drain
// goroutine whenever the feed transitions between delivering and failing.
//
// This package is a stdlib-only leaf with no logging or alerting dependency
// (see the package doc), so this is the seam package main uses to reach the
// process log, /metrics, the operator-contract row and the alert plane —
// mirroring SetPanicObserver, fileutil's and internal/audit's write-failure
// observers.
//
// The observer runs on TRANSITIONS only, never per line, so it may do real
// work (log, alert) without becoming a per-request cost. It MUST NOT call back
// into this Writer's send path: doing so from a failure transition re-enters
// delivery while the drain goroutine is inside it. A nil fn clears it.
func (s *Writer) SetDeliveryObserver(fn func(DeliveryEvent)) {
	if fn == nil {
		s.deliveryObserver.Store(nil)
		return
	}
	s.deliveryObserver.Store(&fn)
}

// DropsByReason reports the per-class breakdown of lost lines. The sum equals
// Drops() for every drop charged through noteDrop.
//
// Atomic reads only — never takes s.mu (invariant (1)).
func (s *Writer) DropsByReason() map[DropReason]uint64 {
	out := make(map[DropReason]uint64, len(dropReasons))
	for i, reason := range dropReasons {
		out[reason] = s.byReason[i].Load()
	}
	return out
}

// LastDelivery reports when the transport last accepted a line, or the zero
// time if it never has. Atomic read only.
func (s *Writer) LastDelivery() time.Time {
	n := s.lastDeliveryNano.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// FailingSince reports when the current uninterrupted failure episode began,
// or the zero time when the feed is healthy or idle. Atomic read only.
func (s *Writer) FailingSince() time.Time {
	n := s.failingSinceNano.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// LastFailureReason reports the bounded class that opened the current episode,
// or "" when no episode is open. Atomic read only.
func (s *Writer) LastFailureReason() DropReason {
	if s.failingSinceNano.Load() == 0 {
		return ""
	}
	i := s.lastFailureIdx.Load()
	if i < 0 || int(i) >= len(dropReasons) {
		return ""
	}
	return dropReasons[i]
}

// DeliveryConfirmable reports whether this Writer's transport can observe a
// delivery failure at all.
//
// TCP can: a refused connect or a failed write is a real signal, and every
// surface downstream of this package is built on that. UDP cannot — see the
// file header. An operator surface that reports a UDP feed as "active" is
// making a claim about the SOCKET, not about the collector, and it must say
// so; this is the accessor that lets it.
func (s *Writer) DeliveryConfirmable() bool { return s.network != "udp" }

// Network reports the transport ("udp" or "tcp"). Immutable after
// construction, so no synchronisation is needed.
func (s *Writer) Network() string { return s.network }

// QueueCap reports the bounded delivery queue's capacity, so the operator
// surfaces can express a queue_full drop as a fraction of a known bound rather
// than as a bare number.
func (s *Writer) QueueCap() int { return queueCap }

// reconnectWindow is how long a failed reconnect suppresses the next attempt.
//
// Jittered by ±20% (jitterFraction) because a SIEM outage is a FLEET event:
// every node's collector goes away at the same instant, so an unjittered fixed
// window has every gateway in the estate retrying in lockstep at exactly the
// same cadence, aimed at a collector that is by hypothesis already struggling
// — and the moment it comes back it is met with the whole fleet's reconnects
// in one burst. Same reasoning, and the same ±20%, as the HA lease recovery
// loop and internal/feedsched's per-round jitter.
//
// The DIRECTION of the bound is unchanged: the window is a rate limit on
// reconnect attempts, and jitter only spreads them within it.
const (
	reconnectWindow = 5 * time.Second
	jitterFraction  = 0.2
)

// jitteredReconnectWindow returns reconnectWindow ± 20%.
//
// Uses math/rand/v2's per-P generator: this is called on the drain goroutine
// while s.mu is held, so a shared seeded source would be one more contended
// thing under a mutex that already spans network operations.
func jitteredReconnectWindow() time.Duration {
	span := float64(reconnectWindow) * jitterFraction
	delta := (rand.Float64()*2 - 1) * span // #nosec G404 -- fleet spread, not crypto
	return time.Duration(float64(reconnectWindow) + delta)
}
