package policylearn

// M2 — the observation TRANSPORT (and nothing more): a bounded, non-blocking,
// drop-on-full channel from the runtime request path into one engine-owned
// drain goroutine. No aggregation, no category resolution, no persistence of
// observations — the drain validates, counts, hands the event to an injected
// sink (tests / M3), and otherwise discards it.
//
// The hard invariant (ADR-0025 §8): learning overloaded / panicking / slow /
// storage-less ⇒ normal enforcement continues unchanged + the observation is
// dropped and ACCOUNTED. The request path never waits: Observe is a lock-free
// gate check, bounded copy, and a non-blocking channel send. There is no retry,
// no auxiliary queue, and no per-observation goroutine.

import (
	"runtime"
	"sync"
	"sync/atomic"
)

const (
	// MaxObservationGroups bounds the groups carried per observation
	// (deterministic truncation — a pathological IdP claim set must not become
	// an unbounded copy on the request path).
	MaxObservationGroups = 16
	// observationQueueCap is the hard bound of the transport queue (~1–2 MB
	// worst case; the house 2048–4096 range for load-shedding queues).
	observationQueueCap = 4096
)

// Observation is the normalized per-decision event the runtime emits. Every
// field is SERVER-DERIVED (typed auth/policy state — F6); nothing here may
// originate from a client-controlled header or request field. Deliberately
// absent: URLs/paths/query strings, request headers/bodies, cookies,
// credentials, client IP (not needed by the M2 transport; M3 decides if
// distinct-subject evidence needs an address token), rule NAME (RuleID is the
// stable rename-safe attribution), and any open-ended metadata map.
//
// Subject carries the authoritative resolved identity TRANSIENTLY (queue +
// sink only — observations are never persisted in M2); M3 decides the durable
// representation (transformation/pseudonymization) before any identifier is
// stored. AuthSource is verbatim opaque provenance — its syntax is not
// canonical and must not be parsed or normalized. Empty Subject with
// AuthSource "unauth"/"exempt" is the explicit unauthenticated marker and must
// never be folded into group evidence (Groups is nil there by construction).
type Observation struct {
	// gen is the acceptance-window generation stamped at enqueue (Codex fix:
	// consumption attributes an event ONLY to the session whose window
	// accepted it — never to a later session). Engine-internal; never
	// serialized.
	gen uint64
	// catEpoch/policyID are the DECISION-TIME identity stamps (Codex round
	// 15): the churn latch must see the identities in effect when the
	// decision was made, not when the drain consumes the event — a transient
	// change (deny→allow→deny, taxonomy A→B→A) completing while the event
	// sat queued would otherwise leave the drain seeing only the restored
	// baseline, and the transient-window evidence would latch no churn.
	// Stamped by Observe from the injected identity seams (memoized at the
	// root — alloc-free reads); engine-internal, never serialized.
	catEpoch string
	policyID string

	At         int64    // unix seconds; stamped by the engine at accept when zero
	Subject    string   // resolved identity; "" = unauthenticated
	AuthSource string   // verbatim provenance ("local"/"exempt"/"unauth"/IdP source)
	Groups     []string // bounded copy of the resolved identity's groups
	Host       string   // normalized destination host only — never a URL
	Method     string
	RuleID     string // matched access-rule ULID; "" = default action
	Action     string // rule action, or "default:allow"/"default:deny"
	Status     string // the request-log Status taxonomy value for this decision
	SSLAction  string // "Inspect"/"Bypass" when resolved; "" on blocked branches

	// PolicyID/CatEpoch are the caller-supplied DECISION-TIME identity stamps
	// (Codex rounds 20/22): the producer captured (or derived a change
	// witness from) the state that actually determined enforcement/category
	// resolution, so the stamp cannot be a later value that a
	// flip-and-restore already re-baselined. When empty, Observe stamps the
	// corresponding seam's current value at enqueue instead (the prior
	// behavior; still used by paths with no decision-time capture). Opaque to
	// the engine — only compared for equality by the churn latch.
	PolicyID string
	CatEpoch string
}

// ObservationStats are the monotonic transport counters (loss accounting —
// future readiness computations must be unable to lie about transport loss).
type ObservationStats struct {
	Accepted       int64 // enqueued
	Dropped        int64 // whole observation lost: queue full at enqueue, transport closed, or no attributable session window at consume (closed/rotated window) — always counted, never silent
	Rejected       int64 // invalid (empty Host) — discarded
	ConsumerPanics int64 // sink panicked — event lost, drain continued
	Delivered      int64 // handed to the sink (or discarded clean when no sink)
	// GroupsTruncated counts ACCEPTED observations whose identity carried more
	// than MaxObservationGroups groups (M5B.1): the observation was kept but
	// attributes to only the first 16 groups, so group context is INCOMPLETE
	// for those events. Surfaced (never silent) so evidence can never imply
	// complete group coverage; deliberately NOT a Degraded() trigger — the
	// omitted groups simply receive no evidence (undercount, the safe
	// direction), while the retained cells' counts are exact.
	GroupsTruncated int64
}

// queuedItem is one transport-channel element: either an observation or a
// drain-barrier marker (barrier non-nil). FIFO through the SAME channel is
// what makes the barrier a proof: when the marker is consumed, every
// observation enqueued before it has been consumed too.
type queuedItem struct {
	o       Observation
	barrier chan struct{}
}

// transport is the engine-owned queue + single drain goroutine.
type transport struct {
	ch       chan queuedItem
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	// producers counts Observe calls between registration and the completion
	// of their enqueue decision; Close waits for it to reach zero AFTER
	// setting the closed flag, so an Observe that read closed == false can
	// never complete its send after the final sweep (Codex fix — the
	// check-then-send gap is otherwise unsynchronized with shutdown).
	producers atomic.Int64

	accepted        atomic.Int64
	dropped         atomic.Int64
	rejected        atomic.Int64
	panics          atomic.Int64
	delivered       atomic.Int64
	groupsTruncated atomic.Int64

	// consumeDropped is the CONSUME-side share of dropped: events that were
	// ACCEPTED (enqueued) and later discarded at consumption (closed/rotated
	// window). Engine-internal — the window-close loss accounting needs
	// "accepted but unresolved" (= accepted − delivered − consumeDropped −
	// panics), and the public Dropped counter also contains enqueue-side
	// drops (queue full / closed transport) that were never accepted, which
	// would deflate that quantity below zero under queue-full history.
	consumeDropped atomic.Int64
}

// waitProducers spins until no Observe call is between its registration and
// the completion of its enqueue decision. Callers must FIRST make the gate
// unpassable for new producers (learningActive off, or the closed flag set)
// so the count can only fall. Producers never take e.mu and their send is
// non-blocking, so the wait is bounded and safe to run while holding e.mu.
// Shared by Close (shutdown) and the window-close paths (Codex fix: a
// producer that passed the active gate must complete its enqueue BEFORE the
// window rotates, so its observation is attributed — or counted — under the
// window that accepted it, never silently lost between windows).
func (t *transport) waitProducers() {
	for t.producers.Load() != 0 {
		runtime.Gosched()
	}
}

// LearningActive reports whether a session is currently Learning (the same
// lock-free gate Observe checks). The M5A adapters consult it BEFORE building
// an Observation, so the enabled-but-idle posture does no per-request work
// beyond two atomic loads — no DTO construction, no group copy, no enqueue.
func (e *Engine) LearningActive() bool { return e.learningActive.Load() }

// SubjectKeyID exposes the pseudonym key's stable identity (hex of a hash
// prefix — reveals nothing of the key). Server-side staleness input; not for
// client DTOs.
func (e *Engine) SubjectKeyID() string { return e.subjKey.keyID }

// Observe emits one observation. Non-blocking under every condition; safe from
// any goroutine. Ignored (uncounted — "not learning" is not loss) when no
// session is Learning.
func (e *Engine) Observe(o Observation) {
	t := e.tr
	// Register BEFORE the gate and closed checks (Codex fix): the window-close
	// paths turn the gate off and then wait for registered producers before
	// rotating the generation, and Close sets the closed flag and waits before
	// its final sweep — so an enqueue can only happen when the producer was
	// registered AND then observed the gate on (or the flag off). A producer
	// registering after the wait completed necessarily observes the gate off
	// (it was turned off before the wait) and returns without enqueueing;
	// there is no interleaving left in which an event lands with a rotated
	// generation or beyond the shutdown sweep.
	t.producers.Add(1)
	defer t.producers.Add(-1)
	if !e.learningActive.Load() {
		return
	}
	if e.closed.Load() {
		// The drain has exited (or is exiting): an enqueue could no longer be
		// consumed, so refuse it HERE and count the loss — a producer must
		// never enqueue successfully into an abandoned channel (Codex fix).
		t.dropped.Add(1)
		return
	}
	if o.Host == "" {
		t.rejected.Add(1)
		return
	}
	// Bounded copy: the caller's slice is request-owned and must not cross the
	// goroutine boundary; truncation beyond the cap is deterministic AND
	// counted (M5B.1) — group context beyond the bound is lost, never silently.
	truncated := false
	if len(o.Groups) > 0 {
		n := len(o.Groups)
		if n > MaxObservationGroups {
			n = MaxObservationGroups
			truncated = true
		}
		g := make([]string, n)
		copy(g, o.Groups[:n])
		o.Groups = g
	}
	if o.At == 0 {
		o.At = e.cfg.Now().Unix()
	}
	// Stamp the CURRENT acceptance window: the consumer attributes the event
	// only while this window's session is still the aggregation target.
	o.gen = e.windowGen.Load()
	// Decision-time identity stamps (Codex round 15; see the field docs). The
	// seams are memoized at the root, so these are cheap alloc-free reads. A
	// producer-supplied stamp (captured at the enforcement decision itself,
	// Codex rounds 20/22) is authoritative over any enqueue-time seam read.
	switch {
	case o.CatEpoch != "":
		o.catEpoch = o.CatEpoch
	case e.cfg.CategoryEpoch != nil:
		o.catEpoch = e.cfg.CategoryEpoch()
	}
	switch {
	case o.PolicyID != "":
		o.policyID = o.PolicyID
	case e.cfg.PolicyContent != nil:
		o.policyID = e.cfg.PolicyContent()
	}
	select {
	case t.ch <- queuedItem{o: o}:
		t.accepted.Add(1)
		if truncated {
			// Counted only on a SUCCESSFUL enqueue (Codex fix): GroupsTruncated
			// means "an ACCEPTED observation carries incomplete group context" —
			// charging it before a failed send made a dropped event also count
			// as truncated-accepted, and under overload the counter could
			// exceed Accepted, corrupting the coverage facts.
			t.groupsTruncated.Add(1)
		}
	default:
		t.dropped.Add(1) // queue full: drop + account, never block the request
	}
}

// drainBarrier blocks until every observation enqueued BEFORE the call has
// been consumed: it sends a marker through the same FIFO channel and waits
// for the drain to reach it. The send may block when the queue is full (the
// admin plane is allowed to wait; the drain is live) and both waits abandon
// cleanly if the transport shuts down concurrently — Close's final sweep
// consumes whatever remains.
func (e *Engine) drainBarrier() {
	t := e.tr
	if t == nil {
		return
	}
	marker := make(chan struct{})
	select {
	case t.ch <- queuedItem{barrier: marker}:
		select {
		case <-marker:
		case <-t.done:
		}
	case <-t.done:
	}
}

// ObservationStats snapshots the transport counters.
func (e *Engine) ObservationStats() ObservationStats {
	return e.observationStatsRaw()
}

// startTransport wires the queue and the single drain goroutine. Called from
// New only — a disabled deployment never constructs an engine, so it never
// owns this goroutine.
func (e *Engine) startTransport() {
	t := &transport{
		ch:   make(chan queuedItem, observationQueueCap),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	e.tr = t
	go e.drainLoop(t)
}

// drainLoop is the single consumer. On stop it drains everything already
// queued (deterministic shutdown: every accepted observation is either
// delivered or accounted as a panic loss), then exits.
func (e *Engine) drainLoop(t *transport) {
	defer close(t.done)
	for {
		select {
		case q := <-t.ch:
			if q.barrier != nil {
				close(q.barrier)
				continue
			}
			e.consumeGuarded(t, q.o)
		case <-t.stop:
			for {
				select {
				case q := <-t.ch:
					if q.barrier != nil {
						close(q.barrier)
						continue
					}
					e.consumeGuarded(t, q.o)
				default:
					return
				}
			}
		}
	}
}

// consumeGuarded aggregates one observation (M3) and hands it to the sink,
// with per-event panic containment: a panicking consumer loses THAT event
// (accounted) and the drain keeps running — the queue must never wedge
// (CHAOS-24 pattern). The mutex-holding section is an inner closure so a panic
// can never leak a held lock.
func (e *Engine) consumeGuarded(t *transport, o Observation) {
	defer func() {
		if r := recover(); r != nil {
			t.panics.Add(1)
		}
	}()
	attributed := false
	func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		sess := e.aggSession
		if sess == nil || o.gen != e.aggGen {
			// Accepted under a window that has since CLOSED (session finished,
			// expired, or rotated before this event drained). A terminal
			// aggregate is immutable and a later session must never consume
			// another window's events (Codex fix) — count the whole-event loss
			// and discard.
			t.dropped.Add(1)
			t.consumeDropped.Add(1)
			return
		}
		attributed = true
		// Per-observation churn latch (Codex rounds 13/15/16). Three latch
		// points make the identity series complete:
		//   - the CONSUME-TIME read BEFORE resolution and the one AFTER it
		//     bracket aggregateLocked's category resolution (round 16): if the
		//     resolver ran under a transient taxonomy/policy B, B was current
		//     at some instant inside the bracket, so one of the two reads sees
		//     it — the old single post-hoc read missed an A→B→A completing
		//     around the resolution moment;
		//   - the DECISION-TIME stamps (round 15) latch a change that
		//     completed while the event sat queued.
		// Each check is a pair of memoized-string compares; equal-to-last is a
		// no-op. The only residual is a full round trip landing entirely
		// between the two adjacent bracket reads with the resolution inside —
		// two atomic swaps within nanoseconds.
		now := e.cfg.Now()
		e.checkEpochLocked(sess, now, "", "") // consume-time, pre-resolution
		e.aggregateLocked(sess, &o)
		e.checkEpochLocked(sess, now, o.catEpoch, o.policyID) // decision-time stamps
		e.checkEpochLocked(sess, now, "", "")                 // consume-time, post-resolution
		e.sinceFlush++
		if e.sinceFlush >= flushEvery {
			e.sinceFlush = 0
			e.syncTransportLocked()
			if err := e.saveLocked(); err != nil {
				e.dirty = true // retry at the next flush/Close; AtomicWrite already notified storage health
			}
		} else {
			e.dirty = true
		}
	}()
	if !attributed {
		return
	}
	if s := e.cfg.Sink; s != nil {
		s(o)
	}
	t.delivered.Add(1)
}

// pinTransportLocked pins the session-window transport baseline at the current
// counters (session start / restart load). Callers hold e.mu.
func (e *Engine) pinTransportLocked() {
	e.tPin = e.observationStatsRaw()
}

// syncTransportLocked folds the counter deltas since the last pin into the
// attributed session's TransportWindow and re-pins. Per-session DELTAS, never
// lifetime totals. Callers hold e.mu.
func (e *Engine) syncTransportLocked() {
	sess := e.aggSession
	if sess == nil {
		return
	}
	cur := e.observationStatsRaw()
	if cur != e.tPin {
		// The fold below changes the session's persisted loss accounting, so
		// the store is dirty even when no aggregation event set the flag
		// (Codex fix): a transport-only change — an empty-host rejection or a
		// consumer panic right after a cadence save — used to leave dirty
		// false, and Close returned without writing the final deltas; the
		// next process then reloaded a window missing recorded loss.
		e.dirty = true
	}
	sess.Transport.Accepted += cur.Accepted - e.tPin.Accepted
	sess.Transport.Dropped += cur.Dropped - e.tPin.Dropped
	sess.Transport.Rejected += cur.Rejected - e.tPin.Rejected
	sess.Transport.ConsumerPanics += cur.ConsumerPanics - e.tPin.ConsumerPanics
	sess.Transport.GroupsTruncated += cur.GroupsTruncated - e.tPin.GroupsTruncated
	e.tPin = cur
}

// observationStatsRaw reads the transport counters without locking (they are
// atomics); nil-transport-safe for constructor-time use.
func (e *Engine) observationStatsRaw() ObservationStats {
	t := e.tr
	if t == nil {
		return ObservationStats{}
	}
	return ObservationStats{
		Accepted:        t.accepted.Load(),
		Dropped:         t.dropped.Load(),
		Rejected:        t.rejected.Load(),
		ConsumerPanics:  t.panics.Load(),
		Delivered:       t.delivered.Load(),
		GroupsTruncated: t.groupsTruncated.Load(),
	}
}
