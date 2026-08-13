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
}

// ObservationStats are the monotonic transport counters (loss accounting —
// future readiness computations must be unable to lie about transport loss).
type ObservationStats struct {
	Accepted       int64 // enqueued
	Dropped        int64 // queue full — event discarded, request unaffected
	Rejected       int64 // invalid (empty Host) — discarded
	ConsumerPanics int64 // sink panicked — event lost, drain continued
	Delivered      int64 // handed to the sink (or discarded clean when no sink)
}

// transport is the engine-owned queue + single drain goroutine.
type transport struct {
	ch       chan Observation
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	accepted  atomic.Int64
	dropped   atomic.Int64
	rejected  atomic.Int64
	panics    atomic.Int64
	delivered atomic.Int64
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
	if !e.learningActive.Load() {
		return
	}
	t := e.tr
	if o.Host == "" {
		t.rejected.Add(1)
		return
	}
	// Bounded copy: the caller's slice is request-owned and must not cross the
	// goroutine boundary; truncation beyond the cap is deterministic.
	if len(o.Groups) > 0 {
		n := len(o.Groups)
		if n > MaxObservationGroups {
			n = MaxObservationGroups
		}
		g := make([]string, n)
		copy(g, o.Groups[:n])
		o.Groups = g
	}
	if o.At == 0 {
		o.At = e.cfg.Now().Unix()
	}
	select {
	case t.ch <- o:
		t.accepted.Add(1)
	default:
		t.dropped.Add(1) // queue full: drop + account, never block the request
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
		ch:   make(chan Observation, observationQueueCap),
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
		case o := <-t.ch:
			e.consumeGuarded(t, o)
		case <-t.stop:
			for {
				select {
				case o := <-t.ch:
					e.consumeGuarded(t, o)
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
	func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		sess := e.aggSession
		if sess == nil {
			return // no attributable session (cannot happen for accepted events; defensive)
		}
		e.aggregateLocked(sess, &o)
		e.sinceEpoch++
		if e.sinceEpoch >= epochCheckEvery {
			e.sinceEpoch = 0
			e.checkEpochLocked(sess, e.cfg.Now())
		}
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
	sess.Transport.Accepted += cur.Accepted - e.tPin.Accepted
	sess.Transport.Dropped += cur.Dropped - e.tPin.Dropped
	sess.Transport.Rejected += cur.Rejected - e.tPin.Rejected
	sess.Transport.ConsumerPanics += cur.ConsumerPanics - e.tPin.ConsumerPanics
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
		Accepted:       t.accepted.Load(),
		Dropped:        t.dropped.Load(),
		Rejected:       t.rejected.Load(),
		ConsumerPanics: t.panics.Load(),
		Delivered:      t.delivered.Load(),
	}
}
