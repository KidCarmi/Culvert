package policylearn

import "time"

// Session states — the minimal explicit machine (ADR-0025 §2):
//
//	(none) ──Start──► Learning ──Stop──────────────► Completed (terminal)
//	                     │  ──Cancel───────────────► Cancelled (terminal)
//	                     └──max-duration overrun───► Completed (StoppedBy=system:max-duration)
//
// Terminal states never transition again. "Inactive" is the absence of a
// Learning session, not a stored state. Degradation (restart gaps) is a
// recorded fact on the session, not a state.
const (
	StateLearning  = "learning"
	StateCompleted = "completed"
	StateCancelled = "cancelled"
)

// Gap records a window in which observations were (or would have been) lost —
// M1: process restarts while a session was active. Never silent (ADR-0025 §8).
type Gap struct {
	At     string `json:"at"` // RFC3339 UTC
	Reason string `json:"reason"`
}

// Session is one learning session. All timestamps are RFC3339 UTC strings
// derived from the injected clock.
type Session struct {
	ID        string   `json:"id"`
	State     string   `json:"state"`
	CreatedAt string   `json:"created_at"`
	StartedAt string   `json:"started_at"`
	StoppedAt string   `json:"stopped_at,omitempty"`
	CreatedBy string   `json:"created_by"`
	StoppedBy string   `json:"stopped_by,omitempty"`
	Baseline  Baseline `json:"baseline"`
	Gaps      []Gap    `json:"gaps,omitempty"`

	// M3 — bounded factual aggregation + degradation metadata.
	SubjectKeyID  string          `json:"subject_key_id,omitempty"` // pseudonym-key identity the tokens were minted under
	CategoryChurn []EpochChurn    `json:"category_churn,omitempty"` // bounded mid-session category-generation changes
	PolicyChurn   []EpochChurn    `json:"policy_churn,omitempty"`   // bounded mid-session policy-content changes (schema v8, Codex round 13: an A→B→A round trip during the session collects evidence under B that the restored baseline hash alone cannot reveal)
	Transport     TransportWindow `json:"transport,omitempty"`      // session-window transport-counter deltas (loss accounting)
	Agg           *Aggregate      `json:"agg,omitempty"`            // bounded Group × Category cells

	startedAtParsed time.Time // cached parse for expiry math; not serialized
}

// TransportWindow is the persisted per-session accumulation of transport-
// counter DELTAS (pinned at session start / restart-load and advanced at every
// flush) — never lifetime process totals.
type TransportWindow struct {
	Accepted       int64 `json:"accepted,omitempty"`
	Dropped        int64 `json:"dropped,omitempty"`
	Rejected       int64 `json:"rejected,omitempty"`
	ConsumerPanics int64 `json:"consumer_panics,omitempty"`
	// GroupsTruncated (M5B.1) counts accepted observations whose group list
	// exceeded MaxObservationGroups: those events carry INCOMPLETE group
	// context (only the first 16 groups received evidence). Carried on every
	// recommendation via Coverage.TransportLoss so evidence can never imply
	// complete group coverage.
	GroupsTruncated int64 `json:"groups_truncated,omitempty"`
}

// Degraded reports whether the session window LOST whole observations.
// GroupsTruncated is deliberately excluded: a truncated observation was
// delivered and its retained cells are exact — the omitted groups simply
// received no evidence (an undercount, the direction evidence is allowed to
// err in), so it is surfaced as a coverage fact rather than capping
// confidence for every cell in the session.
func (w TransportWindow) Degraded() bool {
	return w.Dropped > 0 || w.Rejected > 0 || w.ConsumerPanics > 0
}

func (s *Session) clone() Session {
	c := *s
	c.Gaps = append([]Gap(nil), s.Gaps...)
	c.CategoryChurn = append([]EpochChurn(nil), s.CategoryChurn...)
	c.PolicyChurn = append([]EpochChurn(nil), s.PolicyChurn...)
	// Agg is intentionally shared read-only in clones only via deep accessors;
	// external callers get a nil Agg to keep session copies cheap and to keep
	// the mutable aggregate encapsulated (AggregateSnapshot is the read API).
	c.Agg = nil
	return c
}

// StartSession opens a new Learning session. Enforces the one-active-session
// invariant and the read-only posture; persists before returning.
func (e *Engine) StartSession(actor string) (Session, error) {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.readOnly {
		return Session{}, ErrStoreReadOnly
	}
	if e.closed.Load() {
		// The transport has shut down (graceful-shutdown window: the engine
		// closes before the admin UI stops). Refuse rather than persist a new
		// active session whose observations could only ever become
		// unpersistable post-final-save drops (Codex fix).
		return Session{}, ErrEngineClosed
	}
	now := e.cfg.Now()
	e.maybeExpireLocked(now)
	if e.activeLocked() != nil {
		return Session{}, ErrActiveSession
	}
	var base Baseline
	if e.cfg.Baseline != nil {
		base = e.cfg.Baseline()
	}
	if base.CapturedAt == "" {
		base.CapturedAt = rfc3339(now)
	}
	if e.cfg.CategoryEpoch != nil {
		base.CategoryEpoch = e.cfg.CategoryEpoch() // pinned at Start (M3)
	}
	base.GuardrailsHash = e.guardrailsHash // recommendable-allowlist identity pinned at Start (M4)
	s := &Session{
		ID:              newID(),
		State:           StateLearning,
		CreatedAt:       rfc3339(now),
		StartedAt:       rfc3339(now),
		CreatedBy:       actor,
		Baseline:        base,
		SubjectKeyID:    e.subjKey.keyID,
		Agg:             newAggregate(),
		startedAtParsed: now,
	}
	// Transactional membership snapshot (Codex fix): pruneLocked filters the
	// slice IN PLACE, so a failed persist must restore the pre-transition
	// list — not just drop the appended session — or the pruned terminal
	// record would be silently lost by a transition that reported failure.
	prevSessions := append([]*Session(nil), e.sessions...)
	e.sessions = append(e.sessions, s)
	e.pruneLocked()
	prevAggSession := e.aggSession
	prevAggGen := e.aggGen
	e.aggSession = s
	e.aggGen = e.windowGen.Add(1) // open this session's acceptance window
	e.pinTransportLocked()
	e.learningActive.Store(true)
	if err := e.saveLocked(); err != nil {
		// Persist-before-return: a failed durable write must not leave a
		// phantom active session that a restart would forget.
		e.sessions = prevSessions
		e.aggSession = prevAggSession
		e.aggGen = prevAggGen
		e.learningActive.Store(false)
		return Session{}, err
	}
	return s.clone(), nil
}

// StopSession completes the active session. Persists before returning.
func (e *Engine) StopSession(actor string) (Session, error) {
	return e.finishActive(actor, StateCompleted)
}

// CancelSession cancels the active session (terminal; retained but marked
// non-authoritative — M2+ never generates recommendations from it).
func (e *Engine) CancelSession(actor string) (Session, error) {
	return e.finishActive(actor, StateCancelled)
}

func (e *Engine) finishActive(actor, terminalState string) (Session, error) {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	e.mu.Lock()
	if e.readOnly {
		e.mu.Unlock()
		return Session{}, ErrStoreReadOnly
	}
	now := e.cfg.Now()
	e.maybeExpireLocked(now)
	s := e.activeLocked()
	if s == nil {
		e.mu.Unlock()
		return Session{}, ErrNoActiveSession
	}
	// Close the acceptance window BEFORE the transition (Codex fix): the gate
	// stops new observations, the generation bump makes any gate-racer
	// unattributable (counted, never silently aggregated elsewhere), and
	// events already ACCEPTED under this window still carry its generation —
	// so the drain barrier below flushes exactly this session's backlog into
	// its aggregate before it becomes terminal. finishing suppresses lazy
	// expiry while e.mu is released for the barrier (opMu already serializes
	// the other lifecycle ops).
	e.finishing = true
	e.learningActive.Store(false)
	e.mu.Unlock()

	// Wait for in-flight producers BEFORE rotating the window (Codex fix): an
	// Observe that passed the active gate may not have completed its enqueue
	// yet — rotating first would stamp its observation with the NEXT
	// generation, so the barrier below could not flush it into s and its
	// acceptance would resolve as a post-terminal drop outside s's accounting.
	// The gate is off, so the producer count can only fall; producers never
	// take e.mu and never block (bounded wait).
	if t := e.tr; t != nil {
		t.waitProducers()
	}
	e.windowGen.Add(1)

	e.drainBarrier() // every observation accepted under s's window is now aggregated into s

	e.mu.Lock()
	defer e.mu.Unlock()
	e.finishing = false
	prevState, prevStopAt, prevStopBy := s.State, s.StoppedAt, s.StoppedBy
	// Transactional membership snapshot (Codex fix): see StartSession.
	prevSessions := append([]*Session(nil), e.sessions...)
	s.State = terminalState
	s.StoppedAt = rfc3339(now)
	s.StoppedBy = actor
	e.checkEpochLocked(s, now, "", "") // final churn check for the window (current seam reads)
	e.syncTransportLocked()    // fold the session-window transport deltas
	e.pruneLocked()
	if err := e.saveLocked(); err != nil {
		s.State, s.StoppedAt, s.StoppedBy = prevState, prevStopAt, prevStopBy
		e.sessions = prevSessions
		// The gate was OFF for the whole drain + failed write — requests in
		// that interval went unobserved. Record the window as a gap BEFORE
		// resuming (Codex round 13): a later successful completion must not
		// claim full confidence over it (the round-3 session_gaps cap fires).
		s.Gaps = append(s.Gaps, Gap{At: rfc3339(now), Reason: "failed_transition"})
		e.dirty = true
		// Re-open the window under the CURRENT generation: learning resumes
		// and new observations attribute to s again.
		e.aggGen = e.windowGen.Load()
		e.learningActive.Store(true)
		return Session{}, err
	}
	// Terminal immutability (Codex fix): nothing may attribute to this
	// aggregate again — the next StartSession opens a fresh window.
	e.aggSession = nil
	return s.clone(), nil
}

// ActiveSession returns a copy of the Learning session, if any. Lazy expiry is
// applied in memory (flagged dirty; persisted on the next mutation or Close) so
// reads stay side-effect-free on disk while never reporting an overdue session
// as active.
func (e *Engine) ActiveSession() (Session, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maybeExpireLocked(e.cfg.Now())
	if s := e.activeLocked(); s != nil {
		return s.clone(), true
	}
	return Session{}, false
}

// Sessions returns copies of all retained sessions, creation-ordered.
func (e *Engine) Sessions() []Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maybeExpireLocked(e.cfg.Now())
	out := make([]Session, 0, len(e.sessions))
	for _, s := range e.sessions {
		out = append(out, s.clone())
	}
	return out
}

func (e *Engine) activeLocked() *Session {
	for _, s := range e.sessions {
		if s.State == StateLearning {
			return s
		}
	}
	return nil
}

// maybeExpireLocked auto-completes an overdue active session. Deterministic in
// the supplied instant; sets dirty so the flip is persisted by the next
// mutating operation (or Close). Never called with e.readOnly writes pending —
// on a read-only engine the flip stays in memory only, by design.
func (e *Engine) maybeExpireLocked(now time.Time) {
	if e.finishing {
		return // a finish owns the transition; its barrier window must not race a lazy expiry
	}
	s := e.activeLocked()
	if s == nil {
		return
	}
	if s.startedAtParsed.IsZero() {
		t, err := time.Parse(time.RFC3339, s.StartedAt)
		if err != nil {
			// Unparseable start on an ACTIVE session: fail safe — expire it
			// now rather than let it run unbounded.
			s.State = StateCompleted
			s.StoppedAt = rfc3339(now)
			s.StoppedBy = "system:invalid-start-stamp"
			e.dirty = true
			e.closeWindowLocked()
			e.pruneLocked()
			return
		}
		s.startedAtParsed = t
	}
	if now.Sub(s.startedAtParsed) >= e.cfg.MaxSessionDuration {
		s.State = StateCompleted
		s.StoppedAt = rfc3339(now)
		s.StoppedBy = "system:max-duration"
		e.dirty = true
		e.closeWindowLocked()
		e.pruneLocked()
	}
}

// closeWindowLocked closes the acceptance window at a lazy-expiry transition:
// gate off, final delta fold, window rotated, aggregation target cleared —
// the expired session's aggregate becomes immutable and any still-queued
// events of its window drain as counted drops (an accounted loss at a
// max-duration overrun boundary, never a silent aggregation into a terminal
// or later session). Caller holds e.mu.
func (e *Engine) closeWindowLocked() {
	e.learningActive.Store(false)
	if t := e.tr; t != nil {
		// Codex fix: a producer that passed the active gate may not have
		// completed its enqueue yet — wait (bounded; producers never take e.mu)
		// so its acceptance is visible to the outstanding count below instead
		// of leaking past the close entirely.
		t.waitProducers()
	}
	e.syncTransportLocked()
	// Codex fix: events ACCEPTED but not yet resolved at this instant were
	// accepted under this window and are doomed by the rotation below.
	// Derive the count from the monotonic transport counters — accepted −
	// delivered − consumeDropped − panics, i.e. accepted events not yet
	// delivered, consume-discarded, or lost to a panic — because a
	// queue-length probe misses the event the drain has already DEQUEUED and
	// holds while waiting for e.mu (that event would otherwise resolve as a
	// post-close drop with this session's window claiming zero loss). The
	// consume-side drop share is subtracted rather than the public Dropped
	// counter: the latter also contains enqueue-side drops that were never
	// accepted and would deflate the quantity below zero under queue-full
	// history, silently un-charging a real drain-held loss. Charging here
	// lets a generate from the expired session see a degraded
	// (confidence-capped) window instead of a clean one. The same events also
	// hit the global drop counter when they drain (and an aggregated-but-
	// undelivered event counts here too), which a later window's delta may
	// fold again — an accepted OVERCOUNT of loss (the safe direction: it only
	// weakens claims).
	if sess := e.aggSession; sess != nil && e.tr != nil {
		t := e.tr
		outstanding := t.accepted.Load() - t.delivered.Load() - t.consumeDropped.Load() - t.panics.Load()
		if outstanding > 0 {
			sess.Transport.Dropped += outstanding
		}
	}
	e.windowGen.Add(1)
	e.aggSession = nil
}

// AggregateOverview is the bounded factual summary of one session's
// aggregation state, safe for operator surfaces: counts and degradation flags
// only — no cell contents, no subject tokens, no hosts (M5A API boundary).
type AggregateOverview struct {
	Cells             int   `json:"cells"`
	CellsDropped      int64 `json:"cells_dropped"`
	SubjectBudgetUsed int64 `json:"subject_budget_used"`
	ChurnOverflow     int64 `json:"churn_overflow"`
	SubjectKeyChanged bool  `json:"subject_key_changed"`
}

// SessionOverview returns the aggregate overview for one session by ID.
func (e *Engine) SessionOverview(id string) (AggregateOverview, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.sessions {
		if s.ID != id {
			continue
		}
		var o AggregateOverview
		if s.Agg != nil {
			o = AggregateOverview{
				Cells:             len(s.Agg.Cells),
				CellsDropped:      s.Agg.CellsDropped,
				SubjectBudgetUsed: s.Agg.SubjectBudgetUsed,
				ChurnOverflow:     s.Agg.ChurnOverflow,
				SubjectKeyChanged: s.Agg.SubjectKeyChanged,
			}
		}
		return o, true
	}
	return AggregateOverview{}, false
}

// pruneLocked enforces the retained-terminal-sessions bound: oldest-first
// (creation order) eviction of TERMINAL sessions down to the cap. The active
// session is never evicted. Eviction only ever discards history, never
// resurrects or activates anything (the safe direction).
func (e *Engine) pruneLocked() {
	terminal := 0
	for _, s := range e.sessions {
		if s.State != StateLearning {
			terminal++
		}
	}
	if terminal <= e.cfg.MaxRetainedSessions {
		return
	}
	evict := terminal - e.cfg.MaxRetainedSessions
	kept := e.sessions[:0]
	for _, s := range e.sessions {
		if evict > 0 && s.State != StateLearning {
			evict--
			continue
		}
		kept = append(kept, s)
	}
	e.sessions = kept
	e.dirty = true
}
