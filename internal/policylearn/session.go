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
}

// Degraded reports whether the session window lost any observations.
func (w TransportWindow) Degraded() bool {
	return w.Dropped > 0 || w.Rejected > 0 || w.ConsumerPanics > 0
}

func (s *Session) clone() Session {
	c := *s
	c.Gaps = append([]Gap(nil), s.Gaps...)
	c.CategoryChurn = append([]EpochChurn(nil), s.CategoryChurn...)
	// Agg is intentionally shared read-only in clones only via deep accessors;
	// external callers get a nil Agg to keep session copies cheap and to keep
	// the mutable aggregate encapsulated (AggregateSnapshot is the read API).
	c.Agg = nil
	return c
}

// StartSession opens a new Learning session. Enforces the one-active-session
// invariant and the read-only posture; persists before returning.
func (e *Engine) StartSession(actor string) (Session, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.readOnly {
		return Session{}, ErrStoreReadOnly
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
	e.sessions = append(e.sessions, s)
	e.pruneLocked()
	prevAggSession := e.aggSession
	e.aggSession = s
	e.pinTransportLocked()
	e.learningActive.Store(true)
	if err := e.saveLocked(); err != nil {
		// Persist-before-return: a failed durable write must not leave a
		// phantom active session that a restart would forget.
		e.sessions = e.sessions[:len(e.sessions)-1]
		e.aggSession = prevAggSession
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
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.readOnly {
		return Session{}, ErrStoreReadOnly
	}
	now := e.cfg.Now()
	e.maybeExpireLocked(now)
	s := e.activeLocked()
	if s == nil {
		return Session{}, ErrNoActiveSession
	}
	prevState, prevStopAt, prevStopBy := s.State, s.StoppedAt, s.StoppedBy
	s.State = terminalState
	s.StoppedAt = rfc3339(now)
	s.StoppedBy = actor
	e.checkEpochLocked(s, now) // final churn check for the window
	e.syncTransportLocked()    // fold the session-window transport deltas
	e.pruneLocked()
	e.learningActive.Store(false)
	if err := e.saveLocked(); err != nil {
		s.State, s.StoppedAt, s.StoppedBy = prevState, prevStopAt, prevStopBy
		e.learningActive.Store(true)
		return Session{}, err
	}
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
			e.learningActive.Store(false)
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
		e.learningActive.Store(false)
		e.pruneLocked()
	}
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
