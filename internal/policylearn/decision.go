package policylearn

// M5B — the recommendation DECISION lifecycle: durable acceptance intent and
// reject, with persist-before-return + rollback on every transition (the
// StartSession discipline). This file owns STATE ONLY. Translation of a
// ProposedRule into a real policy rule, every draft interaction, and all
// staleness/fence decisions live at the root trust boundary outside this
// package (the ADR-0025 wall); the engine cannot even name those types.

import "strings"

// findRecLocked returns the stored recommendation by ID. Callers hold e.mu.
func (e *Engine) findRecLocked(id string) *Recommendation {
	for _, r := range e.recs {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// mutateRecommendation runs one guarded decision transition with
// persist-before-return: mutate applies the change to a CLONE, the clone
// replaces the original in a copy-on-write slice, and a failed persist
// restores the previous slice — the in-memory store never diverges from disk.
func (e *Engine) mutateRecommendation(id string, mutate func(*Recommendation) error) (Recommendation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.readOnly {
		return Recommendation{}, ErrStoreReadOnly
	}
	cur := e.findRecLocked(id)
	if cur == nil {
		return Recommendation{}, ErrRecommendationNotFound
	}
	next := cur.clone()
	if err := mutate(&next); err != nil {
		return Recommendation{}, err
	}
	prev := e.recs
	swapped := make([]*Recommendation, len(e.recs))
	copy(swapped, e.recs)
	for i, r := range swapped {
		if r.ID == id {
			swapped[i] = &next
		}
	}
	e.recs = swapped
	if err := e.saveLocked(); err != nil {
		e.recs = prev
		return Recommendation{}, err
	}
	return next.clone(), nil
}

// stateErr maps a recommendation's state to its refusal sentinel.
func stateErr(state string) error {
	switch state {
	case RecStateSuperseded:
		return ErrRecommendationSuperseded
	case RecStateAccepted:
		return ErrRecommendationAccepted
	case RecStateRejected:
		return ErrRecommendationRejected
	case RecStateAccepting:
		return ErrRecommendationAccepting
	default:
		return ErrRecommendationNotFound // unreachable for known states
	}
}

// BeginAccept persists the durable acceptance INTENT: generated → accepting
// with the root-preallocated TargetRuleID. Idempotent on an already-accepting
// recommendation: the EXISTING intent (and its TargetRuleID) is returned and
// the caller's newly minted ID is discarded — retries and crash-recovery must
// converge on ONE target rule identity. Every other state refuses.
func (e *Engine) BeginAccept(id, targetRuleID string) (Recommendation, error) {
	if targetRuleID == "" {
		return Recommendation{}, ErrRecommendationNotFound
	}
	e.mu.Lock()
	if cur := e.findRecLocked(id); cur != nil && cur.State == RecStateAccepting {
		out := cur.clone() // resume path: reuse the persisted intent verbatim
		e.mu.Unlock()
		return out, nil
	}
	e.mu.Unlock()
	return e.mutateRecommendation(id, func(r *Recommendation) error {
		if r.State != RecStateGenerated {
			return stateErr(r.State)
		}
		r.State = RecStateAccepting
		r.TargetRuleID = targetRuleID
		return nil
	})
}

// FinalizeAccept latches accepting → accepted (recording actor + instant).
// Idempotent: already-accepted returns the stored object unchanged. Only an
// accepting recommendation can finalize — the root boundary calls this ONLY
// after verifying the exact target draft rule exists.
func (e *Engine) FinalizeAccept(id, actor string) (Recommendation, error) {
	e.mu.Lock()
	if cur := e.findRecLocked(id); cur != nil && cur.State == RecStateAccepted {
		out := cur.clone()
		e.mu.Unlock()
		return out, nil
	}
	e.mu.Unlock()
	return e.mutateRecommendation(id, func(r *Recommendation) error {
		if r.State != RecStateAccepting {
			return stateErr(r.State)
		}
		r.State = RecStateAccepted
		r.AcceptedAt = rfc3339(e.cfg.Now())
		r.AcceptedBy = actor
		return nil
	})
}

// AbortAccept reverts an unresolved intent: accepting → generated, clearing
// the TargetRuleID (the safe reconcile when the target rule does not exist and
// the current fences refuse re-execution). Idempotent on generated; refuses on
// accepted/rejected/superseded — an intent whose rule EXISTS must finalize,
// never abort.
func (e *Engine) AbortAccept(id string) (Recommendation, error) {
	e.mu.Lock()
	if cur := e.findRecLocked(id); cur != nil && cur.State == RecStateGenerated {
		out := cur.clone()
		e.mu.Unlock()
		return out, nil
	}
	e.mu.Unlock()
	return e.mutateRecommendation(id, func(r *Recommendation) error {
		if r.State != RecStateAccepting {
			return stateErr(r.State)
		}
		r.State = RecStateGenerated
		r.TargetRuleID = ""
		return nil
	})
}

// Reject latches generated → rejected with a bounded, control-char-stripped
// reason. Idempotent: already-rejected returns the stored object (the original
// reason is kept — a retry never rewrites history). Accepted, accepting, and
// superseded recommendations refuse. Reject mutates NOTHING outside this
// recommendation's state.
func (e *Engine) Reject(id, actor, reason string) (Recommendation, error) {
	e.mu.Lock()
	if cur := e.findRecLocked(id); cur != nil && cur.State == RecStateRejected {
		out := cur.clone()
		e.mu.Unlock()
		return out, nil
	}
	e.mu.Unlock()
	return e.mutateRecommendation(id, func(r *Recommendation) error {
		if r.State != RecStateGenerated {
			return stateErr(r.State)
		}
		r.State = RecStateRejected
		r.RejectedAt = rfc3339(e.cfg.Now())
		r.RejectedBy = actor
		r.RejectReason = sanitizeReason(reason)
		return nil
	})
}

// RecommendationByID returns a copy of one stored recommendation.
func (e *Engine) RecommendationByID(id string) (Recommendation, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r := e.findRecLocked(id); r != nil {
		return r.clone(), true
	}
	return Recommendation{}, false
}

// sanitizeReason bounds and strips control characters from an operator-supplied
// reject reason (stored + audited; never subject data).
func sanitizeReason(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxRejectReasonLen {
		s = s[:maxRejectReasonLen]
	}
	return s
}
