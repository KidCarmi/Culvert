// /v1/status surface for interrupted operations (RISK-022 PR-E E3).
//
// The server overlays the journal's on-disk truth onto the StatusProvider's
// snapshot: every live journal record that does NOT belong to a currently
// running op is an interrupted operation, rendered with its stored verdict
// (or "unclassified" when none exists — mark-only mode, or a verdict the
// reconciler could not persist). attention_required is true whenever any
// such record, a quarantined (unreadable) record, or an unreadable journal
// exists. Reads only; no docker.
package server

import (
	"time"
)

// InterruptedOperation is one entry of Status.InterruptedOperations.
type InterruptedOperation struct {
	OpID  string `json:"op_id"`
	Kind  string `json:"kind"`
	Mode  string `json:"mode,omitempty"`
	Phase string `json:"phase"`

	Verdict           string `json:"verdict"`
	Reason            string `json:"reason,omitempty"`
	RecommendedAction string `json:"recommended_action"`
	TagHazard         bool   `json:"tag_hazard"`

	TargetRef            string `json:"target_ref,omitempty"`
	PriorRef             string `json:"prior_ref,omitempty"`
	RunningMatchesTarget bool   `json:"running_matches_target"`
	TagMatchesTarget     bool   `json:"tag_matches_target"`

	Attempts           int        `json:"attempts"`
	ComputedAt         *time.Time `json:"computed_at,omitempty"`
	LastHealth         string     `json:"last_health,omitempty"`
	ResolveOpID        string     `json:"resolve_op_id,omitempty"` // a resolve op currently in flight
	LastResolveOpID    string     `json:"last_resolve_op_id,omitempty"`
	LastResolveOutcome string     `json:"last_resolve_outcome,omitempty"`
}

// overlayReconcileStatus fills the reconcile fields of st from the journal.
func (s *Server) overlayReconcileStatus(st *Status) {
	if s.opts.Cfg != nil {
		st.ReconcileOnStartup = s.opts.Cfg.ReconcileOnStartup
	}
	if s.opts.Journal == nil {
		return
	}
	recs, err := s.opts.Journal.List()
	if err != nil {
		st.JournalError = err.Error()
		st.AttentionRequired = true
	}
	for i := range recs {
		rec := recs[i]
		if s.opts.Ops != nil && s.opts.Ops.IsRunning(rec.OpID) {
			continue
		}
		entry := InterruptedOperation{
			OpID: rec.OpID, Kind: rec.Kind, Mode: rec.Mode, Phase: string(rec.Phase),
			TargetRef: rec.TargetRef, PriorRef: rec.PriorRef,
			Verdict: verdictUnclassified, RecommendedAction: recommendFor(verdictUnclassified, false, ""),
		}
		if v, verr := s.readVerdict(rec.OpID); verr == nil && v != nil {
			entry.Verdict, entry.Reason, entry.RecommendedAction, entry.TagHazard = v.Verdict, v.Reason, v.RecommendedAction, v.TagHazard
			entry.RunningMatchesTarget, entry.TagMatchesTarget = v.RunningMatchesTarget, v.TagMatchesTarget
			entry.Attempts, entry.LastHealth = v.Attempts, v.LastHealth
			entry.LastResolveOpID, entry.LastResolveOutcome = v.LastResolveOpID, v.LastResolveOutcome
			computed := v.ComputedAt
			entry.ComputedAt = &computed
		}
		entry.ResolveOpID = s.resolveInFlight(rec.OpID)
		st.InterruptedOperations = append(st.InterruptedOperations, entry)
	}
	if q, qerr := s.opts.Journal.Quarantined(); qerr == nil {
		st.QuarantinedJournalRecords = q
	}
	if len(st.InterruptedOperations) > 0 || len(st.QuarantinedJournalRecords) > 0 {
		st.AttentionRequired = true
	}
}

// resolveInFlight returns the op_id of a resolve op currently running for
// opID, or "".
func (s *Server) resolveInFlight(opID string) string {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	return s.resolving[opID]
}

// markResolving records / clears the in-flight resolve op for opID.
func (s *Server) markResolving(opID, resolveOpID string) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if s.resolving == nil {
		s.resolving = map[string]string{}
	}
	if resolveOpID == "" {
		delete(s.resolving, opID)
		return
	}
	s.resolving[opID] = resolveOpID
}

// claimReconcile reserves opID for one /v1/reconcile request. It fails when
// another request holds the claim or a resolve op it launched is still
// running, returning which (and that op's id). The caller releases the claim
// when it returns; a resolve it launched has by then installed its own
// in-flight marker (markResolving runs in the admission hook, inside the
// request), so the record is never unclaimed while an action is pending.
func (s *Server) claimReconcile(opID string) (ok bool, busy, resolveOpID string) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if rid := s.resolving[opID]; rid != "" {
		return false, "resolve_in_flight", rid
	}
	if s.claimed[opID] {
		return false, "reconcile_in_progress", ""
	}
	if s.claimed == nil {
		s.claimed = map[string]bool{}
	}
	s.claimed[opID] = true
	return true, "", ""
}

func (s *Server) releaseReconcile(opID string) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	delete(s.claimed, opID)
}
