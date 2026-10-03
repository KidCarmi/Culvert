// POST /v1/reconcile/{op_id} — the explicit, authenticated resolver for an
// interrupted operation (RISK-022 PR-E E3). Nothing here runs at boot; the
// startup pass (reconcile_startup.go) only auto-resolves verdicts that mutate
// nothing. This endpoint is how an operator or the Control Plane acts on the
// rest, and it is deliberately narrow:
//
//	{"action":"resolve"}  — RECOMPUTES the verdict against live Docker truth
//	    (never trusts the stored one blindly), refuses with 409 when the live
//	    verdict differs from the recorded one (verdict_changed — read status
//	    again), when it is loud_stop / data_manual (manual_required), when
//	    Docker is unreachable (inputs_unavailable), or when the attempt bound
//	    is exhausted (reconcile_exhausted). Then executes EXACTLY the verdict:
//	      noop                        → retire the record (200)
//	      verify_adopt_else_rollback  → health-probe; healthy ⇒ adopt (200);
//	                                    else ⇒ rollback to prior_ref (202)
//	      reup                        → tag+up target_ref under the health
//	                                    gate (202)
//	      rollback_to_prior           → rollback to prior_ref (202)
//	    A 202 is a normal journaled, locked, audited async rollbacks.create
//	    op (reconcile_of / reconcile_action params) through the shared
//	    local-first rollback core; the ORIGINAL record is retired only when
//	    that op SUCCEEDS, so a crash or failure mid-resolve stays visible.
//	{"action":"dismiss"}  — removes the record + verdict WITHOUT touching
//	    Docker. Allowed freely for a noop verdict; a tag-hazard verdict needs
//	    "acknowledge_tag_hazard":true; any other non-noop (or unclassified)
//	    verdict needs "acknowledge_unresolved":true. Audited.
//
// Idempotency: a second resolve while one is in flight answers 409
// resolve_in_flight (never a second mutation); once a record is retired,
// any further call answers 404 record_not_found.
package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// reconcileRequest is the POST /v1/reconcile/{op_id} body.
type reconcileRequest struct {
	Action                string `json:"action"`
	AcknowledgeTagHazard  bool   `json:"acknowledge_tag_hazard,omitempty"`
	AcknowledgeUnresolved bool   `json:"acknowledge_unresolved,omitempty"`
	IdempotencyKey        string `json:"idempotency_key,omitempty"`
}

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	opID := strings.TrimPrefix(r.URL.Path, "/v1/reconcile/")
	if !validOpID(opID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_op_id"})
		return
	}
	if s.opts.Journal == nil || s.opts.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "reconcile_not_wired"})
		return
	}
	var req reconcileRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decode: " + err.Error()})
		return
	}
	rec, found, err := s.opts.Journal.Read(opID)
	if err != nil {
		code := "journal_read_failed"
		if errors.Is(err, journal.ErrCorruptRecord) {
			code = "record_corrupt"
		}
		writeJSON(w, http.StatusConflict, map[string]string{"error": code})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "record_not_found", "op_id": opID})
		return
	}
	if s.opts.Ops.IsRunning(opID) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "op_running", "op_id": opID})
		return
	}
	ok, busy, rid := s.claimReconcile(opID)
	if !ok {
		body := map[string]string{"error": busy, "op_id": opID}
		if rid != "" {
			body["resolve_op_id"] = rid
		}
		writeJSON(w, http.StatusConflict, body)
		return
	}
	defer s.releaseReconcile(opID)
	switch req.Action {
	case "dismiss":
		s.reconcileDismiss(w, peer, rec, req)
	case "resolve":
		s.reconcileResolve(w, r, peer, rec, req)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `action must be "resolve" or "dismiss"`})
	}
}

// reconcileDismiss retires the record without touching Docker, gated on the
// acknowledgement the stored verdict demands.
func (s *Server) reconcileDismiss(w http.ResponseWriter, peer auth.PeerInfo, rec *journal.Record, req reconcileRequest) {
	v, _ := s.readVerdict(rec.OpID)
	verdict := verdictUnclassified
	tagHazard := false
	if v != nil {
		verdict, tagHazard = v.Verdict, v.TagHazard
	}
	switch {
	case isNoopVerdict(verdict):
		// nothing to acknowledge
	case tagHazard && !req.AcknowledgeTagHazard:
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error": "tag_hazard_unacknowledged", "op_id": rec.OpID, "verdict": verdict,
			"detail": "the pinned tag already points at the un-health-gated target; pass acknowledge_tag_hazard=true only after repairing it manually",
		})
		return
	case !tagHazard && !req.AcknowledgeUnresolved:
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error": "verdict_unresolved", "op_id": rec.OpID, "verdict": verdict,
			"detail": "this verdict is not a no-op; pass acknowledge_unresolved=true to dismiss it without acting",
		})
		return
	}
	s.retireRecord(rec.OpID)
	av := reconcileVerdictRecord{OpID: rec.OpID, Kind: rec.Kind, Mode: rec.Mode, Phase: rec.Phase, Verdict: verdict, TargetRef: rec.TargetRef, PriorRef: rec.PriorRef, TagHazard: tagHazard}
	if v != nil {
		av.Reason = v.Reason
	}
	s.auditReconcile(peer.String(), rec.OpID, auditKindReconcileDismiss, av, audit.OutcomeSucceeded)
	writeJSON(w, http.StatusOK, map[string]interface{}{"op_id": rec.OpID, "dismissed": true, "verdict": verdict})
}

// reconcileResolve recomputes, refuses the non-executable cases, and executes
// exactly the recorded verdict.
//
//nolint:cyclop // one ordered refusal ladder; splitting hides the refuse-before-act ordering
func (s *Server) reconcileResolve(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo, rec *journal.Record, req reconcileRequest) {
	prev, _ := s.readVerdict(rec.OpID)
	attempts := 0
	if prev != nil {
		attempts = prev.Attempts
	}
	cl := s.classifyRecord(r.Context(), rec, attempts)
	if prev != nil {
		cl.verdict.LastResolveOpID, cl.verdict.LastResolveOutcome = prev.LastResolveOpID, prev.LastResolveOutcome
	}
	_ = s.persistVerdict(prev, &cl)
	if !cl.live {
		writeJSON(w, http.StatusConflict, map[string]interface{}{"error": verdictInputsUnavailable, "op_id": rec.OpID, "reason": cl.verdict.Reason})
		return
	}
	if prev != nil && prev.Verdict != cl.verdict.Verdict {
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error": "verdict_changed", "op_id": rec.OpID, "previous_verdict": prev.Verdict, "current_verdict": cl.verdict.Verdict,
			"reason": cl.verdict.Reason, "detail": "live state no longer matches the recorded verdict; re-read /v1/status and resolve again",
		})
		return
	}
	switch cl.action {
	case actLoudStop, actDataManual:
		writeJSON(w, http.StatusConflict, map[string]interface{}{"error": "manual_required", "op_id": rec.OpID, "verdict": cl.verdict.Verdict, "reason": cl.verdict.Reason})
		return
	case actNoop:
		s.retireRecord(rec.OpID)
		s.auditReconcile(peer.String(), rec.OpID, auditKindReconcileResolve, cl.verdict, audit.OutcomeSucceeded)
		writeJSON(w, http.StatusOK, map[string]interface{}{"op_id": rec.OpID, "resolved": "noop", "reason": cl.verdict.Reason})
		return
	case actVerifyAdoptElseRollback:
		ok, detail := s.probeHealth(r.Context())
		cl.verdict.LastHealth = detail
		if ok {
			s.adopt(rec.OpID, &cl.verdict, peer.String())
			writeJSON(w, http.StatusOK, map[string]interface{}{"op_id": rec.OpID, "resolved": "adopted", "health": detail})
			return
		}
		cl.verdict.RecommendedAction = recommendFor(cl.verdict.Verdict, true, cl.verdict.Reason)
	}
	targetRef, label := resolveTargetFor(cl.action, &cl.verdict)
	if targetRef == "" {
		_ = s.opts.Journal.WriteVerdict(rec.OpID, cl.verdict)
		writeJSON(w, http.StatusConflict, map[string]interface{}{"error": "no_recovery_target", "op_id": rec.OpID, "verdict": cl.verdict.Verdict, "health": cl.verdict.LastHealth})
		return
	}
	s.launchResolveOp(w, r, peer, rec, cl.verdict, targetRef, label, req.IdempotencyKey)
}

// launchResolveOp admits the resolve as a normal journaled, locked, audited
// rollbacks.create op through the shared local-first rollback core. The
// attempt is charged BEFORE the op starts (P0-D), and the original record is
// retired only on the op's success.
func (s *Server) launchResolveOp(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo, rec *journal.Record, v reconcileVerdictRecord, targetRef, label, idemKey string) {
	v.Attempts++
	if err := s.opts.Journal.WriteVerdict(rec.OpID, v); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "verdict_persist_failed", "op_id": rec.OpID})
		return
	}
	params := map[string]interface{}{
		"mode": "image", "image_ref": targetRef,
		"reconcile_of": rec.OpID, "reconcile_action": label, "reconcile_verdict": v.Verdict,
		"compose_override_configured": s.opts.Cfg.ComposeOverrideFile != "",
	}
	srcID := rec.OpID
	acc := &rollbackAccumulator{kind: ops.KindRollbackCreate, actor: peer.String(), mode: "image"}
	marked := false // did THIS request set the in-flight marker?
	op, deduped, herr := s.startAsyncOp(r, peer, ops.KindRollbackCreate, idemKey, params,
		func() ([]ops.FlowStage, *opError) { return s.buildImageRollbackStages(targetRef, acc), nil },
		withOpIDHook(func(id string) {
			acc.opID = id
			marked = true
			s.markResolving(srcID, id)
		}),
		withResultFn(func(state ops.State, reason ops.FailureReason) map[string]interface{} {
			s.finishResolve(srcID, acc.opID, state, reason, v)
			return map[string]interface{}{
				"reconcile_of": srcID, "reconcile_action": label,
				"rollback_pull_skipped_local": acc.pullSkippedLocal,
				"final_running_digest":        firstOrEmpty(acc.runningAfterDigests),
			}
		}),
	)
	if herr != nil || deduped {
		// Nothing ran, so nothing may be charged. Two shapes reach here: an
		// admission refusal (another op holds the maintenance lock, the agent
		// is busy — a CP retrying against a busy agent would otherwise drive
		// every record to loud_stop(reconcile_exhausted) without a single
		// action; adversarial review, PR #1528), and a DEDUPLICATED replay —
		// the same idempotency_key as an earlier resolve returns that op's
		// snapshot with neither the op-ID hook nor the result callback, so
		// the attempt charged above would otherwise stand with no recovery
		// attempted (Codex P1, PR #1528: three harmless replays exhausted
		// the record). Neither shape may clear an in-flight marker this
		// request never set.
		if marked {
			s.markResolving(srcID, "")
		}
		v.Attempts--
		if werr := s.opts.Journal.WriteVerdict(rec.OpID, v); werr != nil {
			log.Printf("culvert-maint: reconcile: op=%s attempt refund not persisted: %v", strings.ReplaceAll(strings.ReplaceAll(rec.OpID, "\n", ""), "\r", ""), werr)
		}
		if herr != nil {
			writeJSON(w, herr.Status, herr.Body)
			return
		}
	}
	writeOpResponse(w, op, deduped)
}

// finishResolve runs at the resolve op's terminal: success retires the
// original record; failure keeps it (with the outcome recorded on the verdict)
// so it stays visible on /v1/status.
func (s *Server) finishResolve(srcID, resolveOpID string, state ops.State, reason ops.FailureReason, v reconcileVerdictRecord) {
	defer s.markResolving(srcID, "")
	v.LastResolveOpID = resolveOpID
	if state == ops.StateSucceeded {
		v.LastResolveOutcome = "succeeded"
		s.retireRecord(srcID)
		s.auditReconcile(reconcileActor, srcID, auditKindReconcileResolve, v, audit.OutcomeSucceeded)
		return
	}
	v.LastResolveOutcome = fmt.Sprintf("%s(%s)", state, reason)
	_ = s.opts.Journal.WriteVerdict(srcID, v)
	s.auditReconcile(reconcileActor, srcID, auditKindReconcileResolve, v, audit.OutcomeFailed)
}
