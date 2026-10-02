// Startup reconcile (RISK-022 PR-E, slice E3 — the boot hook).
//
// At every start, after the journal's Phase A (MarkAllInterrupted), the server
// classifies each interrupted record against Docker TRUTH — the running proxy
// image, what the fixed culvert/proxy:pinned tag resolves to, and the record's
// re-validated refs — through the pure decision table in reconcile_decision.go,
// writes a DURABLE verdict beside the record, and then acts on exactly two
// classes of verdict, the ones that mutate nothing:
//
//   - actNoop: the tag never advanced (or the stack is already on prior) —
//     the record is retired and the op stays failed(agent_restart_interrupted).
//   - actVerifyAdoptElseRollback when the TARGET IS LIVE AND HEALTHY: the
//     interrupted upgrade effectively succeeded, so the op is re-terminalized
//     succeeded(reconciled) (ops.Manager.OverrideInterrupted, design P0-B) and
//     the record retired. An unhealthy or unreachable target is NOT rolled
//     back here — it stays surfaced.
//
// Everything else (reup, rollback_to_prior, loud_stop, data_manual, an
// unhealthy live target, Docker not reachable) is never executed at boot: it is
// surfaced on GET /v1/status as interrupted_operations[] with
// attention_required=true, logged at WARN, and left for the explicit,
// authenticated POST /v1/reconcile/{op_id} (handlers_reconcile.go). The one
// hazard that gets its own WARN line is the pinned-tag hole: a tag that
// already points at an un-health-gated target while the container is not
// running it means the NEXT `docker compose up` — by anyone — starts that
// target silently.
//
// Bounded: the whole pass runs under one deadline (reconcileDeadline) so a
// wedged daemon cannot keep the agent dark indefinitely; the records simply
// stay unclassified ("inputs_unavailable") and the endpoint recomputes later.
// Fail-closed where it matters: a record whose refs do not re-validate is never
// fed to docker (reconcileDecision returns loud_stop), and a record that cannot
// be read was already quarantined by the journal reader.
package server

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

const (
	// reconcileMaxAttempts bounds how many times the explicit resolver may act
	// on one op_id (design P0-D: never loop). Classification does not count.
	reconcileMaxAttempts = 3
	// reconcileActor is the audit actor for boot-time reconcile decisions.
	reconcileActor = "agent:reconcile"
	// defaultReconcileDeadline bounds the whole startup pass when the config
	// stage timeout is unset (tests).
	defaultReconcileDeadline = 5 * time.Minute

	// Verdict strings beyond the pure core's actions.
	verdictInputsUnavailable = "inputs_unavailable"
	verdictUnclassified      = "unclassified"

	auditKindReconcileNoop    = "reconcile.noop"
	auditKindReconcileAdopt   = "reconcile.adopt"
	auditKindReconcileDismiss = "reconcile.dismiss"
	auditKindReconcileResolve = "reconcile.resolve"
)

// reconcileVerdictRecord is the durable per-op classification written beside
// the journal record (<reconcile>/verdicts/<op_id>.json). Plain data, parsed
// identifiers only — never raw inspect JSON.
type reconcileVerdictRecord struct {
	OpID  string        `json:"op_id"`
	Kind  string        `json:"kind"`
	Mode  string        `json:"mode,omitempty"`
	Phase journal.Phase `json:"phase"`

	Verdict           string `json:"verdict"`
	Reason            string `json:"reason"`
	RecommendedAction string `json:"recommended_action"`
	TagHazard         bool   `json:"tag_hazard"`

	TargetRef            string `json:"target_ref,omitempty"`
	PriorRef             string `json:"prior_ref,omitempty"`
	RunningMatchesTarget bool   `json:"running_matches_target"`
	RunningMatchesPrior  bool   `json:"running_matches_prior"`
	TagMatchesTarget     bool   `json:"tag_matches_target"`

	Inputs reconcileInputSummary `json:"inputs"`

	ComputedAt         time.Time `json:"computed_at"`
	Attempts           int       `json:"attempts"`
	LastHealth         string    `json:"last_health,omitempty"`
	LastResolveOpID    string    `json:"last_resolve_op_id,omitempty"`
	LastResolveOutcome string    `json:"last_resolve_outcome,omitempty"`
}

// reconcileInputSummary is the captured fact set the verdict was computed from.
type reconcileInputSummary struct {
	DockerReachable bool     `json:"docker_reachable"`
	RefValid        bool     `json:"ref_valid"`
	RefReason       string   `json:"ref_reason,omitempty"`
	RunningImageID  string   `json:"running_image_id,omitempty"`
	RunningDigests  []string `json:"running_digests,omitempty"`
	TagImageID      string   `json:"tag_image_id,omitempty"`
	TagDigests      []string `json:"tag_digests,omitempty"`
}

// reconcileClassification is one record's computed verdict + the inputs it was
// derived from, before persistence.
type reconcileClassification struct {
	rec     *journal.Record
	verdict reconcileVerdictRecord
	action  reconcileAction // meaningful only when verdict is one of the core's actions
	live    bool            // Docker inputs were captured (verdict is actionable)
}

// reconcileDeadline bounds one startup pass.
func (s *Server) reconcileDeadline() time.Duration {
	if s.opts.Cfg != nil && s.opts.Cfg.StageTimeout > 0 {
		return s.opts.Cfg.StageTimeout
	}
	return defaultReconcileDeadline
}

// ReconcileOnStartup classifies every interrupted journal record and
// auto-resolves only the non-mutating verdicts. It never returns an error —
// a reconcile pass must never prevent the agent from serving; problems are
// logged and surfaced on /v1/status. Returns the number of records that still
// need operator attention.
func (s *Server) ReconcileOnStartup(ctx context.Context) (attention int) {
	if s.opts.Journal == nil || s.opts.Runner == nil {
		return 0
	}
	recs, quarantined, err := s.opts.Journal.ListQuarantining(time.Now().UTC())
	if err != nil {
		log.Printf("culvert-maint: reconcile: journal unreadable (%v) — serving with attention_required", err)
		return 1
	}
	_ = quarantined // already logged by the journal opener; count what is on disk
	if q, qerr := s.opts.Journal.Quarantined(); qerr == nil {
		attention += len(q)
	}
	if len(recs) == 0 {
		return attention
	}
	ctx, cancel := context.WithTimeout(ctx, s.reconcileDeadline())
	defer cancel()
	for i := range recs {
		rec := recs[i]
		if s.opts.Ops.IsRunning(rec.OpID) {
			continue // a live op's record is not an interrupted one
		}
		if s.reconcileOne(ctx, &rec) {
			attention++
		}
	}
	return attention
}

// reconcileOne classifies, persists and (when safe) auto-resolves one record.
// Returns true when the record still needs attention.
func (s *Server) reconcileOne(ctx context.Context, rec *journal.Record) bool {
	prev, _ := s.readVerdict(rec.OpID)
	attempts := 0
	if prev != nil {
		attempts = prev.Attempts
	}
	cl := s.classifyRecord(ctx, rec, attempts)
	if prev != nil {
		cl.verdict.LastResolveOpID = prev.LastResolveOpID
		cl.verdict.LastResolveOutcome = prev.LastResolveOutcome
	}
	if werr := s.persistVerdict(prev, &cl); werr != nil {
		log.Printf("culvert-maint: reconcile: op=%s verdict persist failed: %v", rec.OpID, werr)
	}
	if !cl.live {
		log.Printf("culvert-maint: WARN reconcile: op=%s kind=%s phase=%s verdict=%s reason=%s — needs attention (POST /v1/reconcile/%s)",
			rec.OpID, rec.Kind, rec.Phase, cl.verdict.Verdict, cl.verdict.Reason, rec.OpID)
		return true
	}
	switch cl.action {
	case actNoop:
		s.retireRecord(rec.OpID)
		s.auditReconcile(reconcileActor, rec.OpID, auditKindReconcileNoop, cl.verdict, audit.OutcomeSucceeded)
		log.Printf("culvert-maint: reconcile: op=%s kind=%s phase=%s — nothing to undo (%s); record retired",
			rec.OpID, rec.Kind, rec.Phase, cl.verdict.Reason)
		return false
	case actVerifyAdoptElseRollback:
		if s.adoptIfHealthy(ctx, rec, &cl.verdict) {
			return false
		}
		s.warnAttention(rec, cl.verdict)
		return true
	default:
		s.warnAttention(rec, cl.verdict)
		return true
	}
}

// persistVerdict writes the classification, EXCEPT that an inputs_unavailable
// result never replaces a stored ACTIONABLE verdict: "docker was unreachable
// just now" carries no action of its own, and overwriting the last real verdict
// with it would force a spurious verdict_changed round on the explicit resolver
// once the daemon is back.
func (s *Server) persistVerdict(prev *reconcileVerdictRecord, cl *reconcileClassification) error {
	if !cl.live && prev != nil && prev.Verdict != verdictInputsUnavailable {
		return nil
	}
	return s.opts.Journal.WriteVerdict(cl.verdict.OpID, cl.verdict)
}

// adoptIfHealthy probes the live target; on a clean pass it re-terminalizes the
// op as succeeded(reconciled) and retires the record. Any probe failure,
// timeout, or missing probe factory leaves the record surfaced (never a
// rollback at boot). Persists the probe outcome into the verdict either way.
func (s *Server) adoptIfHealthy(ctx context.Context, rec *journal.Record, v *reconcileVerdictRecord) bool {
	ok, detail := s.probeHealth(ctx)
	v.LastHealth = detail
	if !ok {
		v.RecommendedAction = recommendFor(v.Verdict, true, v.Reason)
		_ = s.opts.Journal.WriteVerdict(rec.OpID, *v)
		return false
	}
	return s.adopt(rec.OpID, v, reconcileActor)
}

// adopt marks the interrupted op succeeded(reconciled) and retires its record.
// The override is narrow (ops.Manager.OverrideInterrupted) — if the op is not
// in the interrupted state (e.g. mark-only mode did not register it) the
// record is still retired: Docker truth says the target is live and healthy.
func (s *Server) adopt(opID string, v *reconcileVerdictRecord, actor string) bool {
	// Analyzer-visible CWE-117 barrier (see logSafeOpID); inline because
	// the taint analysis clears taint only at the sanitizer CALL SITE.
	opID = strings.ReplaceAll(strings.ReplaceAll(opID, "\n", ""), "\r", "")
	result := map[string]interface{}{
		"reconciled": true, "reconcile_reason": v.Reason, "target_ref": v.TargetRef, "health": v.LastHealth,
	}
	if err := s.opts.Ops.OverrideInterrupted(opID, ops.StateSucceeded, "", result); err != nil {
		log.Printf("culvert-maint: reconcile: op=%s adopt: op state not overridden (%v)", opID, err)
	}
	s.retireRecord(opID)
	s.auditReconcile(actor, opID, auditKindReconcileAdopt, *v, audit.OutcomeSucceeded)
	log.Printf("culvert-maint: reconcile: op=%s target %s is live and healthy — adopted as succeeded(reconciled)", opID, v.TargetRef)
	return true
}

// probeHealth runs the configured probe once. (ok=false, detail) on any failure.
func (s *Server) probeHealth(ctx context.Context) (ok bool, detail string) {
	if s.opts.HealthProbeFactory == nil {
		return false, "health probe not wired"
	}
	hr, err := s.opts.HealthProbeFactory().Run(ctx)
	if err != nil {
		return false, "probe error: " + err.Error()
	}
	detail = fmt.Sprintf("ready=%v ready_detail=%q health=%v health_detail=%q", hr.ReadyOK, hr.ReadyDetail, hr.HealthOK, hr.HealthDetail)
	return !hr.Failed(), detail
}

// warnAttention emits the startup WARN for a surfaced verdict, naming the
// pinned-tag hazard explicitly when present.
func (s *Server) warnAttention(rec *journal.Record, v reconcileVerdictRecord) {
	if v.TagHazard {
		log.Printf("culvert-maint: WARN reconcile: op=%s TAG HAZARD — %s already points at %s but the container is NOT running it; the next `docker compose up` starts that un-health-gated image. Not executed automatically: POST /v1/reconcile/%s {\"action\":\"resolve\"} to converge under the health gate",
			rec.OpID, runner.PinnedProxyTag, v.TargetRef, rec.OpID)
		return
	}
	log.Printf("culvert-maint: WARN reconcile: op=%s kind=%s phase=%s verdict=%s reason=%s — not executed automatically; %s",
		rec.OpID, rec.Kind, rec.Phase, v.Verdict, v.Reason, v.RecommendedAction)
}

// retireRecord removes the journal record + verdict (both idempotent).
func (s *Server) retireRecord(opID string) {
	opID = strings.ReplaceAll(strings.ReplaceAll(opID, "\n", ""), "\r", "") // CWE-117 barrier, see logSafeOpID
	if err := s.opts.Journal.Remove(opID); err != nil {
		log.Printf("culvert-maint: reconcile: op=%s record remove failed: %v", opID, err)
	}
	if err := s.opts.Journal.RemoveVerdict(opID); err != nil {
		log.Printf("culvert-maint: reconcile: op=%s verdict remove failed: %v", opID, err)
	}
}

// readVerdict returns the stored verdict or nil (absent or unreadable).
func (s *Server) readVerdict(opID string) (*reconcileVerdictRecord, error) {
	var v reconcileVerdictRecord
	found, err := s.opts.Journal.ReadVerdict(opID, &v)
	if err != nil || !found {
		return nil, err
	}
	return &v, nil
}

// auditReconcile writes one reconcile audit event (parsed identifiers only).
func (s *Server) auditReconcile(actor, opID, kind string, v reconcileVerdictRecord, outcome audit.Outcome) {
	now := time.Now().UTC()
	_ = s.opts.Audit.Write(audit.Event{
		Actor: actor, OpID: opID, Kind: kind, Outcome: outcome, OutcomeAt: &now,
		Params: map[string]interface{}{
			"verdict": v.Verdict, "reason": v.Reason, "phase": string(v.Phase),
			"target_ref": v.TargetRef, "prior_ref": v.PriorRef, "tag_hazard": v.TagHazard,
			"source_kind": v.Kind, "source_mode": v.Mode,
		},
	})
}

// classifyRecord validates refs, captures Docker truth and runs the pure
// decision table. It never mutates anything.
func (s *Server) classifyRecord(ctx context.Context, rec *journal.Record, attempts int) reconcileClassification {
	v := reconcileVerdictRecord{
		OpID: rec.OpID, Kind: rec.Kind, Mode: rec.Mode, Phase: rec.Phase,
		TargetRef: rec.TargetRef, PriorRef: rec.PriorRef,
		ComputedAt: time.Now().UTC(), Attempts: attempts,
	}
	in := reconcileInputs{
		Kind: rec.Kind, Mode: rec.Mode, Phase: rec.Phase,
		Attempts: attempts, MaxAttempts: reconcileMaxAttempts,
		TargetImageID: rec.TargetImageID, PriorImageID: rec.PriorImageID,
		TargetDigests: digestsOf(rec.TargetDigest), PriorDigests: digestsOf(rec.PriorDigest),
	}
	in.RefValid, v.Inputs.RefReason = validateReconcileRefs(rec, s.opts.Cfg.ProxyRepo)
	v.Inputs.RefValid = in.RefValid

	// Two rows need no Docker at all: a data-window record is manual by
	// construction, and a safe-boundary record that recorded NO refs (crashed
	// before resolve_target) has nothing a tag could have advanced to.
	if rec.Kind == ops.KindRollbackCreate && rec.Mode == "data" {
		return s.finishClassification(rec, v, reconcileVerdict{actDataManual, "data_window_manual"}, in, true)
	}
	if refsAbsent(rec) && safeBoundary(rec.Phase) {
		return s.finishClassification(rec, v, reconcileVerdict{actNoop, "safe_boundary_no_refs"}, in, true)
	}

	// Docker readiness gate (design P1): a capture ERROR must never be read as
	// "running = ∅". compose ps succeeding is the readiness evidence.
	if _, err := s.opts.Runner.ComposeStatus(ctx); err != nil {
		v.Verdict = verdictInputsUnavailable
		v.Reason = "docker_unavailable"
		v.RecommendedAction = recommendFor(v.Verdict, false, v.Reason)
		return reconcileClassification{rec: rec, verdict: v}
	}
	v.Inputs.DockerReachable = true
	if ri, err := s.opts.Runner.CaptureRunningProxyImage(ctx); err == nil {
		in.RunningImageID = ri.RunningImageID
		in.RunningDigests = bareDigests(ri.RepoDigests)
	}
	in.TagDigests, v.Inputs.TagImageID = s.pinnedTagIdentity(ctx)
	v.Inputs.RunningImageID, v.Inputs.RunningDigests, v.Inputs.TagDigests = in.RunningImageID, in.RunningDigests, in.TagDigests
	// The tag's config digest is appended to BOTH tag and target sets so a
	// record whose TargetImageID is known matches the tag on the class-invariant
	// key (the manifest axis alone misses a tag-pulled lineage, design P0-A).
	if v.Inputs.TagImageID != "" {
		in.TagDigests = append(in.TagDigests, v.Inputs.TagImageID)
	}
	if rec.TargetImageID != "" {
		in.TargetDigests = append(in.TargetDigests, rec.TargetImageID)
	}
	return s.finishClassification(rec, v, reconcileDecision(in), in, true)
}

// finishClassification fills the verdict from the decision + derived facts.
func (s *Server) finishClassification(rec *journal.Record, v reconcileVerdictRecord, d reconcileVerdict, in reconcileInputs, live bool) reconcileClassification {
	v.Verdict = d.Action.String()
	v.Reason = d.Reason
	v.TagHazard = d.Action == actReup
	v.RunningMatchesTarget = sameImage(in.RunningImageID, in.TargetImageID, in.RunningDigests, in.TargetDigests)
	v.RunningMatchesPrior = sameImage(in.RunningImageID, in.PriorImageID, in.RunningDigests, in.PriorDigests)
	v.TagMatchesTarget = digestSetsIntersect(normDigests(in.TagDigests), normDigests(in.TargetDigests))
	v.RecommendedAction = recommendFor(v.Verdict, false, v.Reason)
	return reconcileClassification{rec: rec, verdict: v, action: d.Action, live: live}
}

// pinnedTagIdentity asks what culvert/proxy:pinned resolves to locally:
// (bare repo digests, config digest). Both empty when the tag is absent.
func (s *Server) pinnedTagIdentity(ctx context.Context) (digests []string, imageID string) {
	res, err := s.opts.Runner.ComposeImageInspect(ctx, runner.PinnedProxyTag)
	if err != nil || res == nil {
		return nil, ""
	}
	return bareDigests(repoDigestsFromInspect(res.Stdout)), imageIDFromInspect(res.Stdout)
}

// digestsOf wraps a (possibly empty) record digest as a set.
func digestsOf(d string) []string {
	if d == "" {
		return nil
	}
	return []string{d}
}

// refsAbsent reports a record that carries no ref/digest at all.
func refsAbsent(rec *journal.Record) bool {
	return rec.TargetRef == "" && rec.TargetDigest == "" && rec.PriorRef == "" && rec.PriorDigest == ""
}

// recommendFor renders the operator-facing next step for a verdict.
func recommendFor(verdict string, healthFailed bool, reason string) string {
	switch verdict {
	case actNoop.String():
		return "safe: nothing to undo; resolve or dismiss clears the record"
	case actVerifyAdoptElseRollback.String():
		if healthFailed {
			return "target is live but NOT healthy: resolve rolls back to prior_ref (local-first) under the health gate; or repair manually, then dismiss with acknowledge_unresolved=true"
		}
		return "target is live: resolve re-probes health and adopts if healthy, else rolls back to prior_ref"
	case actReup.String():
		return "TAG HAZARD: " + runner.PinnedProxyTag + " already points at target_ref but the container is not running it — the next `docker compose up` starts the un-health-gated target; resolve runs tag+up under the health gate, or dismiss with acknowledge_tag_hazard=true after manual repair"
	case actRollbackToPrior.String():
		return "running image is neither target nor prior: resolve rolls back to prior_ref (local-first), or repair manually, then dismiss with acknowledge_unresolved=true"
	case actLoudStop.String():
		return "manual: " + reason + " — the agent will not act; repair, then dismiss with acknowledge_unresolved=true"
	case actDataManual.String():
		return "manual: interrupted /data rollback window is never auto-reconciled; inspect /data (see restore runbook), then dismiss with acknowledge_unresolved=true"
	case verdictInputsUnavailable:
		return "docker was not reachable when classified: resolve recomputes once the daemon is up"
	default:
		return "not classified (reconcile_on_startup=false or verdict missing): resolve recomputes against Docker truth"
	}
}

// resolveTargetFor returns the ref a resolve action moves the stack to, and
// the action label, for an executable verdict. ("" , "") when none.
func resolveTargetFor(action reconcileAction, v *reconcileVerdictRecord) (ref, label string) {
	switch action {
	case actReup:
		return v.TargetRef, "reup"
	case actRollbackToPrior, actVerifyAdoptElseRollback:
		return v.PriorRef, "rollback_to_prior"
	default:
		return "", ""
	}
}

// isNoopVerdict reports a verdict that mutates nothing.
func isNoopVerdict(verdict string) bool { return strings.EqualFold(verdict, actNoop.String()) }

// logSafeOpID documents the analyzer-visible CWE-117 barrier for an op id that is
// about to reach the process log. Every caller already holds a canonical ULID
// (the HTTP handler refuses anything validOpID rejects before it reaches
// adopt/retireRecord, and the journal names its files by the same id), so the
// replacement is a no-op on every real value — but taint analysis cannot see
// a validator, only a sanitizer, and gosec G706 recognises strings.ReplaceAll.
// The two production sites (adopt, retireRecord) spell the same expression
// INLINE: gosec's taint engine clears taint only where the sanitizer is
// called, not through a wrapper, so a helper call there is not a barrier.
// This function is the single definition the gate test pins the inline
// expression against, so the two cannot drift apart.
func logSafeOpID(opID string) string {
	return strings.ReplaceAll(strings.ReplaceAll(opID, "\n", ""), "\r", "")
}
