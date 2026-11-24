// Opt-in startup reconcile (reconcile_on_startup = "converge"; contract AGT-900,
// owner decision 1). With the default "off" nothing in this file runs and
// startup reports and changes nothing (AGT-004).
//
// Ordering, so the report-only guarantees survive every outcome:
//  1. main's initJournal runs unchanged: every record's op is marked
//     failed(agent_restart_interrupted) and audited first. That op is never
//     flipped; the reconcile is a SEPARATE op, reconcile.startup.
//  2. PrepareStartupReconcile (before Serve): take the instance flock on
//     <state_dir>/reconcile/.lock for the life of the process (held by another
//     process: skip, report skipped_second_instance), then Begin the
//     reconcile.startup op, which holds the maintenance lock, so an operator's
//     state-changing request gets 409 naming it (AGT-001) while reads serve.
//  3. Serve binds the socket, THEN starts the work (the API is never dark).
//
// Per record: validate refs; read Docker (container, fixed tag, local ids of
// the validated refs); decide with the pure reconcileDecisionV2; for an action
// that changes Docker, persist the attempt FAIL-CLOSED first (no durable
// write, no action), re-read Docker and act only if the decision is unchanged
// (TOCTOU), act through the existing runner/sudoers commands only (tag to the
// validated PriorRef; `compose up` only to finish an armed rollback whose tag
// is already on the prior image; never pull, never down, never a tag to the
// target), then verify by image id. Audit, THEN retire the record, and only
// after verified convergence. A recovery_required or deferred record is kept.
package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// AuditActorReconcile is the audit actor of the startup reconcile.
const AuditActorReconcile = "agent:reconcile"

// maxReconcileAttempts caps the Docker-changing reconcile attempts per record
// across all starts (persisted in Record.ReconcileAttempts).
const maxReconcileAttempts = 2

// dockerReadyBudget bounds the wait for a readable Docker daemon at startup;
// the stage timeout lowers it further.
const dockerReadyBudget = 60 * time.Second

// Reconcile states (ReconcileStatus.State).
const (
	ReconcileInProgress      = "in_progress"
	ReconcileDone            = "done"
	ReconcileDeferred        = "deferred"
	ReconcileRecoveryNeeded  = "recovery_required"
	ReconcileAbandoned       = "abandoned"
	ReconcileSkippedInstance = "skipped_second_instance"
	ReconcileLockUnavailable = "lock_unavailable"
	ReconcileNotStarted      = "not_started"
)

// Per-record outcomes (ReconcileRecord.Outcome).
const (
	OutcomeConverged           = "converged"
	OutcomeConvergedNotRetired = "converged_not_retired"
	OutcomeRecoveryRequired    = "recovery_required"
	OutcomeDeferred            = "deferred"
	OutcomeAbandoned           = "abandoned"
)

// ReconcileStatus is GET /v1/status `reconcile` (present only in converge mode).
type ReconcileStatus struct {
	State      string            `json:"state"`
	OpID       string            `json:"op_id,omitempty"`
	StartedAt  *time.Time        `json:"started_at,omitempty"`
	FinishedAt *time.Time        `json:"finished_at,omitempty"`
	Records    []ReconcileRecord `json:"records"`
}

// ReconcileRecord is the reconcile result for one journal record. Closed-set
// strings and the ULID-checked op id only; no reference or id from the record.
type ReconcileRecord struct {
	OpID             string   `json:"source_op_id"`
	Kind             string   `json:"kind"`
	Decision         string   `json:"decision"`
	Reason           string   `json:"reason"`
	Outcome          string   `json:"outcome"`
	Actions          []string `json:"actions,omitempty"`
	DockerReconciled bool     `json:"docker_reconciled"`
	RunningImage     string   `json:"running_image,omitempty"`
	PinnedTag        string   `json:"pinned_tag,omitempty"`
}

// ReconcileTracker holds the reconcile status shared with GET /v1/status.
type ReconcileTracker struct {
	mu sync.Mutex
	st ReconcileStatus
}

// NewReconcileTracker returns a tracker in the not_started state.
func NewReconcileTracker() *ReconcileTracker {
	return &ReconcileTracker{st: ReconcileStatus{State: ReconcileNotStarted, Records: []ReconcileRecord{}}}
}

// Snapshot returns a copy of the status.
func (t *ReconcileTracker) Snapshot() ReconcileStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.st
	out.Records = make([]ReconcileRecord, len(t.st.Records))
	for i := range t.st.Records {
		out.Records[i] = t.st.Records[i]
		out.Records[i].Actions = append([]string(nil), t.st.Records[i].Actions...)
	}
	return out
}

// RecoveryRequired reports whether a record was left needing an operator.
func (t *ReconcileTracker) RecoveryRequired() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.st.Records {
		switch t.st.Records[i].Outcome {
		case OutcomeRecoveryRequired, OutcomeAbandoned, OutcomeConvergedNotRetired:
			return true
		}
	}
	return false
}

// RecordFor returns the reconcile result for a source op, if any.
func (t *ReconcileTracker) RecordFor(opID string) (ReconcileRecord, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.st.Records {
		if t.st.Records[i].OpID == opID {
			r := t.st.Records[i]
			r.Actions = append([]string(nil), r.Actions...)
			return r, true
		}
	}
	return ReconcileRecord{}, false
}

func (t *ReconcileTracker) setState(state string) {
	t.mu.Lock()
	t.st.State = state
	t.mu.Unlock()
}

func (t *ReconcileTracker) begin(opID string, at time.Time) {
	t.mu.Lock()
	t.st.State, t.st.OpID, t.st.StartedAt = ReconcileInProgress, opID, &at
	t.mu.Unlock()
}

func (t *ReconcileTracker) put(r ReconcileRecord) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.st.Records {
		if t.st.Records[i].OpID == r.OpID {
			t.st.Records[i] = r
			return
		}
	}
	t.st.Records = append(t.st.Records, r)
}

func (t *ReconcileTracker) finish(state string, at time.Time) {
	t.mu.Lock()
	t.st.State, t.st.FinishedAt = state, &at
	t.mu.Unlock()
}

// holdInstanceLock makes sure this process holds the state_dir instance lock
// before the reconcile reads a record. main takes it before anything else and
// hands it over (Options.InstanceLock), so in production this only confirms
// it; a server built without it (tests) takes it here, as before ADR-0062.
func (s *Server) holdInstanceLock(t *ReconcileTracker) bool {
	s.mu.Lock()
	held := s.reconcileLock != nil
	s.mu.Unlock()
	if held {
		return true
	}
	lock, err := s.opts.Journal.LockReconcile()
	if err != nil {
		state := ReconcileLockUnavailable
		if errors.Is(err, journal.ErrLockHeld) {
			state = ReconcileSkippedInstance
		}
		t.setState(state)
		log.Printf("culvert-maint: startup reconcile not run (%s); interrupted operations are reported only", state)
		return false
	}
	s.mu.Lock()
	s.reconcileLock = lock
	s.mu.Unlock()
	return true
}

// PrepareStartupReconcile arms the converge reconcile. Call it after New and
// before Serve, and only when reconcile_on_startup = "converge". It never
// fails startup: anything that prevents a safe reconcile is reported in the
// tracker and the agent serves in report-only posture.
func (s *Server) PrepareStartupReconcile(t *ReconcileTracker) {
	if t == nil || s.opts.Journal == nil {
		return
	}
	s.reconcileTracker = t
	if !s.holdInstanceLock(t) {
		return
	}

	recs, err := s.opts.Journal.List()
	if err != nil {
		t.setState(ReconcileRecoveryNeeded)
		log.Printf("culvert-maint: startup reconcile not run: the journal could not be listed")
		return
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].OpID < recs[j].OpID })
	if len(recs) == 0 {
		t.finish(ReconcileDone, time.Now().UTC())
		return
	}
	op, err := s.opts.Ops.Begin(ops.KindReconcileStartup, AuditActorReconcile, "", map[string]interface{}{"records": len(recs)})
	if err != nil {
		t.setState(ReconcileLockUnavailable)
		log.Printf("culvert-maint: startup reconcile not run: could not take the maintenance lock")
		return
	}
	now := time.Now().UTC()
	t.begin(op.ID, now)
	_ = s.opts.Audit.Write(audit.Event{Actor: AuditActorReconcile, OpID: op.ID, Kind: ops.KindReconcileStartup,
		Params: map[string]interface{}{"records": len(recs)}, Outcome: audit.OutcomeStarted})
	s.mu.Lock()
	s.startupWork = func() { s.runStartupReconcile(op.ID, recs) }
	s.mu.Unlock()
}

// reconcileDeadline is the single deadline for the whole reconcile.
func (s *Server) reconcileDeadline() time.Duration {
	if st := s.opts.Cfg.StageTimeout; st > 0 {
		return 2 * st
	}
	return 10 * time.Minute
}

// runStartupReconcile is the reconcile.startup op body (run via goOp after the
// listener is bound). Detached from SIGTERM like every op; a kill mid-way is a
// crash the next start reconciles from Docker truth again.
func (s *Server) runStartupReconcile(opID string, recs []journal.Record) {
	ctx, cancel := context.WithTimeout(context.Background(), s.reconcileDeadline())
	defer cancel()
	results := make([]ReconcileRecord, 0, len(recs))
	defer func() {
		if p := recover(); p != nil {
			log.Printf("culvert-maint: startup reconcile panicked; finishing it failed")
			s.finishStartupReconcile(opID, results, true)
		}
	}()
	ready := s.waitDockerReadable(ctx)
	for i := range recs {
		var r ReconcileRecord
		if ctx.Err() != nil {
			r = ReconcileRecord{OpID: recs[i].OpID, Kind: reportKind(recs[i].Kind), Decision: actV2RecoveryRequired.String(),
				Reason: "deadline_elapsed", Outcome: OutcomeAbandoned}
		} else {
			r = s.reconcileOne(ctx, opID, recs[i].OpID, ready)
		}
		results = append(results, r)
		s.reconcileTracker.put(r)
		log.Printf("culvert-maint: reconcile op %s: record %s decision=%s/%s outcome=%s actions=%v",
			opID, r.OpID, r.Decision, r.Reason, r.Outcome, r.Actions)
	}
	s.finishStartupReconcile(opID, results, false)
}

// finishStartupReconcile ends the reconcile.startup op: succeeded only when
// every record converged and was retired.
func (s *Server) finishStartupReconcile(opID string, results []ReconcileRecord, panicked bool) {
	state, reason, trackerState := ops.StateSucceeded, ops.FailureReason(""), ReconcileDone
	counts := map[string]int{}
	for i := range results {
		counts[results[i].Outcome]++
	}
	switch {
	case panicked:
		state, reason, trackerState = ops.StateFailed, ops.ReasonAgentPanic, ReconcileAbandoned
	case counts[OutcomeAbandoned] > 0:
		state, reason, trackerState = ops.StateFailed, ops.ReasonRecoveryRequired, ReconcileAbandoned
	case counts[OutcomeRecoveryRequired]+counts[OutcomeConvergedNotRetired] > 0:
		state, reason, trackerState = ops.StateFailed, ops.ReasonRecoveryRequired, ReconcileRecoveryNeeded
	case counts[OutcomeDeferred] > 0:
		state, reason, trackerState = ops.StateFailed, ops.ReasonRecoveryRequired, ReconcileDeferred
	}
	list := make([]interface{}, 0, len(results))
	for i := range results {
		list = append(list, reconcileRecordMap(&results[i]))
	}
	_ = s.opts.Ops.Finish(opID, state, reason, map[string]interface{}{"reconciled": list})
	now := time.Now().UTC()
	ev := audit.Event{Actor: AuditActorReconcile, OpID: opID, Kind: ops.KindReconcileStartup,
		Params: map[string]interface{}{"records": len(results), "outcomes": counts}, Outcome: audit.OutcomeSucceeded, OutcomeAt: &now}
	if state == ops.StateFailed {
		ev.Outcome, ev.FailureReason = audit.OutcomeFailed, string(reason)
	}
	_ = s.opts.Audit.Write(ev)
	s.reconcileTracker.finish(trackerState, now)
}

func reconcileRecordMap(r *ReconcileRecord) map[string]interface{} {
	actions := make([]interface{}, 0, len(r.Actions))
	for _, a := range r.Actions {
		actions = append(actions, a)
	}
	return map[string]interface{}{
		"source_op_id": r.OpID, "kind": r.Kind, "decision": r.Decision, "reason": r.Reason,
		"outcome": r.Outcome, "actions": actions, "docker_reconciled": r.DockerReconciled,
		"running_image": r.RunningImage, "pinned_tag": r.PinnedTag,
	}
}

// waitDockerReadable retries a read-only `compose ps` until Docker answers,
// for at most dockerReadyBudget (or the stage timeout, if shorter).
func (s *Server) waitDockerReadable(ctx context.Context) bool {
	budget := dockerReadyBudget
	if st := s.opts.Cfg.StageTimeout; st > 0 && st < budget {
		budget = st
	}
	deadline := time.Now().Add(budget)
	backoff := time.Second
	for {
		if _, err := s.opts.Runner.ReadProxyContainer(ctx); err == nil {
			return true
		}
		if time.Now().Add(backoff).After(deadline) || ctx.Err() != nil {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

// reconcileCase carries one record through the reconcile.
type reconcileCase struct {
	opID string // reconcile.startup op
	rec  *journal.Record
	in   reconcileInputsV2
	out  ReconcileRecord
}

// reconcileOne decides and (maybe) acts on one record, and returns its result.
func (s *Server) reconcileOne(ctx context.Context, opID, recID string, dockerReady bool) ReconcileRecord {
	rec, found, err := s.opts.Journal.Read(recID)
	if err != nil || !found {
		// The list succeeded a moment ago and the instance lock is held, so
		// this is an I/O failure: report it, change nothing.
		return ReconcileRecord{OpID: recID, Kind: "unknown", Decision: actV2RecoveryRequired.String(),
			Reason: "journal_unreadable", Outcome: OutcomeRecoveryRequired}
	}
	if rec.FromNewerAgent() {
		// ADR-0062: a record a newer agent wrote may carry facts this build
		// cannot read (and the journal refuses to rewrite or remove it). It is
		// reported and never acted on, before any Docker read.
		return ReconcileRecord{OpID: rec.OpID, Kind: reportKind(rec.Kind), Decision: actV2RecoveryRequired.String(),
			Reason: "record_from_newer_agent", Outcome: OutcomeRecoveryRequired}
	}
	if rec.TerminalOutcome != "" && rec.TerminalSafe {
		// The operation ended with its end state proven safe; only its terminal
		// audit entry or its removal was cut, and startup retries both. There
		// is nothing for the reconcile to decide (Codex review on #2102).
		return ReconcileRecord{OpID: rec.OpID, Kind: reportKind(rec.Kind), Decision: actV2Defer.String(),
			Reason: "terminal_cleanup_pending", Outcome: OutcomeDeferred}
	}
	c := &reconcileCase{opID: opID, rec: rec, in: s.reconcileInputsFor(rec)}
	c.out = ReconcileRecord{OpID: rec.OpID, Kind: reportKind(rec.Kind)}
	// Docker was tested and does not answer: there is nothing to observe, so
	// there is nothing to wait for either. The settle wait exists to make
	// what is READ from Docker trustworthy; spending the reconcile's budget on
	// it here turned a transient "Docker is down" into recovery_required
	// (settle_wait_cut_short) on real Docker. The decision is taken with
	// DockerReadable=false: an image record is deferred (docker_unavailable),
	// kept untouched, and decided again at the next start, which waits out its
	// own window; a data or unknown record gets its usual report. Nothing is
	// read, changed or retired on this path.
	if dockerReady {
		// Decide only on a Docker that no request of the previous agent process
		// can still change: dockerd may be stopping the old proxy container for
		// it, and until that is over a container that is "running the prior
		// image" is not evidence of anything (settle.go). If the wait cannot be
		// completed, the record is kept.
		if _, serr := s.settleInterrupted(ctx); serr != nil {
			c.out.Decision, c.out.Reason = actV2RecoveryRequired.String(), "settle_wait_cut_short"
			return s.keepRecord(c, OutcomeRecoveryRequired)
		}
		s.readReconcileFacts(ctx, rec, &c.in)
	}
	if reconcileNeedsProbe(c.in) {
		c.in.Probe = s.probeReadiness(ctx)
	}
	v := reconcileDecisionV2(c.in)
	c.out.Decision, c.out.Reason = v.Action.String(), v.Reason
	c.out.RunningImage, c.out.PinnedTag = classOf(&c.in, c.in.RunningImageID), classOf(&c.in, c.in.TagImageID)
	switch v.Action {
	case actV2Defer:
		return s.keepRecord(c, OutcomeDeferred)
	case actV2RecoveryRequired:
		return s.keepRecord(c, OutcomeRecoveryRequired)
	case actV2Noop, actV2Adopt:
		// Nothing to change: confirm Docker still says the same, then retire.
		if !s.stillDecides(ctx, c, v) {
			c.out.Reason = "docker_changed_during_reconcile"
			return s.keepRecord(c, OutcomeRecoveryRequired)
		}
		return s.retireIfServing(ctx, c)
	}
	return s.act(ctx, c, v)
}

// reconcileInputsFor maps the record onto the decision input. The record is
// unauthenticated content: ids are shape-checked, a negative attempt count is
// treated as exhausted.
func (s *Server) reconcileInputsFor(rec *journal.Record) reconcileInputsV2 {
	valid, _ := validateReconcileRefs(rec, s.opts.Cfg.ProxyRepo)
	attempts := rec.ReconcileAttempts
	if attempts < 0 {
		attempts = maxReconcileAttempts
	}
	return reconcileInputsV2{
		Kind: rec.Kind, Mode: rec.Mode, Phase: rec.Phase,
		RefValid: valid, TargetRefPresent: rec.TargetRef != "", PriorRefPresent: rec.PriorRef != "",
		TargetDigest: rec.TargetDigest, TargetImageID: reportImageID(rec.TargetImageID),
		PriorImageID: reportImageID(rec.PriorImageID), RollbackArmed: rec.RollbackArmed,
		Attempts: attempts, MaxAttempts: maxReconcileAttempts,
	}
}

// readReconcileFacts fills the Docker half of in. A record's references reach
// Docker only after validateReconcileRefs accepted them; a data or unknown
// record is decided without reading Docker at all.
func (s *Server) readReconcileFacts(ctx context.Context, rec *journal.Record, in *reconcileInputsV2) {
	imageKind := (in.Kind == ops.KindUpgradeApply && in.Mode == "") || (in.Kind == ops.KindRollbackCreate && in.Mode == "image")
	in.DockerReadable = false
	if !imageKind {
		return
	}
	pc, err := s.opts.Runner.ReadProxyContainer(ctx)
	if err != nil {
		return
	}
	tag, err := s.opts.Runner.PinnedTagImageID(ctx)
	if err != nil {
		return
	}
	in.DockerReadable, in.TagImageID = true, tag
	in.RunningImageID, in.ContainerRunning, in.RunningDigests = "", false, nil
	if pc.Present {
		in.RunningImageID, in.ContainerRunning, in.RunningDigests = pc.ImageID, pc.Running, pc.RepoDigests
	}
	in.TargetLocalID, in.PriorLocalID = "", ""
	if !in.RefValid {
		return
	}
	if rec.TargetRef != "" {
		if id, ierr := s.opts.Runner.LocalImageID(ctx, rec.TargetRef); ierr == nil {
			in.TargetLocalID = id
		}
	}
	if rec.PriorRef != "" {
		if id, ierr := s.opts.Runner.LocalImageID(ctx, rec.PriorRef); ierr == nil {
			in.PriorLocalID = id
		}
	}
}

// probeReadiness runs the configured health probe once. Only ReadyOK counts.
func (s *Server) probeReadiness(ctx context.Context) probeState {
	if s.opts.HealthProbeFactory == nil {
		return probeNotRun
	}
	hr, err := s.opts.HealthProbeFactory().Run(ctx)
	if err != nil || hr == nil || !hr.ReadyOK {
		return probeNotReady
	}
	return probeReady
}

// stillDecides re-reads Docker and reports whether the decision is unchanged
// (the probe result of the first read is kept).
func (s *Server) stillDecides(ctx context.Context, c *reconcileCase, v reconcileVerdictV2) bool {
	again := c.in
	s.readReconcileFacts(ctx, c.rec, &again)
	return reconcileDecisionV2(again) == v
}

// act performs realign or finish_rollback: write-ahead, TOCTOU re-read, the
// action, then verification by image id.
func (s *Server) act(ctx context.Context, c *reconcileCase, v reconcileVerdictV2) ReconcileRecord {
	now := time.Now().UTC()
	c.rec.ReconcileAttempts = c.in.Attempts + 1
	c.rec.LastReconcileAt = &now
	c.rec.ReconcileDecision = v.Action.String() + "/" + v.Reason
	if err := s.opts.Journal.Write(*c.rec); err != nil {
		c.out.Reason = "journal_write_failed"
		return s.keepRecord(c, OutcomeRecoveryRequired)
	}
	if !s.stillDecides(ctx, c, v) {
		c.out.Reason = "docker_changed_before_action"
		return s.keepRecord(c, OutcomeRecoveryRequired)
	}
	if err := s.performAction(ctx, c, v); err != nil {
		c.out.Reason = err.Error()
		_ = s.auditReconciled(c, audit.OutcomeFailed) // best-effort: the record is kept either way
		return s.keepRecord(c, OutcomeRecoveryRequired)
	}
	if !s.verifiedOnPrior(ctx, c) {
		c.out.Reason = "post_verify_failed"
		_ = s.auditReconciled(c, audit.OutcomeFailed) // best-effort: the record is kept either way
		return s.keepRecord(c, OutcomeRecoveryRequired)
	}
	c.out.DockerReconciled = true
	return s.retireIfServing(ctx, c)
}

// retireIfServing is the only way a record is retired by the reconcile.
//
// Matching identities are not convergence: "the container runs the prior image
// and the tag is on it" was true, on real Docker, of a proxy dockerd was
// already stopping for the dead operation. A record is retired only when
//   - the settle window is over, so no request of the previous agent process
//     can still be pending (reconcileOne waited for it before reading Docker),
//     and
//   - a readiness probe taken NOW, after that, succeeds.
//
// Anything less keeps the record and reports recovery_required. There is no
// "probably converged".
func (s *Server) retireIfServing(ctx context.Context, c *reconcileCase) ReconcileRecord {
	if s.settleRemaining() > 0 {
		c.out.DockerReconciled = false
		c.out.Reason = "settle_not_established"
		return s.keepRecord(c, OutcomeRecoveryRequired)
	}
	if s.probeReadiness(ctx) != probeReady {
		c.out.DockerReconciled = false
		c.out.Reason = "not_ready_at_retirement"
		return s.keepRecord(c, OutcomeRecoveryRequired)
	}
	return s.retire(c)
}

// errReconcileStep is a reconcile step that failed; its text is a closed-set
// reason for the report.
type errReconcileStep string

func (e errReconcileStep) Error() string { return string(e) }

// performAction runs the Docker change for v. Only existing runner methods are
// used: the tag goes to the record's validated PriorRef, and `compose up` runs
// only for finish_rollback, whose decision required the tag to be on the prior
// image already.
func (s *Server) performAction(ctx context.Context, c *reconcileCase, v reconcileVerdictV2) error {
	switch v.Action {
	case actV2Realign:
		c.out.Actions = append(c.out.Actions, "tag:prior")
		if _, err := s.opts.Runner.ComposeTagPinned(ctx, c.rec.PriorRef); err != nil {
			return errReconcileStep("tag_failed")
		}
		return nil
	case actV2FinishRollback:
		c.out.Actions = append(c.out.Actions, "up")
		if _, err := s.composeUp(ctx); err != nil {
			return errReconcileStep("up_failed")
		}
		if s.probeReadiness(ctx) != probeReady {
			return errReconcileStep("prior_not_ready")
		}
		return nil
	}
	return errReconcileStep("unexpected_action")
}

// verifiedOnPrior re-reads Docker after a realign or finish_rollback: the
// container and the fixed tag must both be the recorded prior image.
func (s *Server) verifiedOnPrior(ctx context.Context, c *reconcileCase) bool {
	after := c.in
	s.readReconcileFacts(ctx, c.rec, &after)
	p := normID(after.PriorImageID)
	c.out.RunningImage, c.out.PinnedTag = classOf(&after, after.RunningImageID), classOf(&after, after.TagImageID)
	return after.DockerReadable && after.ContainerRunning && p != "" &&
		normID(after.RunningImageID) == p && normID(after.TagImageID) == p
}

// retire audits the converged record and only then removes it. A failed audit
// or removal keeps the record (and says so).
//
// Exactly-once audit: the ":reconciled" entry is fsynced BEFORE the record is
// removed, so a crash between the two leaves an audited record that the next
// start retires again. retire therefore first looks for this op's succeeded
// ":reconciled" entry and writes one only if none exists. If the log cannot be
// read it writes anyway: a duplicate entry is acceptable, a retirement with no
// entry is not (AGT-005).
func (s *Server) retire(c *reconcileCase) ReconcileRecord {
	c.out.Outcome = OutcomeConverged
	// A kept record of an operation that ended: its own terminal entry first
	// (normally already done by initJournal), or it is not retired.
	if c.rec.TerminalOutcome != "" && ensureTerminalAudited(s.opts.Audit, c.rec, s.opts.Cfg.ProxyRepo) != nil {
		return s.keepRecord(c, OutcomeConvergedNotRetired)
	}
	if !s.reconciledAlreadyAudited(c) {
		if err := s.auditReconciled(c, audit.OutcomeSucceeded); err != nil {
			return s.keepRecord(c, OutcomeConvergedNotRetired)
		}
	}
	if err := s.opts.Journal.Remove(c.rec.OpID); err != nil {
		return s.keepRecord(c, OutcomeConvergedNotRetired)
	}

	return c.out
}

// reconciledAlreadyAudited reports whether a previous start already wrote this
// record's succeeded ":reconciled" entry and was killed before removing the
// record. Any doubt (no logger path, unreadable log) answers false, so the
// entry is written.
func (s *Server) reconciledAlreadyAudited(c *reconcileCase) bool {
	if s.opts.Audit == nil || c.rec == nil {
		return false
	}
	found, err := audit.HasSucceeded(s.opts.Audit.Path(), c.rec.OpID, reportKind(c.rec.Kind)+":reconciled")
	if err != nil {
		log.Printf("culvert-maint: WARN: could not check the audit log for a prior retirement of %s; writing the entry: %v", c.rec.OpID, err)
		return false
	}
	return found
}

// keepRecord writes the outcome into the kept record (best-effort: the
// in-memory report is authoritative for this process) and returns the result.
func (s *Server) keepRecord(c *reconcileCase, outcome string) ReconcileRecord {
	c.out.Outcome = outcome
	if c.rec != nil {
		c.rec.ReconcileDecision = c.out.Decision + "/" + c.out.Reason
		c.rec.ReconcileOutcome = outcome
		if err := s.opts.Journal.Write(*c.rec); err != nil {
			log.Printf("culvert-maint: WARN: could not record the reconcile outcome of %s", c.rec.OpID)
		}
	}
	return c.out
}

// auditReconciled writes the per-record audit entry: ids and classes only.
func (s *Server) auditReconciled(c *reconcileCase, outcome audit.Outcome) error {
	now := time.Now().UTC()
	actions := make([]interface{}, 0, len(c.out.Actions))
	for _, a := range c.out.Actions {
		actions = append(actions, a)
	}
	ev := audit.Event{
		Actor: AuditActorReconcile, OpID: c.rec.OpID, Kind: reportKind(c.rec.Kind) + ":reconciled",
		Params: map[string]interface{}{
			"reconcile_op_id": c.opID, "decision": c.out.Decision, "reason": c.out.Reason,
			"actions": actions, "running_image": c.out.RunningImage, "pinned_tag": c.out.PinnedTag,
		},
		Outcome: outcome, OutcomeAt: &now,
	}
	if outcome == audit.OutcomeFailed {
		ev.FailureReason = string(ops.ReasonRecoveryRequired)
	}
	if err := s.opts.Audit.Write(ev); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	return nil
}

// classOf names an image id relative to the record: prior / target / other /
// none (no container or tag) / unknown (Docker unreadable).
func classOf(in *reconcileInputsV2, id string) string {
	switch {
	case !in.DockerReadable:
		return RunningIsUnknown
	case normID(id) == "":
		return "none"
	case in.PriorImageID != "" && normID(id) == normID(in.PriorImageID):
		return RunningIsPrior
	case in.TargetLocalID != "" && normID(id) == normID(in.TargetLocalID):
		return RunningIsTarget
	default:
		return RunningIsOther
	}
}
