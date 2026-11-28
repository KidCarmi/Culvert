// Runtime recovery (ADR-0062 slice 6, PR 3; owner decision 2026-11-28: act
// only on images this agent installed).
//
// With runtime_recovery = "restore_last_gated" the agent puts back the image an
// install of its own replaced, when the installed image keeps failing its
// health check:
//
//  1. Trigger. The runtime health observer hands every sample it kept to
//     noteRuntimeSample, which only counts: RuntimeRecoveryStreak consecutive
//     `not_ready` samples of one container and image wake the worker. The
//     observer itself never acts (AGT-007).
//  2. Pre-admission, read-only and without the lock: everything below is
//     checked once so a refusal costs no operation and no audit entry.
//  3. The operation. runtime.recover takes the maintenance lock (operators get
//  409. and checks admission again on fresh facts, under the lock.
//  4. Write-ahead. The attempt counter (runtimehealth.RecoverAttempts), then the
//     journal record: kind runtime.recover, armed, at restarted, the restore
//     image as the prior and the unhealthy image as the target. Both fail
//     closed: nothing moves without them.
//  5. The plan. The decision on fresh facts must be finish_rollback_retag; act
//     then runs the startup reconcile's own steps (tag the prior, recheck, up,
//     gate, verify by image id, probe, audit, retire), each pre-change recheck
//     reading compatibility again (PR 2). A crash anywhere leaves an armed
//     record the startup reconcile decides with the same branch.
//
// Admission (all of them, on fresh facts):
//   - the settle window is over and no operation holds the lock;
//   - the proxy container runs, is the one the samples were of, and the fixed
//     tag is on its image X;
//   - X is the image installed.json names (the agent's last verified upgrade),
//     or the target of a kept upgrade record of this agent; the restore image
//     R is the one that change replaced;
//   - R is in gated.json, its gated reference passes the repo-bound exact-
//     digest gate and the image allowlist, and it is local as that image;
//   - R is compatible with the data (dataCompat, slice 6a);
//   - fewer than runtimehealth.MaxRecoverAttempts recoveries were begun for X
//     from that source.
//
// Anything else is reported (status runtime_recovery.last, and a log line when
// the reason changes) and changes nothing.
package server

import (
	"context"
	"log"
	"sync"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/config"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runtimehealth"
)

// AuditActorRuntimeRecovery is the actor of the agent's own runtime recovery.
const AuditActorRuntimeRecovery = "agent:runtime-recovery"

// RuntimeRecoveryStreak is how many consecutive kept not_ready samples of one
// container and image trigger a recovery.
const RuntimeRecoveryStreak = 3

// Outcomes of a recovery attempt (RuntimeRecoveryAttempt.Outcome).
const (
	RecoveryRefused   = "refused"
	RecoveryRecovered = "recovered"
	RecoveryFailed    = "failed"
)

// RuntimeRecoveryStatus is GET /v1/status `runtime_recovery`.
type RuntimeRecoveryStatus struct {
	Policy         string                  `json:"policy"`
	Threshold      int                     `json:"threshold"`
	NotReadyStreak int                     `json:"not_ready_streak"`
	Running        bool                    `json:"running"`
	Last           *RuntimeRecoveryAttempt `json:"last,omitempty"`
}

// RuntimeRecoveryAttempt is the last evaluation that went past the trigger.
// Image ids only, never a container id.
type RuntimeRecoveryAttempt struct {
	At             time.Time `json:"at"`
	OpID           string    `json:"op_id,omitempty"`
	Outcome        string    `json:"outcome"`
	Reason         string    `json:"reason"`
	ImageID        string    `json:"image_id,omitempty"`
	RestoreImageID string    `json:"restore_image_id,omitempty"`
}

// RuntimeRecoveryTracker is the recovery's in-memory state, shared with the
// status provider. A restart starts it again (the streak too).
type RuntimeRecoveryTracker struct {
	mu      sync.Mutex
	streak  int
	key     string
	running bool
	last    *RuntimeRecoveryAttempt
	kick    chan runtimeTrigger
}

// NewRuntimeRecoveryTracker returns an empty tracker.
func NewRuntimeRecoveryTracker() *RuntimeRecoveryTracker {
	return &RuntimeRecoveryTracker{kick: make(chan runtimeTrigger, 1)}
}

// Snapshot returns the status, with policy filled by the caller.
func (t *RuntimeRecoveryTracker) Snapshot(policy string) RuntimeRecoveryStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := RuntimeRecoveryStatus{Policy: policy, Threshold: RuntimeRecoveryStreak, NotReadyStreak: t.streak, Running: t.running}
	if t.last != nil {
		l := *t.last
		st.Last = &l
	}
	return st
}

func (t *RuntimeRecoveryTracker) setLast(a RuntimeRecoveryAttempt) (changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed = t.last == nil || t.last.Outcome != a.Outcome || t.last.Reason != a.Reason || t.last.ImageID != a.ImageID
	t.last = &a
	return changed
}

func (t *RuntimeRecoveryTracker) setRunning(v bool) {
	t.mu.Lock()
	t.running = v
	t.mu.Unlock()
}

// runtimeTrigger identifies what the streak was of.
type runtimeTrigger struct {
	containerID, imageID string
}

// runtimeRecoveryEnabled reports whether the recovery is configured and wired.
func (s *Server) runtimeRecoveryEnabled() bool {
	return s.opts.Cfg.RuntimeRecovery == config.RecoveryRestoreLastGated && s.opts.RuntimeRecovery != nil &&
		s.opts.Journal != nil && s.runtimeObserverEnabled()
}

// noteRuntimeSample counts a sample the observer kept. It only counts and, at
// the threshold, wakes the worker without waiting; it never reads or changes
// anything else, so the observer stays an observer.
func (s *Server) noteRuntimeSample(smp *runtimehealth.Sample) {
	if !s.runtimeRecoveryEnabled() {
		return
	}
	t := s.opts.RuntimeRecovery
	t.mu.Lock()
	defer t.mu.Unlock()
	if smp.State != runtimehealth.StateUnhealthy || smp.Reason != obsReasonNotReady || smp.ContainerID == "" || smp.ImageID == "" {
		t.streak, t.key = 0, ""
		return
	}
	key := smp.ContainerID + "/" + smp.ImageID
	if key != t.key {
		t.streak, t.key = 0, key
	}
	t.streak++
	if t.streak < RuntimeRecoveryStreak {
		return
	}
	// Another full streak is needed before the next evaluation.
	t.streak, t.key = 0, ""
	select {
	case t.kick <- runtimeTrigger{containerID: smp.ContainerID, imageID: smp.ImageID}:
	default: // one is already pending
	}
}

// startRuntimeRecovery starts the worker when it is configured. It runs under
// goOp, so a recovery in progress is part of the shutdown drain; ctx ending
// stops it between recoveries, never inside one.
func (s *Server) startRuntimeRecovery(ctx context.Context) {
	if !s.runtimeRecoveryEnabled() {
		return
	}
	t := s.opts.RuntimeRecovery
	s.goOp(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case trig := <-t.kick:
				s.runtimeRecoverOnce(trig)
			}
		}
	})
}

// runtimeAdmission is what admission established.
type runtimeAdmission struct {
	sourceOpID       string
	x, xRef, xDigest string
	r                runtimehealth.GatedEntry
	begun            int
	attempts         *runtimehealth.RecoverAttempts // as read by admission
}

// runtimeRecoverOnce evaluates one trigger and, when admitted, recovers.
func (s *Server) runtimeRecoverOnce(trig runtimeTrigger) RuntimeRecoveryAttempt {
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.Cfg.OperationTimeout)
	defer cancel()
	if _, why := s.admitRuntimeRecovery(ctx, trig, false); why != "" {
		return s.reportRecovery(RuntimeRecoveryAttempt{Outcome: RecoveryRefused, Reason: why, ImageID: trig.imageID})
	}
	op, err := s.opts.Ops.Begin(ops.KindRuntimeRecover, AuditActorRuntimeRecovery, "", map[string]interface{}{"image_id": trig.imageID})
	if err != nil {
		return s.reportRecovery(RuntimeRecoveryAttempt{Outcome: RecoveryRefused, Reason: "lock_held", ImageID: trig.imageID})
	}
	t := s.opts.RuntimeRecovery
	t.setRunning(true)
	defer t.setRunning(false)
	_ = s.opts.Audit.Write(audit.Event{Actor: AuditActorRuntimeRecovery, OpID: op.ID, Kind: ops.KindRuntimeRecover,
		Params: map[string]interface{}{"image_id": trig.imageID}, Outcome: audit.OutcomeStarted})
	att := s.recoverUnderLock(ctx, op.ID, trig)
	s.finishRuntimeRecovery(op.ID, &att)
	return s.reportRecovery(att)
}

// recoverUnderLock admits again under the lock, writes ahead and runs the plan.
func (s *Server) recoverUnderLock(ctx context.Context, opID string, trig runtimeTrigger) RuntimeRecoveryAttempt {
	att := RuntimeRecoveryAttempt{OpID: opID, Outcome: RecoveryFailed, ImageID: trig.imageID}
	adm, why := s.admitRuntimeRecovery(ctx, trig, true)
	if why != "" {
		att.Outcome, att.Reason = RecoveryRefused, why
		return att
	}
	att.RestoreImageID = adm.r.ImageID
	counted, err := adm.attempts.Counted(adm.sourceOpID, adm.x, adm.begun+1, s.recoverySourceInForce)
	if err == nil {
		err = s.opts.RuntimeHealth.WriteRecoverAttempts(counted)
	}
	if err != nil {
		att.Outcome, att.Reason = RecoveryRefused, "attempts_unwritable"
		return att
	}
	rec := runtimeRecoverRecord(opID, adm)
	if err := s.opts.Journal.Write(rec); err != nil {
		att.Outcome, att.Reason = RecoveryRefused, "journal_write_failed"
		return att
	}
	c := &reconcileCase{opID: opID, rec: &rec, in: s.reconcileInputsFor(&rec), actor: AuditActorRuntimeRecovery}
	c.out = ReconcileRecord{OpID: rec.OpID, Kind: reportKind(rec.Kind)}
	s.readReconcileFacts(ctx, &rec, &c.in, true)
	if reconcileNeedsProbe(c.in) {
		c.in.Probe = s.probeReadiness(ctx)
	}
	v := reconcileDecisionV2(c.in)
	c.out.Decision, c.out.Reason = v.Action.String(), v.Reason
	if v.Action != actV2RetagFinishRollback {
		// Nothing moved. The record is kept like any report-only verdict: the
		// operator sees it, and a later start decides it on its facts.
		att.Reason = "decision_" + v.Action.String() + "_" + v.Reason
		s.keepRecord(c, OutcomeRecoveryRequired)
		return att
	}
	out := s.act(ctx, c, v)
	att.Reason = out.Reason
	if out.Outcome == OutcomeConverged {
		att.Outcome, att.Reason = RecoveryRecovered, v.Reason
	}
	return att
}

// runtimeRecoverRecord is the armed record written before anything moves.
func runtimeRecoverRecord(opID string, adm *runtimeAdmission) journal.Record {
	now := time.Now().UTC()
	return journal.Record{
		OpID: opID, Kind: ops.KindRuntimeRecover, Phase: journal.PhaseRestarted, RollbackArmed: true,
		TargetRef: adm.xRef, TargetDigest: adm.xDigest, TargetImageID: adm.x,
		PriorRef: adm.r.Ref, PriorDigest: adm.r.Digest, PriorImageID: adm.r.ImageID,
		Actor: AuditActorRuntimeRecovery, StartedAt: now, UpdatedAt: now,
	}
}

// finishRuntimeRecovery ends the operation and writes its outcome entry.
func (s *Server) finishRuntimeRecovery(opID string, att *RuntimeRecoveryAttempt) {
	state, reason, outcome := ops.StateSucceeded, ops.FailureReason(""), audit.OutcomeSucceeded
	if att.Outcome != RecoveryRecovered {
		state, reason, outcome = ops.StateFailed, ops.ReasonRecoveryRequired, audit.OutcomeFailed
	}
	result := map[string]interface{}{"outcome": att.Outcome, "reason": att.Reason, "image_id": att.ImageID,
		"restore_image_id": att.RestoreImageID}
	_ = s.opts.Ops.Finish(opID, state, reason, result)
	now := time.Now().UTC()
	ev := audit.Event{Actor: AuditActorRuntimeRecovery, OpID: opID, Kind: ops.KindRuntimeRecover, Params: result,
		Outcome: outcome, OutcomeAt: &now}
	if state == ops.StateFailed {
		ev.FailureReason = string(reason)
	}
	_ = s.opts.Audit.Write(ev)
}

// reportRecovery records the attempt for status and logs it when it differs
// from the last one, so a steady refusal is logged once.
func (s *Server) reportRecovery(att RuntimeRecoveryAttempt) RuntimeRecoveryAttempt {
	att.At = time.Now().UTC()
	if s.opts.RuntimeRecovery.setLast(att) || att.OpID != "" {
		log.Printf("culvert-maint: runtime recovery: %s/%s (image %q, op %q)", att.Outcome, att.Reason, att.ImageID, att.OpID)
	}
	return att
}
