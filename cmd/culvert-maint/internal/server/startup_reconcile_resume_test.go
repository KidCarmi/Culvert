package server

// ADR-0062 slice 7: the converge reconcile resumes an interrupted health gate
// of an upgrade's target. These tests drive the real reconcile (journal, audit
// log, runner argv, health probe) over the reconWorld Docker model.

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// seedUngatedTT: the proxy runs the target and the fixed tag is on it; the
// record is at restarted with the target id the restart digest-verified,
// interrupted_seen as THIS start counted it, and the given checkpoint.
func seedUngatedTT(t *testing.T, r *reconRig, seen int, ck *journal.Checkpoint) {
	t.Helper()
	r.setWorld(cfgNew, cfgNew)
	r.seed(t, journal.PhaseRestarted, func(rec *journal.Record) {
		rec.TargetImageID = "sha256:" + cfgNew
		rec.InterruptedSeen = seen
		rec.Checkpoint = ck
	})
}

// seedRestarting turns the seeded record into one whose restart was never
// recorded: phase restarting, no TargetImageID.
func seedRestarting(t *testing.T, r *reconRig) {
	t.Helper()
	rec := r.recordOnDisk(t)
	rec.Phase, rec.TargetImageID = journal.PhaseRestarting, ""
	if err := r.jnl.Write(*rec); err != nil {
		t.Fatal(err)
	}
}

func openTargetGate(attempts, epoch int) *journal.Checkpoint {
	return &journal.Checkpoint{Step: journal.StepGateTarget, IntentAt: time.Now().UTC().Add(-time.Minute),
		Attempts: attempts, Epoch: epoch, ImageID: "sha256:" + cfgNew}
}

func (r *reconRig) enableResume() {
	r.opts.Cfg.ReconcileOnStartup, r.opts.Cfg.ResumeInterruptedGate = "converge", true
}

// auditEntries counts this record's entries of kind <upgrade>+suffix by outcome.
func auditEntries(t *testing.T, r *reconRig, suffix string) map[audit.Outcome]int {
	t.Helper()
	f, err := os.Open(r.al.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	kind := reportKind(ops.KindUpgradeApply) + suffix
	n := map[audit.Outcome]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev audit.Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.OpID == testOpULID && ev.Kind == kind {
			n[ev.Outcome]++
		}
	}
	return n
}

// TestResume_OffLeavesTheTargetReported: the switch is off by default. An
// interrupted gate is reported exactly as before: no gate, no Docker change,
// the record kept.
func TestResume_OffLeavesTheTargetReported(t *testing.T) {
	r := newReconRig(t, true)
	seedUngatedTT(t, r, 1, openTargetGate(1, 0))
	got := r.run(t)
	if got.Decision != "recovery_required" || got.Reason != "target_live_ungated" {
		t.Fatalf("result = %+v, want recovery_required/target_live_ungated", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("mutating calls = %v, want none", c)
	}
	if rec := r.recordOnDisk(t); rec == nil || rec.Checkpoint.Attempts != 1 {
		t.Errorf("record = %+v, want it kept with its checkpoint untouched", rec)
	}
}

// TestResume_PassedGateAdoptsAndRetires: an interrupted gate (open
// checkpoint, only this start has seen it) and a gate that never began (no
// checkpoint, interrupted_seen 1) are both resumed: nothing in Docker changes,
// one succeeded `:resumed` entry, no `:reconciled` entry, the record retired.
func TestResume_PassedGateAdoptsAndRetires(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		ck           *journal.Checkpoint
		restarting   bool
	}{
		{"interrupted", "target_gate_interrupted", openTargetGate(1, 0), false},
		{"never began", "target_gate_not_begun", nil, false},
		// killed after `compose up` returned, before the restart was recorded:
		// no recorded id, the identity is read fresh (resumeIdentity)
		{"never began, restart unrecorded", "target_gate_not_begun", nil, true},
		{"interrupted, restart unrecorded", "target_gate_interrupted", openTargetGate(1, 0), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReconRig(t, true)
			r.enableResume()
			seedUngatedTT(t, r, 1, tc.ck)
			if tc.restarting {
				seedRestarting(t, r)
			}
			got := r.run(t)
			if got.Decision != "resume_gate" || got.Reason != tc.reason || got.Outcome != OutcomeConverged || !got.DockerReconciled {
				t.Fatalf("result = %+v, want resume_gate/%s converged", got, tc.reason)
			}
			if c := r.world.calls(); len(c) != 0 {
				t.Errorf("mutating calls = %v, want none: a passed resumed gate changes nothing", c)
			}
			if run, tag := r.worldState(); run != cfgNew || tag != cfgNew {
				t.Errorf("Docker after: running %.8s tag %.8s, want the target", run, tag)
			}
			if r.recordOnDisk(t) != nil {
				t.Error("record not retired")
			}
			if n := auditEntries(t, r, ":resumed"); n[audit.OutcomeSucceeded] != 1 || n[audit.OutcomeFailed] != 0 {
				t.Errorf(":resumed entries = %v, want exactly one succeeded", n)
			}
			if n := auditEntries(t, r, ":reconciled"); len(n) != 0 {
				t.Errorf(":reconciled entries = %v, want none", n)
			}
		})
	}
}

// TestResume_RefusedWithoutFreshEvidence: each condition the resume needs,
// broken alone, leaves the record reported as before and Docker unchanged.
func TestResume_RefusedWithoutFreshEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		seen int
		ck   *journal.Checkpoint
		mod  func(*journal.Record)
	}{
		{"a start counted since the gate began", 2, openTargetGate(1, 0), nil},
		{"the gate-run cap reached", 1, openTargetGate(2, 0), nil},
		{"the checkpoint names another image", 1, &journal.Checkpoint{Step: journal.StepGateTarget, Attempts: 1, Epoch: 0, ImageID: "sha256:" + imgOther}, nil},
		{"the checkpoint already has a result", 1, &journal.Checkpoint{Step: journal.StepGateTarget, Attempts: 1, Epoch: 0, Result: "failed:unhealthy", ImageID: "sha256:" + cfgNew}, nil},
		{"no checkpoint, a second start", 2, nil, nil},
		{"at restarted, the restart's id was never recorded", 1, nil, func(rec *journal.Record) { rec.TargetImageID = "" }},
		{"at restarted, the recorded id is another image", 1, nil, func(rec *journal.Record) { rec.TargetImageID = "sha256:" + imgOther }},
		{"at restarting, an id is already recorded", 1, nil, func(rec *journal.Record) { rec.Phase = journal.PhaseRestarting }},
		{"at restarting, a second start", 2, nil, func(rec *journal.Record) { rec.Phase, rec.TargetImageID = journal.PhaseRestarting, "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReconRig(t, true)
			r.enableResume()
			seedUngatedTT(t, r, tc.seen, tc.ck)
			if tc.mod != nil {
				rec := r.recordOnDisk(t)
				tc.mod(rec)
				if err := r.jnl.Write(*rec); err != nil {
					t.Fatal(err)
				}
			}
			got := r.run(t)
			if got.Decision == "resume_gate" || got.Outcome == OutcomeConverged {
				t.Fatalf("result = %+v, want it reported, not resumed", got)
			}
			if c := r.world.calls(); len(c) != 0 {
				t.Errorf("mutating calls = %v, want none", c)
			}
			if r.recordOnDisk(t) == nil {
				t.Error("record retired")
			}
			if n := auditEntries(t, r, ":resumed"); len(n) != 0 {
				t.Errorf(":resumed entries = %v, want none", n)
			}
		})
	}
}

// TestResume_RefusedWhenTheImageLacksThePinnedDigest: container, tag and the
// target reference agree on one id, but that image does not carry the pinned
// digest. Its identity is not established, at restarted or restarting, so no
// gate runs and nothing changes.
func TestResume_RefusedWhenTheImageLacksThePinnedDigest(t *testing.T) {
	for _, restarting := range []bool{false, true} {
		r := newReconRig(t, true)
		r.enableResume()
		seedUngatedTT(t, r, 1, nil)
		if restarting {
			seedRestarting(t, r)
		}
		r.world.mu.Lock()
		r.world.wrongDigest = cfgNew
		r.world.mu.Unlock()
		got := r.run(t)
		if got.Decision != "recovery_required" || got.Reason != "target_live_ungated" {
			t.Fatalf("restarting=%v: result = %+v, want recovery_required/target_live_ungated", restarting, got)
		}
		if c := r.world.calls(); len(c) != 0 {
			t.Errorf("restarting=%v: mutating calls = %v, want none", restarting, c)
		}
		if rec := r.recordOnDisk(t); rec == nil || rec.Checkpoint != nil {
			t.Errorf("restarting=%v: record = %+v, want it kept with no checkpoint (no gate begun)", restarting, rec)
		}
	}
}

// TestResume_FailedGateFinishesTheRollbackInTheSameStart: the resumed gate
// fails. The result and rollback_armed are durable, a failed `:resumed` entry
// is written, and in this same start the record is decided again onto #2051's
// T/T-armed finish: tag to the PriorRef, `up`, the prior's own gate, verify,
// retired with one succeeded `:reconciled` entry.
func TestResume_FailedGateFinishesTheRollbackInTheSameStart(t *testing.T) {
	r := newReconRig(t, false) // the target does not answer ready
	r.enableResume()
	seedUngatedTT(t, r, 1, openTargetGate(1, 0))
	r.world.mu.Lock()
	r.world.onUp = func() { r.ready.Store(true) } // the prior answers ready once started
	r.world.mu.Unlock()
	got := r.run(t)
	if got.Decision != "finish_rollback_retag" || got.Outcome != OutcomeConverged {
		t.Fatalf("result = %+v, want the armed finish converged in the same start", got)
	}
	if c := r.world.calls(); strings.Join(c, ",") != "tag:"+cfgOld+",up" {
		t.Errorf("mutating calls = %v, want exactly [tag:prior up], never a replay of the target's", c)
	}
	if n := auditEntries(t, r, ":resumed"); n[audit.OutcomeFailed] != 1 || n[audit.OutcomeSucceeded] != 0 {
		t.Errorf(":resumed entries = %v, want exactly one failed", n)
	}
	assertConvergedOnPrior(t, r)
}

// TestResume_UnwritableCheckpointRunsNoGate: the checkpoint is written ahead
// fail-closed. If it cannot be, no gate runs (an unhealthy target would
// otherwise reach resume_failed_unarmed) and nothing changes.
func TestResume_UnwritableCheckpointRunsNoGate(t *testing.T) {
	r := newReconRig(t, false)
	r.enableResume()
	seedUngatedTT(t, r, 1, nil)
	r.jnl.SetWriteErrorForTest(errors.New("no space left on device"))
	got := r.run(t)
	r.jnl.SetWriteErrorForTest(nil)
	if got.Decision != "resume_gate" || got.Reason != "resume_checkpoint_unwritable" || got.Outcome != OutcomeRecoveryRequired {
		t.Fatalf("result = %+v, want resume_gate kept with resume_checkpoint_unwritable", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("mutating calls = %v, want none", c)
	}
	if rec := r.recordOnDisk(t); rec == nil || rec.Checkpoint != nil {
		t.Errorf("record = %+v, want it kept without a checkpoint", rec)
	}
}

// TestResume_AuditedButNotRemovedIsOnlyRemoved: a previous start passed the
// resumed gate, wrote the succeeded `:resumed` entry and was killed before
// removing the record. This start only removes it: no second entry, no
// attempt spent, even at the cap.
func TestResume_AuditedButNotRemovedIsOnlyRemoved(t *testing.T) {
	r := newReconRig(t, true)
	r.enableResume()
	seedUngatedTT(t, r, 2, openTargetGate(2, 1))
	now := time.Now().UTC()
	if err := r.al.Write(audit.Event{Actor: AuditActorReconcile, OpID: testOpULID, Kind: reportKind(ops.KindUpgradeApply) + ":resumed",
		Outcome: audit.OutcomeSucceeded, OutcomeAt: &now}); err != nil {
		t.Fatal(err)
	}
	got := r.run(t)
	if got.Decision != "resume_gate" || got.Reason != "resumed_not_retired" || got.Outcome != OutcomeConverged {
		t.Fatalf("result = %+v, want resume_gate/resumed_not_retired converged", got)
	}
	if r.recordOnDisk(t) != nil {
		t.Error("record not removed")
	}
	if n := auditEntries(t, r, ":resumed"); n[audit.OutcomeSucceeded] != 1 {
		t.Errorf(":resumed entries = %v, want still exactly one", n)
	}
}

// TestResume_CheckpointWrittenAheadForTheNextStart: the resumed gate's
// checkpoint is durable before the gate runs, with attempts raised and the
// epoch this start's interrupted_seen, so a death inside the resumed gate is
// itself resumable once more by the next start, and not after that.
func TestResume_CheckpointWrittenAheadForTheNextStart(t *testing.T) {
	r := newReconRig(t, true)
	r.enableResume()
	seedUngatedTT(t, r, 1, nil)
	var atProbe *journal.Checkpoint
	r.world.mu.Lock()
	r.world.onPS = func(int) {
		if rec, found, err := r.jnl.Read(testOpULID); err == nil && found && rec.Checkpoint != nil && atProbe == nil {
			cp := *rec.Checkpoint
			atProbe = &cp
		}
	}
	r.world.mu.Unlock()
	r.run(t)
	if atProbe == nil {
		t.Fatal("no checkpoint was on disk during the resumed gate")
	}
	if atProbe.Step != journal.StepGateTarget || atProbe.Attempts != 1 || atProbe.Epoch != 1 || atProbe.Result != "" ||
		atProbe.ImageID != "sha256:"+cfgNew {
		t.Errorf("checkpoint during the resumed gate = %+v, want gate:target attempts 1 epoch 1 open on the target", *atProbe)
	}
	// What the next start would decide on that record: resumable once more.
	in := reconcileInputsV2{Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarted, RefValid: true, TargetRefPresent: true,
		PriorRefPresent: true, TargetDigest: digNew, TargetImageID: "sha256:" + cfgNew, PriorImageID: "sha256:" + cfgOld,
		MaxAttempts: maxReconcileAttempts, DockerReadable: true, RunningImageID: "sha256:" + cfgNew, ContainerRunning: true,
		TagImageID: "sha256:" + cfgNew, TargetLocalID: "sha256:" + cfgNew, PriorLocalID: "sha256:" + cfgOld,
		RunningDigests: []string{"repo@sha256:" + digNew}, ResumeEnabled: true, Seen: 2, Ck: ckFactsOf(atProbe)}
	if v := reconcileDecisionV2(in); v != verdictResumeInterrupted {
		t.Errorf("next start on that record decides %v, want %v", v, verdictResumeInterrupted)
	}
	in.Seen, in.Ck.Attempts, in.Ck.Epoch = 3, 2, 2
	if v := reconcileDecisionV2(in); v.Action == actV2ResumeGate {
		t.Errorf("after the second resumed gate run the record is still resumable: %v", v)
	}
}

// TestResume_VerifyMismatchRollsBack: the resumed gate passes, but by the
// verify's own read the running image no longer carries the pinned digest.
// That is a failed resume: armed durably and finished onto the prior in the
// same start. (Reads after the checkpoint: the re-read before the gate, the
// re-read before the verify, then the verify's read.)
func TestResume_VerifyMismatchRollsBack(t *testing.T) {
	r := newReconRig(t, true)
	r.enableResume()
	seedUngatedTT(t, r, 1, nil)
	after := 0
	r.world.mu.Lock()
	r.world.onPS = func(int) {
		if rec, found, err := r.jnl.Read(testOpULID); err == nil && found && rec.Checkpoint != nil {
			after++
			if after == 3 {
				r.world.mu.Lock()
				r.world.wrongDigest = cfgNew
				r.world.mu.Unlock()
			}
		}
	}
	r.world.mu.Unlock()
	got := r.run(t)
	if got.Decision != "finish_rollback_retag" || got.Outcome != OutcomeConverged {
		t.Fatalf("result = %+v, want the armed finish converged after the failed verify", got)
	}
	if n := auditEntries(t, r, ":resumed"); n[audit.OutcomeFailed] != 1 || n[audit.OutcomeSucceeded] != 0 {
		t.Errorf(":resumed entries = %v, want exactly one failed", n)
	}
	assertConvergedOnPrior(t, r)
}

// TestResume_UnwritableArmAfterAFailedGateIsReported: the checkpoint was
// written ahead, the resumed gate fails, and the result and rollback_armed
// cannot be written. Nothing is rolled back on an arm that is not durable:
// the record is reported (resume_failed_unarmed) with its open checkpoint and
// the attempt it spent, and Docker is unchanged.
func TestResume_UnwritableArmAfterAFailedGateIsReported(t *testing.T) {
	r := newReconRig(t, false) // the target does not answer ready
	r.enableResume()
	seedUngatedTT(t, r, 1, nil)
	r.world.mu.Lock()
	r.world.onPS = func(int) {
		// The re-read after the checkpoint write-ahead: from here the state
		// directory cannot be written.
		if rec, found, err := r.jnl.Read(testOpULID); err == nil && found && rec.Checkpoint != nil {
			r.jnl.SetWriteErrorForTest(errors.New("no space left on device"))
		}
	}
	r.world.mu.Unlock()
	got := r.run(t)
	r.jnl.SetWriteErrorForTest(nil)
	if got.Reason != "resume_failed_unarmed" || got.Outcome != OutcomeRecoveryRequired {
		t.Fatalf("result = %+v, want recovery_required/resume_failed_unarmed", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("mutating calls = %v, want none: no rollback on an arm that is not durable", c)
	}
	rec := r.recordOnDisk(t)
	if rec == nil || rec.RollbackArmed || rec.Checkpoint == nil || rec.Checkpoint.Attempts != 1 || rec.Checkpoint.Result != "" {
		t.Errorf("record = %+v, want it kept unarmed with the open checkpoint and one attempt spent", rec)
	}
}

// TestResume_AfterADeathInsideItsOwnUp: the agent died inside the upgrade's
// own `compose up`, which Docker had carried through: the target runs under
// the tag, the record is at restarting (owner decision of 2026-11-26). The
// gate is resumed only once `compose ps -a` shows Compose finished that
// recreate (no never-started proxy container); a container left behind, or a
// listing that cannot be read, leaves the record reported and Docker
// unchanged.
func TestResume_AfterADeathInsideItsOwnUp(t *testing.T) {
	for _, tc := range []struct {
		name               string
		leftover, psAllErr bool
		resumed            bool
	}{
		{"compose finished", false, false, true},
		{"a never-started container is left", true, false, false},
		{"the listing cannot be read", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReconRig(t, true)
			r.enableResume()
			seedUngatedTT(t, r, 1, nil)
			seedRestarting(t, r)
			r.srv.SetCommandAttribution(map[string]string{testOpULID: journal.MutationComposeUp})
			r.world.mu.Lock()
			r.world.leftover, r.world.psAllFail = tc.leftover, tc.psAllErr
			r.world.mu.Unlock()
			got := r.run(t)
			if c := r.world.calls(); len(c) != 0 {
				t.Errorf("mutating calls = %v, want none", c)
			}
			if r.world.psAllCount == 0 {
				t.Error("`compose ps -a` was never read")
			}
			if !tc.resumed {
				if got.Decision != "recovery_required" || got.Reason != "target_live_ungated" {
					t.Fatalf("result = %+v, want recovery_required/target_live_ungated", got)
				}
				if rec := r.recordOnDisk(t); rec == nil || rec.Checkpoint != nil {
					t.Errorf("record = %+v, want it kept with no gate begun", rec)
				}
				return
			}
			if got.Decision != "resume_gate" || got.Reason != "target_gate_not_begun" || got.Outcome != OutcomeConverged {
				t.Fatalf("result = %+v, want resume_gate/target_gate_not_begun converged", got)
			}
			if r.recordOnDisk(t) != nil {
				t.Error("record not retired")
			}
			if n := auditEntries(t, r, ":resumed"); n[audit.OutcomeSucceeded] != 1 {
				t.Errorf(":resumed entries = %v, want exactly one succeeded", n)
			}
		})
	}
}

// TestResume_OffDoesNotReadTheComposeListingWithTheStackUp: with the switch
// off, a death inside `compose up` with the proxy running reads nothing more
// than before (an install whose sudoers file predates the read is unaffected).
func TestResume_OffDoesNotReadTheComposeListingWithTheStackUp(t *testing.T) {
	r := newReconRig(t, true)
	seedUngatedTT(t, r, 1, nil)
	seedRestarting(t, r)
	r.opts.Cfg.ReconcileOnStartup = "converge"
	r.srv.SetCommandAttribution(map[string]string{testOpULID: journal.MutationComposeUp})
	got := r.run(t)
	if got.Reason != "target_live_ungated" {
		t.Fatalf("result = %+v, want target_live_ungated", got)
	}
	if r.world.psAllCount != 0 {
		t.Errorf("`compose ps -a` read %d times with resume off, want 0", r.world.psAllCount)
	}
}
