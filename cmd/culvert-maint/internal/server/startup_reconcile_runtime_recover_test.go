package server

import (
	"strings"
	"testing"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// seedRuntimeRecover writes the record a runtime recovery writes before it
// moves anything: kind runtime.recover, armed, at restarted, the restore
// target (cfgOld) as the prior and the unhealthy installed image (cfgNew) as
// the target. The world has the agent dead before its retag: both on cfgNew.
func seedRuntimeRecover(t *testing.T, r *reconRig) {
	t.Helper()
	r.seed(t, journal.PhaseRestarted, func(rec *journal.Record) {
		rec.Kind, rec.RollbackArmed, rec.TargetImageID = ops.KindRuntimeRecover, true, "sha256:"+cfgNew
	})
	r.world.running, r.world.pinned = cfgNew, cfgNew
}

// A runtime recovery killed before its retag is finished by the next start
// with the same plan as an interrupted inline rollback, once compatibility is
// proven: retag to the prior, up, gate, verify by id, audit, retire.
func TestRuntimeRecover_StartupFinishesItWhenCompatible(t *testing.T) {
	r := newReconRig(t, true)
	seedRuntimeRecover(t, r)
	r.world.priorEpochLabels, r.world.dataEpoch = true, 1
	got := r.run(t)
	if got.Outcome != OutcomeConverged || got.Decision != actV2RetagFinishRollback.String() {
		t.Fatalf("reconcile = %+v", got)
	}
	if m := strings.Join(r.world.mutating, ","); m != "tag:"+cfgOld+",up" {
		t.Fatalf("docker changes = %s, want the retag to the prior and one up", m)
	}
	if r.world.running != cfgOld || r.world.pinned != cfgOld {
		t.Fatalf("world = run %s tag %s, want the prior", r.world.running, r.world.pinned)
	}
	if r.recordOnDisk(t) != nil {
		t.Fatal("the record was not retired")
	}
	if r.world.epochReads == 0 {
		t.Fatal("vacuous: the data epoch was never read")
	}
}

// Without proof the record is reported and nothing in Docker changes: an
// unlabelled restore target, an unreadable data epoch, or data the target
// cannot read.
func TestRuntimeRecover_StartupRefusesWithoutProof(t *testing.T) {
	cases := map[string]struct {
		labels bool
		max    int
		epoch  int
		reason string
	}{
		"target carries no data-epoch labels": {false, 0, 1, "restore_compatibility_unknown"},
		"data epoch unreadable":               {true, 0, 0, "restore_compatibility_unknown"},
		"data newer than the target reads":    {true, 1, 2, "restore_incompatible"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := newReconRig(t, true)
			seedRuntimeRecover(t, r)
			r.world.priorEpochLabels, r.world.priorEpochMax, r.world.dataEpoch = c.labels, c.max, c.epoch
			got := r.run(t)
			if got.Outcome != OutcomeRecoveryRequired || got.Reason != c.reason {
				t.Fatalf("reconcile = %+v, want recovery_required/%s", got, c.reason)
			}
			if len(r.world.mutating) != 0 {
				t.Fatalf("docker changed: %v", r.world.mutating)
			}
			if r.recordOnDisk(t) == nil {
				t.Fatal("the record was removed")
			}
		})
	}
}

// Killed between its retag and its up: the tag is on the prior, the unhealthy
// image still runs. The next start decides finish_rollback and starts the
// prior only after reading compatibility again.
func TestRuntimeRecover_StartupAfterTheRetag(t *testing.T) {
	r := newReconRig(t, true)
	seedRuntimeRecover(t, r)
	r.world.pinned = cfgOld
	r.world.priorEpochLabels, r.world.dataEpoch = true, 1
	got := r.run(t)
	if got.Outcome != OutcomeConverged || got.Decision != actV2FinishRollback.String() {
		t.Fatalf("reconcile = %+v", got)
	}
	if m := strings.Join(r.world.mutating, ","); m != "up" {
		t.Fatalf("docker changes = %s, want one up", m)
	}
	r2 := newReconRig(t, true)
	seedRuntimeRecover(t, r2)
	r2.world.pinned = cfgOld
	r2.world.priorEpochLabels, r2.world.dataEpoch = true, 2
	if got := r2.run(t); got.Outcome != OutcomeRecoveryRequired || len(r2.world.mutating) != 0 {
		t.Fatalf("incompatible after the retag: %+v, docker %v", got, r2.world.mutating)
	}
}

// The compatibility check is repeated before `up`, the step that starts the
// prior on the data: when the data epoch rises after the retag, the up does
// not run and the record is kept for the next start to report.
func TestRuntimeRecover_CompatibilityRereadBeforeTheUp(t *testing.T) {
	r := newReconRig(t, true)
	seedRuntimeRecover(t, r)
	r.world.priorEpochLabels, r.world.dataEpoch = true, 1
	r.world.onTag = func(w *reconWorld) { w.dataEpoch = 2 }
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired {
		t.Fatalf("reconcile = %+v, want recovery_required", got)
	}
	if m := strings.Join(r.world.mutating, ","); m != "tag:"+cfgOld {
		t.Fatalf("docker changes = %s, want only the retag (no up)", m)
	}
	if r.world.running != cfgNew {
		t.Fatalf("running %s, want the unhealthy image left in place", r.world.running)
	}
	if r.recordOnDisk(t) == nil {
		t.Fatal("the record was removed")
	}
	if r.world.epochReads < 2 {
		t.Fatalf("data epoch read %d times, want a fresh read before the up", r.world.epochReads)
	}
}
