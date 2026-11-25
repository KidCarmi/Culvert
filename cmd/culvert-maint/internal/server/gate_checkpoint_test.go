package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"culvert-maint/internal/journal"
)

// gateWatch records the op's checkpoint as the journal holds it at chosen
// moments of an apply (ADR-0062 slice 3b).
type gateWatch struct {
	mu sync.Mutex
	// atProbe: the checkpoint at the FIRST probe request of the target and of
	// the prior image (keyed by the bare digest running), and the record's
	// identifiers at that moment.
	atProbe     map[string]*journal.Checkpoint
	targetIDAt  map[string]string
	priorIDAt   map[string]string
	probed      map[string]int
	atRbPull    *journal.Checkpoint // at the rollback's `pull` of the prior
	sawRbPull   bool
	listFailure error
}

func newGateWatch() *gateWatch {
	return &gateWatch{
		atProbe: map[string]*journal.Checkpoint{}, targetIDAt: map[string]string{},
		priorIDAt: map[string]string{}, probed: map[string]int{},
	}
}

// record returns the single journal record, or nil (noting why).
func (g *gateWatch) record(rig *applyRig) *journal.Record {
	recs, err := rig.journal.List()
	if err != nil || len(recs) != 1 {
		g.listFailure = errors.Join(err, errors.New("journal does not hold exactly one record"))
		return nil
	}
	return &recs[0]
}

func cloneCheckpoint(c *journal.Checkpoint) *journal.Checkpoint {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

func (g *gateWatch) install(rig *applyRig) {
	rig.onProbe = func(running string) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.probed[running]++
		if g.probed[running] > 1 {
			return
		}
		if rec := g.record(rig); rec != nil {
			g.atProbe[running] = cloneCheckpoint(rec.Checkpoint)
			g.targetIDAt[running], g.priorIDAt[running] = rec.TargetImageID, rec.PriorImageID
		}
	}
	rig.onCommand = func(argv []string) {
		g.mu.Lock()
		defer g.mu.Unlock()
		rec := g.record(rig)
		if rec == nil {
			return
		}
		if argvHas(argv, "pull") && strings.Contains(strings.Join(argv, " "), digOld) && !g.sawRbPull {
			g.sawRbPull, g.atRbPull = true, cloneCheckpoint(rec.Checkpoint)
		}
	}
}

func applyTo(t *testing.T, rig *applyRig) map[string]interface{} {
	t.Helper()
	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	return op
}

// TestGateCheckpoint_TargetIntentDurableBeforeTheProbe: the target's gate is
// recorded as begun, with no result, on the target's digest-verified image id,
// before the first probe request. (Its `passed` is written by verify:
// TestGateCheckpoint_VerifyClosesTheTargetGate.)
func TestGateCheckpoint_TargetIntentDurableBeforeTheProbe(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	g := newGateWatch()
	g.install(rig)

	op := applyTo(t, rig)
	if op["state"] != "succeeded" {
		t.Fatalf("apply state = %v (%v), want succeeded", op["state"], op["failure_reason"])
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.atProbe[digNew]
	switch {
	case c == nil:
		t.Fatalf("no checkpoint when the target was first probed (list: %v)", g.listFailure)
	case c.Step != journal.StepGateTarget || c.Result != "" || c.Attempts != 1 || c.Epoch != 0:
		t.Errorf("checkpoint at the probe = %+v, want gate:target, no result, attempts 1, epoch 0", *c)
	case c.ImageID == "" || c.ImageID != g.targetIDAt[digNew]:
		t.Errorf("checkpoint image_id = %q, want the restart's digest-verified target id %q", c.ImageID, g.targetIDAt[digNew])
	}
}

// TestGateCheckpoint_FailedResultDurableBeforeRollbackPull: a target that fails
// its gate is recorded as failed before the rollback pulls anything, and the
// rollback's own gate is then recorded as begun on the prior image.
func TestGateCheckpoint_FailedResultDurableBeforeRollbackPull(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	g := newGateWatch()
	g.install(rig)

	op := applyTo(t, rig)
	if res := resultMap(t, op); res["rollback_succeeded"] != true {
		t.Fatalf("rollback did not succeed: %+v", res)
	}
	if op["failure_reason"] != "health_failed" {
		t.Errorf("failure_reason = %v, want health_failed (a real gate failure keeps its reason)", op["failure_reason"])
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.sawRbPull {
		t.Fatal("the rollback never pulled the prior image")
	}
	if c := g.atRbPull; c == nil || c.Step != journal.StepGateTarget || c.Result != "failed:unhealthy" {
		t.Errorf("checkpoint at the rollback pull = %+v, want gate:target failed:unhealthy", c)
	}
	c := g.atProbe[digOld]
	switch {
	case c == nil:
		t.Fatalf("no checkpoint when the prior was probed (list: %v)", g.listFailure)
	case c.Step != journal.StepGatePrior || c.Result != "" || c.Attempts != 1:
		t.Errorf("checkpoint at the rollback probe = %+v, want gate:prior begun, attempts 1", *c)
	case c.ImageID == "" || c.ImageID != g.priorIDAt[digOld]:
		t.Errorf("gate:prior image_id = %q, want the record's prior id %q", c.ImageID, g.priorIDAt[digOld])
	}
}

// TestGateCheckpoint_UnwritableTargetIntentFailsTheGateAndRollsBack: a target
// gate that cannot be recorded as begun is a failed gate. The target is never
// probed, the inline rollback runs and is gated, and the op says why under
// its own failure_reason. Every later journal write fails too: the rollback's
// arm and its own gate are best-effort and must not stop it (rule 1).
func TestGateCheckpoint_UnwritableTargetIntentFailsTheGateAndRollsBack(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	g := newGateWatch()
	g.install(rig)
	inner := rig.onCommand
	rig.onCommand = func(argv []string) {
		inner(argv)
		// The forward `up` has started the target: from here the state
		// directory cannot be written.
		if argvHas(argv, "up") && rig.currentRunning() == digNew {
			rig.journal.SetWriteErrorForTest(errors.New("no space left on device"))
		}
	}

	op := applyTo(t, rig)
	if op["failure_reason"] != "checkpoint_unwritable" {
		t.Errorf("failure_reason = %v, want checkpoint_unwritable", op["failure_reason"])
	}
	g.mu.Lock()
	probedTarget, probedPrior := g.probed[digNew], g.probed[digOld]
	g.mu.Unlock()
	if probedTarget != 0 {
		t.Errorf("the target was probed %d times; a gate that could not be recorded must not run", probedTarget)
	}
	if probedPrior == 0 {
		t.Error("the rollback was not gated")
	}
	if got := rig.currentRunning(); got != digOld {
		t.Errorf("the world runs %s, want the prior %s", short(got), short(digOld))
	}
	if res := resultMap(t, op); res["rollback_succeeded"] != true {
		t.Errorf("rollback_succeeded = %v, want true", res["rollback_succeeded"])
	}
}

// TestGateCheckpoint_LostFailedResultDoesNotBlockTheRollback: the target's
// gate fails and its `failed` result cannot be written; the rollback runs
// anyway. Blocking on the write would keep a target that failed its gate
// serving.
func TestGateCheckpoint_LostFailedResultDoesNotBlockTheRollback(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	rig.onProbe = func(running string) {
		if running == digNew {
			rig.journal.SetWriteErrorForTest(errors.New("no space left on device"))
		}
	}

	op := applyTo(t, rig)
	if got := rig.currentRunning(); got != digOld {
		t.Errorf("the world runs %s, want the prior %s", short(got), short(digOld))
	}
	if res := resultMap(t, op); res["rollback_succeeded"] != true {
		t.Errorf("rollback_succeeded = %v, want true", res["rollback_succeeded"])
	}
	if op["failure_reason"] != "health_failed" {
		t.Errorf("failure_reason = %v, want health_failed (the gate ran and failed)", op["failure_reason"])
	}
}

// TestGateCheckpoint_StandaloneRollbackWritesNone: the standalone image
// rollback's record carries no checkpoint. Its barrier and checkpoint are
// decision changes and land with slice 7 (ADR-0062, slice 3b amendment).
func TestGateCheckpoint_StandaloneRollbackWritesNone(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	var mu sync.Mutex
	var seen []*journal.Checkpoint
	probes := 0
	rig.onProbe = func(string) {
		recs, err := rig.journal.List()
		mu.Lock()
		defer mu.Unlock()
		probes++
		if err == nil && len(recs) == 1 {
			seen = append(seen, recs[0].Checkpoint)
		}
	}

	op, _ := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": repo + "@sha256:" + digOld})
	if op["state"] != "succeeded" {
		t.Fatalf("rollback state = %v (%v), want succeeded", op["state"], op["failure_reason"])
	}
	mu.Lock()
	defer mu.Unlock()
	if probes == 0 || len(seen) == 0 {
		t.Fatalf("the rollback's gate was not observed (probes=%d)", probes)
	}
	for _, c := range seen {
		if c != nil {
			t.Errorf("standalone rollback record carries a checkpoint %+v", *c)
		}
	}
}

// TestGateCheckpoint_VerifyClosesTheTargetGate: verify is the second half of the
// target's gate. A digest that verifies closes the open gate:target as passed
// (next to PhaseVerified); one that does not closes it as failed before the
// stage returns, i.e. before any rollback stage runs.
func TestGateCheckpoint_VerifyClosesTheTargetGate(t *testing.T) {
	for _, tc := range []struct {
		name, runningID, repoDigest, want string
		wantPhase                         journal.Phase
	}{
		{"verified", cfgNew, digNew, journal.CheckpointPassed, journal.PhaseVerified},
		{"digest mismatch", cfgOld, digOld, "failed:digest_mismatch", journal.PhaseAdmitted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, jnl := newRestartBarrierServer(t, tc.runningID, tc.repoDigest)
			seedAdmitted(t, jnl, time.Now().UTC().Add(-time.Minute))
			rec, _, err := jnl.Read(testOpULID)
			if err != nil {
				t.Fatal(err)
			}
			rec.BeginCheckpoint(journal.StepGateTarget, "sha256:"+cfgNew, time.Now().UTC())
			if err := jnl.Write(*rec); err != nil {
				t.Fatal(err)
			}
			acc := &upgradeApplyAccumulator{opID: testOpULID, actor: "cp", pinnedRef: repo + "@sha256:" + digNew, pinnedDigest: "sha256:" + digNew}
			_, _, verr := srv.verifyRunningImage(acc)(context.Background())
			if (verr == nil) != (tc.want == journal.CheckpointPassed) {
				t.Fatalf("verify err = %v", verr)
			}
			got, _, err := jnl.Read(testOpULID)
			if err != nil {
				t.Fatal(err)
			}
			if c := got.Checkpoint; c == nil || c.Step != journal.StepGateTarget || c.Result != tc.want || c.ResultAt == nil {
				t.Errorf("checkpoint after verify = %+v, want gate:target %q", c, tc.want)
			}
			if got.Phase != tc.wantPhase {
				t.Errorf("phase = %q, want %q", got.Phase, tc.wantPhase)
			}
		})
	}
}

// TestGateCheckpoint_ReportNeverEchoesForgedValues: status reports the
// checkpoint, but every field comes from a file. Steps and results this build
// does not write are reported as unrecognised, a malformed image id and a
// negative count are dropped.
func TestGateCheckpoint_ReportNeverEchoesForgedValues(t *testing.T) {
	if reportGateCheckpoint(nil) != nil {
		t.Error("a record without a checkpoint reports one")
	}
	at := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	ok := reportGateCheckpoint(&journal.Checkpoint{Step: journal.StepGateTarget, IntentAt: at, Attempts: 2,
		Result: "failed:unhealthy", ResultAt: &at, ImageID: "sha256:" + cfgNew})
	if ok.Step != journal.StepGateTarget || ok.Result != "failed:unhealthy" || ok.Attempts != 2 || ok.ImageID != "sha256:"+cfgNew || !ok.BeganAt.Equal(at) {
		t.Errorf("valid checkpoint reported as %+v", *ok)
	}
	for _, c := range []journal.Checkpoint{
		{Step: "gate:<script>", Result: journal.CheckpointPassed},
		{Step: journal.StepGatePrior, Result: "failed:Unhealthy; rm -rf /"},
		{Step: journal.StepGatePrior, Result: "adopted"},
		{Step: journal.StepGatePrior, Result: "failed:"},
	} {
		r := reportGateCheckpoint(&c)
		if r.Step != checkpointUnrecognised && r.Result != checkpointUnrecognised {
			t.Errorf("forged %+v reported as step=%q result=%q", c, r.Step, r.Result)
		}
	}
	if r := reportGateCheckpoint(&journal.Checkpoint{Step: journal.StepGateTarget, Attempts: -3, ImageID: "not-an-id"}); r.Attempts != 0 || r.ImageID != "" {
		t.Errorf("forged count/id reported: attempts=%d image_id=%q", r.Attempts, r.ImageID)
	}
}
