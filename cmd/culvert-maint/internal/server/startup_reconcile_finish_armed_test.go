package server

// Owner Decision 1 (2026-11-23), AGT-900: the converge reconcile finishes an
// already-armed inline rollback whose own `docker tag` never ran ("T/T armed":
// container and tag still on the target that failed its gate). These tests
// drive the real reconcile (journal, audit log, runner argv, health probe) over
// the reconWorld Docker model, including restarts of the agent between and
// after the steps.

import (
	"strings"
	"testing"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// seedArmedTT puts Docker in the T/T-armed state: the proxy runs the target
// and the fixed tag is on it, and the record proves the rollback was armed.
func seedArmedTT(t *testing.T, r *reconRig, phase journal.Phase) {
	t.Helper()
	r.world.running, r.world.pinned = cfgNew, cfgNew
	r.seed(t, phase, func(rec *journal.Record) {
		rec.RollbackArmed = true
		rec.TargetImageID = "sha256:" + cfgNew
	})
}

func (r *reconRig) worldState() (running, pinned string) {
	r.world.mu.Lock()
	defer r.world.mu.Unlock()
	return r.world.running, r.world.pinned
}

func (r *reconRig) setWorld(running, pinned string) {
	r.world.mu.Lock()
	r.world.running, r.world.pinned = running, pinned
	r.world.mu.Unlock()
}

func (r *reconRig) clearCalls() {
	r.world.mu.Lock()
	r.world.mutating, r.world.tagRefs = nil, nil
	r.world.mu.Unlock()
}

// TestStartupReconcile_FinishArmedRollbackTagNeverMoved: T/T armed, at both
// danger phases an armed record can have. Exactly `docker tag <PriorRef>`, then
// `compose up`, then the gate and the verify; audited once and retired. The
// interrupted upgrade itself is never touched (its op is not in this process).
func TestStartupReconcile_FinishArmedRollbackTagNeverMoved(t *testing.T) {
	for _, phase := range []journal.Phase{journal.PhaseRestarted, journal.PhaseRestarting} {
		t.Run(string(phase), func(t *testing.T) {
			r := newReconRig(t, true)
			seedArmedTT(t, r, phase)
			got := r.run(t)
			if got.Decision != "finish_rollback_retag" || got.Reason != "rollback_armed_tag_not_moved" ||
				got.Outcome != OutcomeConverged || !got.DockerReconciled {
				t.Fatalf("result = %+v, want finish_rollback_retag converged", got)
			}
			if c := r.world.calls(); strings.Join(c, ",") != "tag:"+cfgOld+",up" {
				t.Errorf("mutating calls = %v, want exactly [tag:prior up]", c)
			}
			if refs := r.world.tagRefs; len(refs) != 1 || refs[0] != repo+"@sha256:"+digOld {
				t.Errorf("tag references = %v, want only the record's PriorRef", refs)
			}
			if strings.Join(got.Actions, ",") != "tag:prior,up" || got.RunningImage != RunningIsPrior || got.PinnedTag != RunningIsPrior {
				t.Errorf("report = %+v", got)
			}
			assertConvergedOnPrior(t, r)
		})
	}
}

// assertConvergedOnPrior: Docker on the prior image, the record retired with
// exactly one succeeded ":reconciled" entry, the reconcile op succeeded.
func assertConvergedOnPrior(t *testing.T, r *reconRig) {
	t.Helper()
	if run, tag := r.worldState(); run != cfgOld || tag != cfgOld {
		t.Errorf("Docker after: running %.8s tag %.8s, want the prior", run, tag)
	}
	if r.recordOnDisk(t) != nil {
		t.Error("record not retired after verified convergence")
	}
	if n := reconciledEntries(t, r); n[audit.OutcomeSucceeded] != 1 || n[audit.OutcomeFailed] != 0 {
		t.Errorf(":reconciled entries = %v, want exactly one succeeded", n)
	}
	if op := r.mgr.Get(r.rt.Snapshot().OpID); op == nil || op.Kind != ops.KindReconcileStartup || op.State != ops.StateSucceeded {
		t.Errorf("reconcile op = %+v, want a succeeded reconcile.startup", op)
	}
}

// TestStartupReconcile_ArmedTTRefusals: every refusal of the T/T finish is
// report-only: recovery_required, no Docker change, the record kept.
func TestStartupReconcile_ArmedTTRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mod    func(*journal.Record)
		reason string
	}{
		{"unarmed (older agent, or the arm write failed)", func(rec *journal.Record) { rec.RollbackArmed = false }, "target_live_ungated"},
		{"prior ref not local", func(rec *journal.Record) {
			rec.PriorRef, rec.PriorDigest = repo+"@sha256:"+strings.Repeat("e", 64), strings.Repeat("e", 64)
		}, "prior_not_restorable"},
		{"prior id differs from the image the PriorRef names", func(rec *journal.Record) { rec.PriorImageID = "sha256:" + strings.Repeat("d", 64) }, "prior_not_restorable"},
		{"refs failed validation", func(rec *journal.Record) { rec.PriorRef = "evil.example/proxy@sha256:" + digOld }, "invalid_record_ref"},
		{"attempt cap reached", func(rec *journal.Record) { rec.ReconcileAttempts = maxReconcileAttempts }, "reconcile_exhausted"},
		{"armed at verified contradicts the journal", func(rec *journal.Record) { rec.Phase = journal.PhaseVerified }, "rollback_armed_at_verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReconRig(t, true)
			seedArmedTT(t, r, journal.PhaseRestarted)
			rec := r.recordOnDisk(t)
			tc.mod(rec)
			if err := r.jnl.Write(*rec); err != nil {
				t.Fatal(err)
			}
			got := r.run(t)
			if got.Outcome != OutcomeRecoveryRequired || got.Reason != tc.reason {
				t.Errorf("result = %+v, want recovery_required/%s", got, tc.reason)
			}
			if c := r.world.calls(); len(c) != 0 {
				t.Errorf("a refused record changed Docker: %v", c)
			}
			if r.recordOnDisk(t) == nil {
				t.Error("a refused record was retired")
			}
		})
	}
}

// TestStartupReconcile_ArmedTTDockerChangedBeforeEachMutation: Docker is
// re-read immediately before EACH mutation. A change this reconcile's own
// steps do not explain stops it there, with nothing further changed.
func TestStartupReconcile_ArmedTTDockerChangedBeforeEachMutation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		atPS         int // 3: the re-read before the retag; 4: the one before `up`
		running, tag string
		reason       string
		calls        string
	}{
		{"before the retag: an operator restarted the prior", 3, cfgOld, cfgNew, "docker_changed_before_action", ""},
		{"before the retag: an operator moved the tag", 3, cfgNew, cfgOld, "docker_changed_before_action", ""},
		{"before `up`: the tag was moved back to the target", 4, cfgNew, cfgNew, "docker_changed_before_up", "tag:" + cfgOld},
		{"before `up`: the container changed under the retag", 4, cfgOld, cfgOld, "docker_changed_before_up", "tag:" + cfgOld},
		{"before `up`: the container was removed", 4, "", cfgOld, "docker_changed_before_up", "tag:" + cfgOld},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReconRig(t, true)
			seedArmedTT(t, r, journal.PhaseRestarted)
			r.world.onPS = func(n int) {
				if n == tc.atPS {
					r.setWorld(tc.running, tc.tag)
				}
			}
			got := r.run(t)
			if got.Outcome != OutcomeRecoveryRequired || got.Reason != tc.reason {
				t.Errorf("result = %+v, want recovery_required/%s", got, tc.reason)
			}
			if c := strings.Join(r.world.calls(), ","); c != tc.calls {
				t.Errorf("mutating calls = [%s], want [%s]", c, tc.calls)
			}
			rec := r.recordOnDisk(t)
			if rec == nil || rec.ReconcileAttempts != 1 || rec.ReconcileOutcome != OutcomeRecoveryRequired {
				t.Errorf("record = %+v, want kept, attempt 1 counted, recovery_required", rec)
			}
			// Something was changed before the second recheck: that is audited as a
			// failed reconcile. Nothing was changed before the first: no entry.
			wantFailed := 0
			if tc.atPS == 4 {
				wantFailed = 1
			}
			if n := reconciledEntries(t, r); n[audit.OutcomeFailed] != wantFailed || n[audit.OutcomeSucceeded] != 0 {
				t.Errorf(":reconciled entries = %v, want %d failed", n, wantFailed)
			}
		})
	}
}

// TestStartupReconcile_ArmedTTGateFailsThenRestarts: the prior image fails the
// fresh gate after the reconcile's `up`. Recovery required, record kept, no
// second `up`. The next start finds container and tag on the prior with an
// armed record: it changes nothing and keeps reporting until the prior answers
// ready, and only then retires the record (audited once).
func TestStartupReconcile_ArmedTTGateFailsThenRestarts(t *testing.T) {
	r := newReconRig(t, false)
	seedArmedTT(t, r, journal.PhaseRestarted)
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "prior_not_ready" {
		t.Fatalf("result = %+v, want recovery_required/prior_not_ready", got)
	}
	if c := strings.Join(r.world.calls(), ","); c != "tag:"+cfgOld+",up" {
		t.Errorf("mutating calls = [%s], want exactly one retag and one up", c)
	}
	if rec := r.recordOnDisk(t); rec == nil || rec.ReconcileAttempts != 1 {
		t.Fatalf("record = %+v, want kept with attempt 1", rec)
	}

	r.restart(t) // still unhealthy
	r.clearCalls()
	got = r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "armed_rollback_prior_not_ready" {
		t.Errorf("second start = %+v, want recovery_required/armed_rollback_prior_not_ready", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("second start changed Docker: %v", c)
	}
	if r.recordOnDisk(t) == nil {
		t.Fatal("an ungated prior was retired")
	}

	r.restart(t)
	r.ready.Store(true)
	r.clearCalls()
	got = r.run(t)
	if got.Decision != "noop" || got.Reason != "armed_rollback_prior_ready" || got.Outcome != OutcomeConverged {
		t.Errorf("third start = %+v, want noop/armed_rollback_prior_ready converged", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("third start changed Docker: %v", c)
	}
	if r.recordOnDisk(t) != nil {
		t.Error("record not retired once the prior answered ready")
	}
	if n := reconciledEntries(t, r); n[audit.OutcomeSucceeded] != 1 {
		t.Errorf(":reconciled entries = %v, want exactly one succeeded", n)
	}
}

// TestStartupReconcile_ArmedTTVerifyMismatchIsCapped: `compose up` exits 0 but
// does not recreate the proxy (it keeps running the target). The gate answers
// ready, the verify by id fails: recovery required. Later starts retry only up
// to the persisted cap, then report without touching Docker. Never a restart
// loop.
func TestStartupReconcile_ArmedTTVerifyMismatchIsCapped(t *testing.T) {
	r := newReconRig(t, true)
	r.world.upStale = true
	seedArmedTT(t, r, journal.PhaseRestarted)
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "post_verify_failed" || got.RunningImage != RunningIsTarget {
		t.Fatalf("result = %+v, want recovery_required/post_verify_failed with the target running", got)
	}
	if c := strings.Join(r.world.calls(), ","); c != "tag:"+cfgOld+",up" {
		t.Errorf("mutating calls = [%s]", c)
	}

	// Second start: T/P armed, attempt 2 of 2: `up` only (the tag is already
	// on the prior), verify fails again.
	r.restart(t)
	r.clearCalls()
	got = r.run(t)
	if got.Decision != "finish_rollback" || got.Reason != "post_verify_failed" {
		t.Errorf("second start = %+v, want finish_rollback/post_verify_failed", got)
	}
	if c := strings.Join(r.world.calls(), ","); c != "up" {
		t.Errorf("second start mutating calls = [%s], want [up]", c)
	}

	r.restart(t)
	r.clearCalls()
	got = r.run(t)
	if got.Reason != "reconcile_exhausted" || got.Outcome != OutcomeRecoveryRequired {
		t.Errorf("third start = %+v, want recovery_required/reconcile_exhausted", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("an exhausted record changed Docker: %v", c)
	}
	if rec := r.recordOnDisk(t); rec == nil || rec.ReconcileAttempts != maxReconcileAttempts {
		t.Errorf("record = %+v, want kept at the cap", rec)
	}
}

// TestStartupReconcile_ArmedRealignRetiresOnlyOnAFreshProbe: an armed record
// whose container still runs the prior while the tag is on the target. The
// retag is done (it restarts nothing), but the record is retired only when a
// fresh probe after it says the prior is ready; otherwise it is kept, with
// nothing further changed, and the next start applies the armed-on-prior rule.
func TestStartupReconcile_ArmedRealignRetiresOnlyOnAFreshProbe(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ready    bool
		noProbe  bool
		reason   string
		outcome  string
		retired  bool
		failedAt int // :reconciled failed entries
	}{
		{"prior ready", true, false, "armed_tag_ahead_container_on_prior", OutcomeConverged, true, 0},
		{"prior not ready", false, false, "armed_rollback_prior_not_ready", OutcomeRecoveryRequired, false, 1},
		{"no probe configured", true, true, "readiness_not_probed", OutcomeRecoveryRequired, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReconRig(t, tc.ready)
			if tc.noProbe {
				r.srv.opts.HealthProbeFactory = nil
			}
			r.world.running, r.world.pinned = cfgOld, cfgNew
			r.seed(t, journal.PhaseRestarting, func(rec *journal.Record) { rec.RollbackArmed = true })
			got := r.run(t)
			if got.Decision != "realign" || got.Reason != tc.reason || got.Outcome != tc.outcome {
				t.Fatalf("result = %+v, want realign/%s %s", got, tc.reason, tc.outcome)
			}
			if c := strings.Join(r.world.calls(), ","); c != "tag:"+cfgOld {
				t.Errorf("mutating calls = [%s], want only the retag", c)
			}
			if retired := r.recordOnDisk(t) == nil; retired != tc.retired {
				t.Errorf("retired = %v, want %v", retired, tc.retired)
			}
			if n := reconciledEntries(t, r); n[audit.OutcomeFailed] != tc.failedAt || n[audit.OutcomeSucceeded] != map[bool]int{true: 1}[tc.retired] {
				t.Errorf(":reconciled entries = %v", n)
			}
			if tc.retired {
				return
			}
			// The next start sees the armed record on the prior: still not
			// retired without a ready probe, and nothing is changed.
			r.restart(t)
			if tc.noProbe {
				r.srv.opts.HealthProbeFactory = nil
			}
			r.clearCalls()
			got = r.run(t)
			if got.Decision != "recovery_required" || got.Reason != tc.reason || len(r.world.calls()) != 0 || r.recordOnDisk(t) == nil {
				t.Errorf("next start = %+v calls=%v, want recovery_required/%s, no change, kept", got, r.world.calls(), tc.reason)
			}
		})
	}
}

// TestStartupReconcile_ArmedRealignDockerChangedBeforeRetire: Docker changes
// between the retag and the probe step's read: nothing is retired.
func TestStartupReconcile_ArmedRealignDockerChangedBeforeRetire(t *testing.T) {
	r := newReconRig(t, true)
	r.world.running, r.world.pinned = cfgOld, cfgNew
	r.seed(t, journal.PhaseRestarting, func(rec *journal.Record) { rec.RollbackArmed = true })
	r.world.onPS = func(n int) {
		if n == 4 { // the probe step's read
			r.setWorld(cfgNew, cfgOld)
		}
	}
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "docker_changed_before_retire" || r.recordOnDisk(t) == nil {
		t.Errorf("result = %+v, want recovery_required/docker_changed_before_retire, kept", got)
	}
}

// TestReconcileNeedsProbe_AfterArmedRealign: the state an armed realign leaves
// (container and tag on the prior, armed) is one where the probe changes the
// verdict, so the probe step runs the probe.
func TestReconcileNeedsProbe_AfterArmedRealign(t *testing.T) {
	in := v2Base()
	in.RollbackArmed = true
	if !reconcileNeedsProbe(in) {
		t.Fatal("reconcileNeedsProbe is false for an armed record on the prior")
	}
	in.Probe = probeReady
	if v := reconcileDecisionV2(in); v != verdictArmedPriorReady {
		t.Fatalf("ready: %v", v)
	}
	if p := reconcilePlan(verdictRealignArmed); len(p) != 2 || p[1].op != stepProbe || p[1].expect != verdictArmedPriorReady {
		t.Fatalf("armed realign plan = %+v", p)
	}
}

// TestStartupReconcile_ArmedTTVerifyNeedsTheValidatedPriorRef: the verify also
// requires the record's validated PriorRef to still name the prior image. An
// operator who removes that reference during the finish leaves a state this
// reconcile cannot vouch for: recovery required, record kept.
func TestStartupReconcile_ArmedTTVerifyNeedsTheValidatedPriorRef(t *testing.T) {
	r := newReconRig(t, true)
	seedArmedTT(t, r, journal.PhaseRestarted)
	r.world.onPS = func(n int) {
		if n == 5 { // the verify's read
			r.world.mu.Lock()
			r.world.priorRefGone = true
			r.world.mu.Unlock()
		}
	}
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "post_verify_failed" {
		t.Errorf("result = %+v, want recovery_required/post_verify_failed", got)
	}
	if r.recordOnDisk(t) == nil {
		t.Error("record retired without a verified prior reference")
	}
}

// TestStartupReconcile_ArmedTTStepFailures:a failed retag, `up` or gate stops
// the finish there: recovery required, the record kept, no later step.
func TestStartupReconcile_ArmedTTStepFailures(t *testing.T) {
	for _, tc := range []struct {
		name, failOn, reason, calls string
	}{
		{"retag fails", "tag", "tag_failed", ""},
		{"up fails", "up", "up_failed", "tag:" + cfgOld},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReconRig(t, true)
			seedArmedTT(t, r, journal.PhaseRestarted)
			r.world.failCmd = tc.failOn
			got := r.run(t)
			if got.Outcome != OutcomeRecoveryRequired || got.Reason != tc.reason {
				t.Errorf("result = %+v, want recovery_required/%s", got, tc.reason)
			}
			if c := strings.Join(r.world.calls(), ","); c != tc.calls {
				t.Errorf("applied mutating calls = [%s], want [%s]", c, tc.calls)
			}
			if r.world.failedCalls != 1 {
				t.Errorf("failed command issued %d times, want once (no retry within a start)", r.world.failedCalls)
			}
			if rec := r.recordOnDisk(t); rec == nil || rec.ReconcileAttempts != 1 {
				t.Errorf("record = %+v, want kept with attempt 1", rec)
			}
			if n := reconciledEntries(t, r); n[audit.OutcomeFailed] != 1 {
				t.Errorf(":reconciled entries = %v, want one failed", n)
			}
		})
	}
}

// TestStartupReconcile_ArmedOnPriorAuditedOnceAfterACrash: the finish was
// killed after its audit entry and before the record's removal (or anywhere
// after its `up`): the next start finds an armed record on the prior, probes,
// and retires it without a second entry.
func TestStartupReconcile_ArmedOnPriorAuditedOnceAfterACrash(t *testing.T) {
	for _, audited := range []bool{true, false} {
		r := newReconRig(t, true)
		r.seed(t, journal.PhaseRestarted, func(rec *journal.Record) {
			rec.RollbackArmed, rec.ReconcileAttempts = true, 1
			rec.ReconcileDecision = "finish_rollback_retag/rollback_armed_tag_not_moved"
		})
		if audited {
			writeReconciled(t, r, audit.OutcomeSucceeded)
		}
		got := r.run(t)
		if got.Reason != "armed_rollback_prior_ready" || got.Outcome != OutcomeConverged || r.recordOnDisk(t) != nil {
			t.Errorf("audited=%v: result = %+v, want retired", audited, got)
		}
		if n := reconciledEntries(t, r); n[audit.OutcomeSucceeded] != 1 {
			t.Errorf("audited=%v: succeeded :reconciled entries = %d, want 1", audited, n[audit.OutcomeSucceeded])
		}
		if c := r.world.calls(); len(c) != 0 {
			t.Errorf("audited=%v: mutating calls = %v", audited, c)
		}
	}
}
