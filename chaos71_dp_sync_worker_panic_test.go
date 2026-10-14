package main

// chaos71_dp_sync_worker_panic_test.go — CHAOS-71: panic containment for the
// Data Plane's control-plane sync plane.
//
// DataPlaneClient.Run launches five long-lived workers inside the proxy's own
// process (config poll, heartbeat, rate-limit gossip, revocation sync, audit
// push). Go terminates the process on an unrecovered panic in ANY goroutine, so
// before this change a fault in any one of those rounds — all of which parse
// and APPLY a payload the node does not author — was a total gateway outage,
// and a deterministic one was a crash loop under `restart: unless-stopped`.
// CHAOS-24 established the per-round guard for every other background worker in
// the tree, including the cert-renewal loop started by the same startDataPlane;
// these five were never in that sweep's scope.
//
// Every gate below is a MUTATION proof rather than an assertion about a
// comment: reverting the guard makes the test BINARY die on the first panicking
// round, so the gate cannot quietly pass against the pre-fix shape.
//
// The two fail-closed halves get their own gates, because containment alone
// would make those rounds worse than the crash they replace:
//
//   - the config round must mark the apply REJECTED, or a panic mid-apply
//     leaves a partially applied snapshot reported as healthy;
//   - the audit round must RETURN its drained batch, or containment destroys
//     evidence once per interval, forever, with the process alive.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// panickingCall is a callForTest seam that counts every round that reached the
// RPC and then panics, standing in for a fault anywhere under the round's
// fan-out (snapshot apply, broadcast merge, revocation merge, heartbeat parse).
func panickingCall(rounds *atomic.Int64) func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
	return func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		rounds.Add(1)
		panic("CHAOS-71: injected control-plane round fault")
	}
}

// awaitRounds waits until at least want rounds have run, which is what proves
// the LOOP survived rather than the single round.
func awaitRounds(t *testing.T, rounds *atomic.Int64, want int64, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rounds.Load() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s completed %d rounds, want >= %d — the loop stopped on a panicking round", what, rounds.Load(), want)
}

// runLoopUntilRounds drives one worker loop at a 1 ms cadence until it has
// completed want panicking rounds, then cancels and requires the goroutine to
// exit. A loop that exits on the panic fails awaitRounds; a loop that never
// honours cancellation fails the join.
func runLoopUntilRounds(t *testing.T, want int64, what string, loop func(context.Context, *atomic.Int64)) {
	t.Helper()
	var rounds atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); loop(ctx, &rounds) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("%s did not honour cancellation", what)
		}
	}()
	awaitRounds(t, &rounds, want, what)
}

// ── 1. Config poll: contained, counted, and FAILED CLOSED on apply health ────

// TestChaos71_ConfigRoundPanicIsContainedAndMarksApplyRejected pins both halves
// of the config round: the panic is contained and counted under its own
// component, and the apply-health surface fails CLOSED rather than keeping the
// previous success while the node enforces a half-applied snapshot.
func TestChaos71_ConfigRoundPanicIsContainedAndMarksApplyRejected(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	resetConfigSnapshotApplyHealth(t)

	var rounds atomic.Int64
	c := &DataPlaneClient{callForTest: panickingCall(&rounds)}
	c.lastVersion.Store(0) // skip the delta path; go straight to the full poll

	// Reaching the line after this call is itself the containment assertion:
	// un-guarded, the panic propagates out of fetchAndApply and kills the
	// process, taking the test binary with it.
	c.guardedConfigRound(context.Background())

	if got := rounds.Load(); got != 1 {
		t.Fatalf("rounds = %d, want 1 — the injected fault did not reach the round", got)
	}
	if got := atomic.LoadInt64(&statCrashRecords); got != 1 {
		t.Errorf("crash records = %d, want 1 — a contained round must stay observable", got)
	}
	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("no crash record stored for the contained config round")
	}
	if rec.Component != dpComponentConfigPoll {
		t.Errorf("component = %q, want %q", rec.Component, dpComponentConfigPoll)
	}
	if lastConfigSnapshotApplyOK() {
		t.Fatal("a panicking apply round must fail the apply-health surface closed — " +
			"otherwise the node reports a healthy config while enforcing a half-applied snapshot")
	}
}

// CONTROL: the fail-closed marking must be caused by the PANIC, not by the
// guard running at all. A clean round leaves the surface healthy and records
// no crash, so a passing gate above cannot mean the surface is simply stuck.
func TestChaos71_CleanConfigRoundRecordsNothingAndLeavesApplyHealthOK(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	resetConfigSnapshotApplyHealth(t)

	c := &DataPlaneClient{}
	c.lastVersion.Store(0)
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		if method != methodGetConfig {
			t.Errorf("unexpected method %s", method)
		}
		// The CP's "unchanged" sentinel: a real, successful, no-op round.
		return json.RawMessage(`{"config_unchanged":true}`), nil
	}

	c.guardedConfigRound(context.Background())

	if got := atomic.LoadInt64(&statCrashRecords); got != 0 {
		t.Errorf("crash records = %d, want 0 for a clean round", got)
	}
	if !lastConfigSnapshotApplyOK() {
		t.Error("a clean round must leave the apply-health surface healthy")
	}
}

// TestChaos71_PollLoopSurvivesEveryPanickingRound requires the config loop to
// keep ticking through a deterministic fault. Un-guarded this kills the test
// BINARY on the first round, which is the defect itself.
func TestChaos71_PollLoopSurvivesEveryPanickingRound(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	resetConfigSnapshotApplyHealth(t)
	restoreEpoch := resetDPLastSeenEpochForTest()
	t.Cleanup(restoreEpoch)

	runLoopUntilRounds(t, 3, "pollLoop", func(ctx context.Context, rounds *atomic.Int64) {
		c := &DataPlaneClient{callForTest: panickingCall(rounds)}
		c.lastVersion.Store(0)
		c.pollLoop(ctx, time.Millisecond)
	})
}

// ── 2. Audit push: containment must not destroy the drained batch ────────────

// TestChaos71_AuditRoundPanicReturnsTheDrainedBatchToTheQueue is the fail-closed
// half of the audit round: Drain already removed the batch, so containment
// without a requeue would destroy evidence once per interval, forever, with the
// process alive and every surface green.
func TestChaos71_AuditRoundPanicReturnsTheDrainedBatchToTheQueue(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	t.Cleanup(audit.ResetPendingForTest())

	const queued = 3
	for i := 0; i < queued; i++ {
		audit.QueueForClusterForTest(audit.Entry{Action: "chaos71_evidence", ObjectID: "dp"})
	}

	var rounds atomic.Int64
	c := &DataPlaneClient{callForTest: panickingCall(&rounds)}
	if panicked := runGuarded(dpComponentAuditPush, func() { c.auditPushRound(context.Background()) }); !panicked {
		t.Fatal("the injected fault did not panic the audit round")
	}

	// Drain is the only way to observe the queue; a batch destroyed by the
	// panic shows up here as a short (or empty) drain.
	back := audit.Drain()
	if len(back) != queued {
		t.Fatalf("pending audit events after a panicking push = %d, want %d — "+
			"containment must not consume the batch Drain already removed", len(back), queued)
	}
	for i := range back {
		if back[i].Action != "chaos71_evidence" {
			t.Fatalf("requeued entry %d = %q, want the original event", i, back[i].Action)
		}
	}
}

// CONTROL: the requeue must be caused by the FAILURE, not by every round. A
// delivered batch stays delivered — otherwise the gate above would pass with a
// round that simply never clears the queue, duplicating every event forever.
func TestChaos71_DeliveredAuditBatchIsNotRequeued(t *testing.T) {
	t.Cleanup(audit.ResetPendingForTest())

	audit.QueueForClusterForTest(audit.Entry{Action: "chaos71_delivered", ObjectID: "dp"})

	var calls atomic.Int64
	c := &DataPlaneClient{callForTest: func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		calls.Add(1)
		if method != methodPushAuditEvents {
			t.Errorf("unexpected method %s", method)
		}
		return json.RawMessage(`{}`), nil
	}}

	c.auditPushRound(context.Background())

	if got := calls.Load(); got != 1 {
		t.Fatalf("push calls = %d, want 1", got)
	}
	if back := audit.Drain(); len(back) != 0 {
		t.Fatalf("pending audit events after a SUCCESSFUL push = %d, want 0", len(back))
	}
}

// A failed RPC must still requeue — the deferred requeue replaced an explicit
// call on that branch, so this pins the pre-existing retry behaviour.
func TestChaos71_FailedAuditPushStillRequeues(t *testing.T) {
	t.Cleanup(audit.ResetPendingForTest())

	audit.QueueForClusterForTest(audit.Entry{Action: "chaos71_retry", ObjectID: "dp"})

	c := &DataPlaneClient{callForTest: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return nil, errors.New("controlled CP outage")
	}}

	c.auditPushRound(context.Background())

	if back := audit.Drain(); len(back) != 1 {
		t.Fatalf("pending audit events after a FAILED push = %d, want 1", len(back))
	}
}

// TestChaos71_AuditPushLoopSurvivesEveryPanickingRound is the loop-level form:
// the requeue keeps a batch available, so every subsequent tick panics again and
// the loop must survive all of them.
func TestChaos71_AuditPushLoopSurvivesEveryPanickingRound(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	t.Cleanup(audit.ResetPendingForTest())

	// One queued event is enough: the panicking round requeues it, so every
	// subsequent tick has a batch to drain and can panic again.
	audit.QueueForClusterForTest(audit.Entry{Action: "chaos71_loop", ObjectID: "dp"})

	runLoopUntilRounds(t, 3, "auditPushLoop", func(ctx context.Context, rounds *atomic.Int64) {
		c := &DataPlaneClient{callForTest: panickingCall(rounds)}
		c.auditPushLoop(ctx, time.Millisecond)
	})
}

// ── 3. The remaining three loops ─────────────────────────────────────────────

// TestChaos71_MetricsLoopSurvivesEveryPanickingRound requires the heartbeat loop
// to keep ticking through a deterministic fault; a missing heartbeat is already
// loud via the CP-side timeout, a dead process is not.
func TestChaos71_MetricsLoopSurvivesEveryPanickingRound(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	runLoopUntilRounds(t, 3, "metricsLoop", func(ctx context.Context, rounds *atomic.Int64) {
		c := &DataPlaneClient{callForTest: panickingCall(rounds)}
		c.metricsLoop(ctx, time.Millisecond)
	})
}

// TestChaos71_RevocationLoopSurvivesEveryPanickingRound requires the revocation
// loop to keep ticking: a loop that stops leaves revoked sessions live
// fleet-wide while the node reports healthy, which is a silent fail-OPEN.
func TestChaos71_RevocationLoopSurvivesEveryPanickingRound(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	runLoopUntilRounds(t, 3, "revocationSyncLoop", func(ctx context.Context, rounds *atomic.Int64) {
		c := &DataPlaneClient{callForTest: panickingCall(rounds)}
		c.revocationSyncLoop(ctx, time.Millisecond)
	})
}

// The gossip loop additionally owns the cluster-enabled flag: it is set on
// entry and cleared only on ctx.Done. A goroutine that died on a panic would
// leave the limiter cluster-enabled with nothing ever refreshing the broadcast
// again — the frozen-broadcast blackhole CHAOS-61 closed, manufactured by the
// recovery. So this gate requires the loop to survive AND to clear the flag on
// cancellation afterwards.
func TestChaos71_GossipLoopSurvivesPanicsAndStillDisarmsOnCancel(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	limiter := newRateLimiter()
	limiter.Configure(100, time.Minute) // Enabled() must be true to reach the RPC

	var rounds atomic.Int64
	c := &DataPlaneClient{nodeID: "chaos71", callForTest: panickingCall(&rounds)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.rateLimitGossipLoop(ctx, time.Millisecond, limiter) }()

	awaitRounds(t, &rounds, 3, "rateLimitGossipLoop")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("rateLimitGossipLoop did not honour cancellation after contained panics")
	}
	if limiter.ClusterEnabled() {
		t.Error("the gossip loop must still disarm cluster-aware limiting on shutdown " +
			"after a contained panic — a limiter left armed with no broadcast is CHAOS-61's blackhole")
	}
}

// ── 4. Every loop Run starts names a distinct crash component ───────────────
//
// The component label is the operator's only handle on which worker is faulting
// (culvert_crash_records_total{component}). Two loops sharing one label would
// make a config-apply fault indistinguishable from an audit-push fault.
func TestChaos71_SyncPlaneComponentsAreDistinct(t *testing.T) {
	components := []string{
		dpComponentConfigPoll,
		dpComponentMetricsPush,
		dpComponentRateLimitSync,
		dpComponentRevocation,
		dpComponentAuditPush,
	}
	seen := map[string]bool{}
	for _, name := range components {
		if name == "" {
			t.Error("a sync-plane component name is empty")
		}
		if seen[name] {
			t.Errorf("duplicate crash component %q — the five Run loops must be distinguishable", name)
		}
		seen[name] = true
	}
	if len(seen) != 5 {
		t.Fatalf("named components = %d, want 5 (one per loop Run starts)", len(seen))
	}
}

// ── 5. CHAOS-72: a dropped CP-authoritative slice is reported, not silent ────
//
// applySnapshotExtendedState guards the bandwidth and node-group applies on
// BOTH a non-nil field (the presence contract: an older CP omitting a slice
// must not clear local state) and a non-nil store. The second condition is a
// startup-order fact, not a presence one: initCluster → startDataPlane →
// applyDPLastGoodConfigSnapshot replays a snapshot synchronously BEFORE
// initPersistentAdminState constructs either store, so on every Data Plane boot
// the replay drops both slices while the surrounding apply records a complete,
// version-advancing success. These gates pin the reporting; the ordering fix
// itself is tracked separately (see the review).

// TestChaos72_DroppedBandwidthSliceIsReported requires a CP-authoritative slice
// dropped for a startup-order reason to be reported with its slice and config
// version, rather than discarded silently behind a guard that reads like the
// presence contract next to it.
func TestChaos72_DroppedBandwidthSliceIsReported(t *testing.T) {
	origBW, origNG := globalBandwidth, globalNodeGroups
	globalBandwidth, globalNodeGroups = nil, nil
	t.Cleanup(func() { globalBandwidth, globalNodeGroups = origBW, origNG })

	out := captureLogger(t, func() {
		applySnapshotExtendedState(ConfigSnapshot{
			Version:           7,
			BandwidthPolicies: []BandwidthPolicy{{Name: "chaos72", MaxBytesPerSec: 1024}},
			NodeGroups:        []NodeGroup{{Name: "chaos72-group"}},
		})
	})

	if !strings.Contains(out, "bandwidth policies NOT applied") {
		t.Errorf("a dropped bandwidth slice must be reported, got: %s", out)
	}
	if !strings.Contains(out, "node groups NOT applied") {
		t.Errorf("a dropped node-group slice must be reported, got: %s", out)
	}
	if !strings.Contains(out, "v7") {
		t.Errorf("the report must name the config version so an operator can correlate it, got: %s", out)
	}
}

// CONTROL: the report must be caused by the DROP, not by every apply. An
// omitted slice (the presence contract) is a legitimate no-op and must stay
// quiet, or the log would fire on every poll from a CP that ships neither.
func TestChaos72_OmittedSlicesAreNotReportedAsDropped(t *testing.T) {
	origBW, origNG := globalBandwidth, globalNodeGroups
	globalBandwidth, globalNodeGroups = nil, nil
	t.Cleanup(func() { globalBandwidth, globalNodeGroups = origBW, origNG })

	out := captureLogger(t, func() {
		applySnapshotExtendedState(ConfigSnapshot{Version: 8})
	})

	if strings.Contains(out, "NOT applied") {
		t.Errorf("an omitted slice is the presence contract, not a drop — must stay quiet, got: %s", out)
	}
}
