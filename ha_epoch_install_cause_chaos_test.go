package main

// ha_epoch_install_cause_chaos_test.go — CHAOS-71, the three Codex P1s on
// #1645 @c6ccb5b:
//
//   - 4302926142: an install failure is classified BY CAUSE. A grant lost
//     between the commit and the exposure is an unknown fence (a resume arms
//     CHAOS-55 recovery); only a snapshot-commit refusal takes the no-retry
//     read-only stance.
//   - 4302926140: a delta reply's epoch labels the committed data it carries,
//     never live HA state, and the Data Plane fences on every epoch in it.
//   - 4302926144: onPromote is transactional: a promote that fails after its
//     Control Plane activation completed undoes the activation.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/blocklist"
	"github.com/KidCarmi/Culvert/internal/halease"
)

// cpLoseGrantOnce wraps the stamped commit, on its FIRST call only: the grant
// lapses (no other holder) and the keepalive drops it, either after the commit
// ran (afterCommit) or instead of it, with the commit then failing.
func cpLoseGrantOnce(t *testing.T, h *HAState, f *halease.Fake, afterCommit bool) {
	t.Helper()
	prev := haRestampFenceEpoch
	var calls atomic.Int32
	haRestampFenceEpoch = func() error {
		if calls.Add(1) != 1 {
			return prev()
		}
		var err error
		if afterCommit {
			err = prev()
		} else {
			err = errors.New("injected: the restamp failed while the grant was being lost")
		}
		f.ExpireForTest()
		cpAwait(t, "the keepalive to drop the lost grant", func() bool {
			h.mu.RLock()
			defer h.mu.RUnlock()
			return h.grantEpoch == 0
		})
		return err
	}
	t.Cleanup(func() { haRestampFenceEpoch = prev })
}

// TestChaos71_ResumeLosingItsGrantArmsLeaseRecovery — Codex P1 4302926142. A
// resumed leader whose staged grant is lost before exposure (after the commit,
// or during a commit that then fails) holds an UNKNOWN fence, not a refused
// one: it keeps the leader role read-only, pages no epoch refusal, and the
// CHAOS-55 recovery loop re-acquires and installs a new grant. The negative
// control is a real commit refusal: paged once, read-only, no recovery armed.
func TestChaos71_ResumeLosingItsGrantArmsLeaseRecovery(t *testing.T) {
	const myAddr = "10.0.0.2:50051"
	cfg := &haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051", Token: "tok"}
	for _, tc := range []struct {
		name        string
		afterCommit bool
	}{{"lost_after_the_commit", true}, {"lost_during_a_failing_commit", false}} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, pages := cpEpochHarness(t, myAddr)
			f := halease.NewFake(3 * time.Second) // write authority needs a TTL above its 1 s margin
			h.SetLeaseProvider(f, "cp-a")
			e := cpNextGrantEpoch(t, f)
			cpLoseGrantOnce(t, h, f, tc.afterCommit)

			h.ResumeAsLeader(cfg)
			if st := h.Status(); st.Role != "leader" {
				t.Fatalf("role = %q, want the leader role kept", st.Role)
			}
			if n := cpEpochPagesFrom(pages(), "ha"); n != 0 {
				t.Errorf("a lost grant paged an epoch refusal %d time(s) — it is an unknown fence, not a refusal", n)
			}
			cpAwait(t, "lease recovery to install a new grant", func() bool {
				return h.WriteAllowed() && h.CurrentEpoch() > e
			})
			cpAssertEpochServable(t, h, h.CurrentEpoch())
		})
	}
	t.Run("negative_control_a_refused_commit_stays_read_only", func(t *testing.T) {
		h, f, pages := cpEpochHarness(t, myAddr)
		cpRejectEpochStamp(t, cpNextGrantEpoch(t, f))
		h.ResumeAsLeader(cfg)
		if h.leaseRecoveryActive() || h.WriteAllowed() {
			t.Errorf("a refused commit armed recovery=%v / write authority=%v — ADR-0005 S2: read-only, no auto-retry",
				h.leaseRecoveryActive(), h.WriteAllowed())
		}
		cpAssertRefusalPagedOnce(t, pages)
	})
}

// TestChaos71_InstallFailuresAreClassifiedByCause pins the classifier every
// path uses: a lost grant, however it surfaces, is grantLost; a commit refusal
// is not.
func TestChaos71_InstallFailuresAreClassifiedByCause(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		lost bool
	}{
		{"exposure_found_the_grant_gone", errGrantLost, true},
		{"nothing_staged_at_the_commit", errNoStagedGrant, true},
		{"lost_while_the_commit_failed", fmt.Errorf("%w: %w", errGrantLost, errors.New("restamp")), true},
		{"nothing_published", errNoSnapshotToRestamp, false},
		{"not_committed_at_exposure", errEpochNotCommitted, false},
		{"over_budget", errors.New("snapshot exceeds the wire budget"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := grantLost(tc.err); got != tc.lost {
				t.Errorf("grantLost(%v) = %v, want %v", tc.err, got, tc.lost)
			}
			granted, refused := resumeInstallOutcome(tc.err)
			if granted || refused == tc.lost {
				t.Errorf("resumeInstallOutcome(%v) = granted %v refused %v, want refused=%v", tc.err, granted, refused, !tc.lost)
			}
		})
	}
	if granted, refused := resumeInstallOutcome(nil); !granted || refused {
		t.Errorf("resumeInstallOutcome(nil) = %v, %v", granted, refused)
	}
}

// TestChaos71_DeltaReplyEpochLabelsItsCommittedTarget — Codex P1 4302926140,
// CP side. A leader at E1 commits version N+1 while a new grant's E2 is in
// flight (stamped, not yet advertised). The delta reply for N+1 must carry E2,
// the stamp of the data it describes, not the live E1.
func TestChaos71_DeltaReplyEpochLabelsItsCommittedTarget(t *testing.T) {
	h, _, _ := cpEpochHarness(t, "10.0.0.2:50051")
	if _, err := h.EnableAsLeader("10.0.0.9:50051", false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	e1 := h.CurrentEpoch()
	before := globalConfigStore.Version()
	e2 := e1 + 1
	h.mu.Lock()
	h.stampEpoch = e2 // commitGrant's window: publishes stamp E2, nothing advertises it
	h.syncFenceEpochLocked()
	h.mu.Unlock()
	t.Cleanup(func() {
		h.mu.Lock()
		h.stampEpoch = 0
		h.syncFenceEpochLocked()
		h.mu.Unlock()
	})
	if changed, err := globalConfigStore.UpdateCPAddressesFrom(func() []string { return []string{"10.0.0.8:50051"} }); err != nil || !changed {
		t.Fatalf("publish: changed=%v err=%v", changed, err)
	}
	if got := globalConfigStore.Get().Epoch; got != e2 || h.CurrentEpoch() != e1 {
		t.Fatalf("precondition: committed epoch %d (want %d), advertised %d (want %d)", got, e2, h.CurrentEpoch(), e1)
	}
	const ip = "203.0.113.74"
	clearUnenrolledPull(ip)
	t.Cleanup(func() { clearUnenrolledPull(ip) })
	svc := &controlPlaneServer{}
	for _, known := range []int64{before, globalConfigStore.Version()} {
		reply := callDelta(t, svc, deltaCtx(ip), known)
		if reply.Epoch != e2 {
			t.Errorf("delta reply (known=%d, mode %s) labelled epoch %d, want the committed stamp %d (live: %d)",
				known, reply.Mode, reply.Epoch, e2, e1)
		}
	}
}

// TestChaos71_DataPlaneFencesOnEveryEpochInADeltaReply — Codex P1
// 4302926140, DP side. A reply labelled E1 whose delta and remainder carry E2
// ratchets the Data Plane to E2, so a later E1 snapshot from the fenced CP is
// rejected. Negative controls on the fence itself: a chain that spans a
// failover (older entries at older epochs) is accepted; a target below an
// epoch the same reply carries (S3's zombie shape) is rejected.
func TestChaos71_DataPlaneFencesOnEveryEpochInADeltaReply(t *testing.T) {
	const e1, e2 = int64(5), int64(7)
	restoreBlAndIPF(t)
	t.Cleanup(resetDPLastSeenEpochForTest())
	dpLastSeenEpoch.Store(e1)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDataDir })

	bl.ReplaceFeedEntries([]string{"a.example"})
	c := &DataPlaneClient{}
	c.lastVersion.Store(5)
	reply := getConfigDeltaReply{
		Mode: "delta", BaseVersion: 5, TargetVersion: 6, Epoch: e1, // the live, stale label
		Deltas:    []blocklistDelta{{Version: 6, Base: 5, Added: []string{"b.example"}, Epoch: e2}},
		TargetFP:  blocklist.FeedSetFingerprint([]string{"a.example", "b.example"}),
		Remainder: mustRemainder(t, ConfigSnapshot{Version: 6, Epoch: e2}),
	}
	if !c.applyDeltaReply(reply) || c.lastVersion.Load() != 6 {
		t.Fatalf("precondition: the delta did not apply (lastVersion %d)", c.lastVersion.Load())
	}
	if got := dpLastSeenEpoch.Load(); got != e2 {
		t.Errorf("the Data Plane applied data committed with epoch %d but ratcheted only to %d", e2, got)
	}
	if dpObserveEpoch("config snapshot", e1) {
		t.Error("a later snapshot stamped with the old epoch was accepted — the fenced CP's writes reach the Data Plane")
	}
	// A stale label alone is not a fence verdict: the next version, committed
	// under E2 but still labelled E1, applies on the E2 data it carries.
	next := reply
	next.BaseVersion, next.TargetVersion = 6, 7
	next.Deltas = []blocklistDelta{{Version: 7, Base: 6, Added: []string{"c.example"}, Epoch: e2}}
	next.TargetFP = blocklist.FeedSetFingerprint([]string{"a.example", "b.example", "c.example"})
	if !c.applyDeltaReply(next) || c.lastVersion.Load() != 7 {
		t.Errorf("a delta whose data carries the ratcheted epoch %d was skipped over its stale label %d (lastVersion %d)",
			e2, e1, c.lastVersion.Load())
	}

	t.Cleanup(resetDPLastSeenEpochForTest())
	for _, tc := range []struct {
		name  string
		reply getConfigDeltaReply
		rem   int64
		ok    bool
	}{
		{"chain_spanning_a_failover", getConfigDeltaReply{Epoch: e2, Deltas: []blocklistDelta{{Epoch: e1}, {Epoch: e2}}}, e2, true},
		{"zombie_target_below_the_chain", getConfigDeltaReply{Epoch: 0, Deltas: []blocklistDelta{{Epoch: e2}, {Epoch: 0}}}, 0, false},
		{"stale_label_on_newer_data", getConfigDeltaReply{Epoch: e1, Deltas: []blocklistDelta{{Epoch: e2}}}, e2, true},
		{"target_snapshot_below_its_own_delta", getConfigDeltaReply{Epoch: e2, Deltas: []blocklistDelta{{Epoch: e2}}}, e1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dpLastSeenEpoch.Store(e1)
			if got := fenceDeltaTarget(deltaReplyEpochs(tc.reply, tc.rem)); got != tc.ok {
				t.Errorf("fenceDeltaTarget = %v, want %v", got, tc.ok)
			}
		})
	}
}

// cpTransactionalActivation models activateControlPlane for a promote: it
// owns the CP address list, makes the initial publish (whose error it
// ignores, as production does), and refuses a second activation while one is
// up ("already running as control-plane"). undo is the deactivation.
type cpTransactionalActivation struct {
	mu            sync.Mutex
	active        bool
	starts, undos int
	budget        int // >0: the config grows between the preflight and the activation, once
}

func (a *cpTransactionalActivation) activate() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active {
		return errors.New("already running as control-plane")
	}
	a.active = true
	a.starts++
	globalConfigStore.setCPAddressSource(buildCPAddressList)
	if a.budget > 0 {
		snapshotWireBudget, a.budget = a.budget, 0
	}
	_ = globalConfigStore.Update(CurrentConfigSnapshot())
	return nil
}

func (a *cpTransactionalActivation) undo() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active = false
	a.undos++
	globalConfigStore.releaseCPAddressSource()
}

// TestChaos71_PromoteFailingAfterItsActivationUndoesIt — Codex P1 4302926144.
// Nothing published; the preflight passes; the activation's initial publish
// is then rejected, so the exposure finds no committed snapshot carrying the
// epoch. The activation is undone, so once the config fits again the retry
// promotes. The negative control has no undo: the activation stays up and
// every retry fails "already running as control-plane".
func TestChaos71_PromoteFailingAfterItsActivationUndoesIt(t *testing.T) {
	const myAddr = "10.0.0.2:50051"
	for _, tc := range []struct {
		name     string
		withUndo bool
	}{{"undone", true}, {"negative_control_without_an_undo", false}} {
		t.Run(tc.name, func(t *testing.T) {
			h, f, _ := cpUnpublishedEpochHarness(t, nil)
			prev := snapshotWireBudget
			t.Cleanup(func() { snapshotWireBudget = prev })
			a := &cpTransactionalActivation{budget: 16}
			var undo func()
			if tc.withUndo {
				undo = a.undo
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			h.StartAsStandbyWithUndo(ctx, "10.0.0.7:50051", "tok", myAddr, "", "", "", false, a.activate, undo)

			if err := h.PromoteManually(); err == nil {
				t.Fatal("promote succeeded although no committed snapshot carries its epoch")
			}
			if st := h.Status(); st.Role != "standby" || h.promoted.Load() {
				t.Fatalf("role=%q promoted=%v, want a retryable standby", st.Role, h.promoted.Load())
			}
			snapshotWireBudget = prev // the operator reduced the config
			f.ExpireForTest()         // the failed promote's grant lapses unkept
			want := cpNextGrantEpoch(t, f)
			err := h.PromoteManually()
			if !tc.withUndo {
				if err == nil && h.IsLeader() {
					t.Fatal("negative control: the retry promoted although the first activation was never undone — the test no longer reproduces the defect")
				}
				return
			}
			if err != nil || !h.IsLeader() {
				t.Fatalf("the retry after the undo: err=%v leader=%v — the failed promote left the node unpromotable", err, h.IsLeader())
			}
			if a.undos != 1 || a.starts != 2 {
				t.Errorf("activation starts=%d undos=%d, want 2 and 1", a.starts, a.undos)
			}
			cpAssertEpochServable(t, h, want)
		})
	}
}

// TestChaos71_DeactivateControlPlaneUndoesASyncActivation: the production
// undo (deactivateControlPlane) against a real listener. After it the node
// holds no Control Plane role, no supervisor and no address-list ownership,
// and the same synchronous activation runs again instead of failing "already
// running as control-plane".
func TestChaos71_DeactivateControlPlaneUndoesASyncActivation(t *testing.T) {
	clusterDB := cpIsolateActivation(t)
	cpChaosSetup(t)
	cpInsecure(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = deactivateControlPlane(ctx)
	})
	isCP := func() bool {
		clusterRoleMu.RLock()
		defer clusterRoleMu.RUnlock()
		return clusterRole.role == "control-plane"
	}
	if err := enableControlPlane(addr, "", "", "", clusterDB); err != nil || !isCP() {
		t.Fatalf("precondition: activation err=%v cp=%v", err, isCP())
	}
	if err := enableControlPlane(addr, "", "", "", clusterDB); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("precondition: a second activation returned %v, want already running", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := deactivateControlPlane(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	cpActivationMu.Lock()
	sup := cpSupervisor
	cpActivationMu.Unlock()
	globalConfigStore.mu.RLock()
	owned := globalConfigStore.cpAddrSource != nil
	globalConfigStore.mu.RUnlock()
	if isCP() || sup != nil || owned {
		t.Fatalf("after the undo: cp role=%v supervisor=%v address owner=%v, want none", isCP(), sup != nil, owned)
	}
	if err := enableControlPlane(addr, "", "", "", clusterDB); err != nil || !isCP() {
		t.Fatalf("the activation after the undo: err=%v cp=%v — the undo left the node unactivatable", err, isCP())
	}
}
