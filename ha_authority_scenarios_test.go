package main

// ha_authority_scenarios_test.go — ADR-0064: the failure scenarios the owner
// named, each through the real paths. Scenarios already pinned elsewhere are
// listed here so the set can be read in one place:
//
//	slow store init (starting grace, then failover, late leader joins)
//	    TestLegacyStandby_StartingGraceExpiresAndTheLateLeaderJoinsAsStandby
//	stale snapshot (preserved configuration older than a reported version)
//	    TestPublishReconcile_KeepsTheHoldWhenNotVerifiable
//	conflicting fleet generations (both leaders wrote; two fingerprints)
//	    TestPublishReconcile_KeepsTheHoldWhenNotVerifiable
//	restart mid-reconciliation
//	    TestPublishReconcile_RestartMidReconciliationConverges
//	asymmetric: the standby cannot reach a leader that still holds the lease
//	    TestLeaseAutoPromote_DeniedWhileLeaderHoldsLease
//	stale leader returning (lease mode)
//	    TestStaleLeader_DeniedLeaseResumeDistributesNothing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// Simultaneous restart (legacy): both nodes come back with role=leader on disk
// (an earlier split brain). Each probes the other; neither is a standby, so
// neither hears a standby's poll, and neither answers as leader. Both stay
// gated — no automatic winner, no second leader.
func TestScenario_SimultaneousRestartOfTwoPersistedLeadersFailsClosed(t *testing.T) {
	f := newRevalFixture(t, revalStandby)
	f.peerLeads = false // the peer is itself revalidating: it serves no HASync
	if resumeLeadershipAttempt() {
		t.Fatal("node A decided with no evidence")
	}
	// The peer's probe arrives. It says what it is; it is not a standby's poll.
	if _, err := standbyPoll(t, map[string]any{"token": revalToken, "role": haRoleRevalidating, "term": 5}); err == nil {
		t.Fatal("a revalidating node answered another leader's probe as a leader")
	}
	assertRevalidating(t)
	if f.probes.Load() == 0 {
		t.Error("the node must have probed its peer")
	}
}

// Network partition and heal (legacy, both sides led): the standby promoted
// while the old leader kept serving its data planes and accepted an edit. After
// the heal those data planes report the old leader's newer version to the new
// leader. They are never rolled back, publication is held, and — because the
// new leader also accepted an edit of its own — nothing is adopted
// automatically: this is the conflicting branch, with an actionable diff.
func TestScenario_PartitionHealWithWritesOnBothSidesHoldsAndNeverRollsBack(t *testing.T) {
	promotedPair(t)
	// The new leader's own edit during the partition.
	policyStore.ReplaceAll(append(policyStore.List(), PolicyRule{Priority: 7, Name: "new-side-edit", DestFQDN: "new.example", Action: ActionAllow}))
	if err := publishCurrentConfigSnapshot(); err != nil {
		t.Fatalf("new leader's edit: %v", err)
	}
	// The heal: the old side's data planes arrive, and the old leader answers.
	rec := previousLeaderPreserved(t)
	haFetchPeerSnapshot = func(context.Context) (*haPreservedSnapshot, error) { return rec, nil }
	for _, k := range []int64{reconAhead, reconAhead - 1} {
		if unchanged, snap, _ := dpGetConfig(t, k); !unchanged {
			t.Fatalf("k=%d: a data plane of the old side was rolled back to v%d", k, snap.Version)
		}
	}
	if reconcilePublishHoldOnce(context.Background()) {
		t.Fatal("adopted the old side's configuration over the new side's own edit")
	}
	st := publishGateSnapshot()
	if !st.Held || !strings.Contains(st.ReconcileNote, "both sides hold changes") {
		t.Fatalf("want the conflicting branch; got held=%v note=%q", st.Held, st.ReconcileNote)
	}
	if got := ruleNamesOf(policyStore.List()); !strings.Contains(got, "new-side-edit") || strings.Contains(got, reconNewerRule) {
		t.Fatalf("the new side's configuration changed: [%s]", got)
	}
	// The new side's own data planes are not frozen.
	if unchanged, _, err := dpGetConfig(t, gateWatermark); err != nil || unchanged {
		t.Errorf("a consistent data plane must keep being served (unchanged=%v err=%v)", unchanged, err)
	}
}

// Asymmetric connectivity, the other way round: the standby reaches the
// leader, the data planes do not. Nothing fails over, no gate arms, nothing is
// held — the data planes simply keep their last configuration.
func TestScenario_DataPlanesCutOffButStandbyConnectedChangesNothing(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	for i := 0; i < haStandbyMaxFail*3; i++ {
		if p.s.guardedTick() {
			t.Fatal("a standby that syncs every round promoted")
		}
	}
	if p.h.IsLeader() || publishGateSnapshot().Armed {
		t.Fatalf("leader=%v gate=%+v", p.h.IsLeader(), publishGateSnapshot())
	}
}

// Lease expiration mid-publish: a leader that loses the fencing lease stops
// being a publisher at once — a publish that follows the loss is refused, and
// nothing is distributed from it.
func TestScenario_LeaseLostMidPublishStopsPublicationAndDistribution(t *testing.T) {
	isolateEligGlobals(t)
	restore := swapGlobalHA(t)
	t.Cleanup(func() { globalHA.Stop(); restore() })
	f := halease.NewFake(time.Minute)
	globalHA = leaseStandby(f, "cp-a")
	globalHA.mu.Lock()
	globalHA.pc = promoteContext{set: true, onPromote: publishCurrentConfigSnapshot}
	globalHA.mu.Unlock()
	if err := globalHA.PromoteManually(); err != nil {
		t.Fatalf("setup: promote: %v", err)
	}
	if err := publishCurrentConfigSnapshot(); err != nil {
		t.Fatalf("control: a fenced leader publishes: %v", err)
	}
	before := globalConfigStore.Version()

	// The lease expires and another node takes it, between two publishes.
	f.ExpireForTest()
	if granted, _, _ := f.Acquire(context.Background(), "cp-b"); !granted {
		t.Fatal("usurper acquire")
	}
	deadline := time.Now().Add(5 * time.Second)
	for globalHA.WriteAllowed() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if globalHA.WriteAllowed() {
		t.Fatal("setup: the keepalive must notice the loss")
	}
	if haLeadershipHeld() {
		t.Fatal("a node that lost the lease still reports leadership")
	}
	if err := publishCurrentConfigSnapshot(); !errors.Is(err, errPublishWithoutLeadership) {
		t.Fatalf("a publish after the lease was lost must be refused; got %v", err)
	}
	if globalConfigStore.Version() != before {
		t.Fatal("a refused publish committed a version")
	}
}

// Large data set: a 200,000-host blocklist goes through preservation shape,
// the content fingerprint and the adoption unchanged.
func TestScenario_LargeConfigurationIsAdoptedIntact(t *testing.T) {
	_, rec := heldPair(t)
	const n = 200_000
	hosts := make([]string, n)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host-%d.large.ha-recon.example", i)
	}
	rec.Snapshot.BlockedHosts = hosts
	if a, b := contentFingerprint(rec.Snapshot), contentFingerprint(rec.Snapshot); a == "" || a != b {
		t.Fatal("content fingerprint must be stable")
	}
	if !reconcilePublishHoldOnce(context.Background()) {
		t.Fatalf("large adoption failed: %q", publishGateSnapshot().ReconcileNote)
	}
	unchanged, snap, err := dpGetConfig(t, reconAhead)
	if err != nil || unchanged || len(snap.BlockedHosts) != n {
		t.Fatalf("served %d blocked hosts (unchanged=%v err=%v), want %d", len(snap.BlockedHosts), unchanged, err, n)
	}
}
