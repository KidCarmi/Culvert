package main

// ha_split_brain_failover_evidence_test.go — CL-4 + CL-5 behavior
// evidence tests.
//
// Purpose
// =======
// roadmap/CLUSTER-RUNTIME-DISCOVERY.md §13 CL-4 (HA split-brain
// resolution) and CL-5 (rolling update vs HA failover) flagged
// behavior that was previously labelled "unverified — requires
// integration test". This file converts those unknowns into
// observed, reproducible facts.
//
// Scope of this file
// ==================
// EVIDENCE ONLY. The tests pin the CURRENT behavior of the system so
// that:
//
//   1. Future hardening work (quorum, fencing, HA-replicated update
//      state) can use these tests as a structural starting point —
//      flip the assertions when the behavior changes.
//   2. The discovery doc can replace "unverified — requires test"
//      language with "verified by ha_split_brain_failover_evidence_test.go:<line>".
//
// UPDATED for ADR-0004 Slice 1 (2026-06-30). The mitigation landed:
//   - auto-failover is now OPT-IN and OFF by default (a witness-less
//     2-node cluster cannot auto-promote safely);
//   - a restart HONORS the persisted role (a standby never silently
//     resumes as a second leader — haRestartAction);
//   - /healthz now exposes `term` + `write_authority`, so a double
//     leader is DETECTABLE (compare terms across both CPs) instead of
//     two indistinguishable `leader:true` bodies.
// The assertions below are updated to pin this NEW behavior.
//
// UPDATED for ADR-0005 S5 (2026-07-03). The failover-mechanism slice
// landed: with an etcd fencing lease armed, every path to leadership
// is Acquire-gated, so the CL-4 double-leader shape is STRUCTURALLY
// impossible in lease mode (TestCL4_LeaseMode_SplitBrainStructurally-
// Prevented below). The legacy-mode facts stay pinned as-is — they
// describe deployments WITHOUT a lease (nil provider = byte-identical
// ADR-0004 behavior), where no-reconcile-on-heal and opt-in-flag
// split-brain remain the documented reality.
//
// Determinism contract
// ====================
// All tests:
//   - Use whitebox direct mutation of HAState / ClusterStore /
//     ClusterUpdateState. No real gRPC sockets, no real partitions,
//     no real timers.
//   - Do not call HAState.promote() (whose onPromote starts a gRPC
//     server). Instead, set h.role / h.since / h.token directly
//     under h.mu to simulate the *result* of a promotion.
//   - Do not sleep, do not wait, do not poll. Every assertion is on
//     a synchronous value produced by direct in-memory state.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// ─────────────────────────────────────────────────────────────────────
// CL-4: Split-Brain Behavior Evidence
// ─────────────────────────────────────────────────────────────────────
//
// Post-Slice-1 behaviour (ADR-0004; recorded here)
// -------------------------------------------------
// 1. The standby self-promotes after 3 HASync failures ONLY when
//    auto-failover is explicitly enabled (default OFF). With the
//    default, the standby stays read-only and fires
//    `ha_manual_failover_required` (ha.go standbyLoop / onMaxFail).
// 2. The original leader is still NOT notified and does NOT step down
//    (no demote path yet) — split-brain remains POSSIBLE under opt-in
//    auto-failover. Automatic fencing/reconcile is the mechanism slice.
// 3. Restart now HONORS the persisted role (haRestartAction): a
//    standby re-enters standby; only a persisted leader resumes
//    leadership. The old unconditional self-assert (and the stale
//    ha.go comment) are gone.
// 4. apiHealthz still returns `leader:true` on each leader side (the
//    LB-readiness ambiguity remains until write_authority is gated on
//    quorum), BUT it now ALSO exposes `term`, so two leaders are
//    DETECTABLE by comparing terms across both CPs.
//
// These tests pin facts 1–4 as they stand after Slice 1.

// TestCL4_SplitBrain_BothSidesReportLeaderAfterPromote exercises the
// /healthz endpoint on each "side" of a simulated split-brain. The
// test installs two distinct HAState instances (one per side) and
// flips globalHA between them while the handler runs. Both responses
// report 200 OK + leader, which is the operator-visible failure mode.
func TestCL4_SplitBrain_BothSidesReportLeaderAfterPromote(t *testing.T) {
	defer swapGlobalHA(t)()

	token := "shared-ha-token-for-evidence-test"

	// Side L: the original leader (term 1), unchanged by the partition.
	sideL := &HAState{}
	sideL.mu.Lock()
	sideL.role = "leader"
	sideL.token = token
	sideL.peerAddr = "cp-s.internal:50051"
	sideL.since = time.Now().Add(-1 * time.Hour) // L has been leader for a while
	sideL.term = 1
	sideL.mu.Unlock()

	// Side S: the former standby, promoted after maxFail=3 HASync
	// failures (auto-failover enabled). promote() bumps the term, so the
	// post-promote epoch is HIGHER than L's. (We do NOT call promote()
	// directly because its onPromote starts a real gRPC server; we set
	// the post-promote state — role=leader, term incremented.)
	sideS := &HAState{}
	sideS.mu.Lock()
	sideS.role = "leader" // ← post-promote
	sideS.token = token
	sideS.peerAddr = "cp-l.internal:50051"
	sideS.since = time.Now() // promote just happened
	sideS.term = 2           // ← promote bumped the epoch (ADR-0004 Slice 1c)
	sideS.mu.Unlock()

	// /healthz reads globalHA. Swap to L and probe.
	globalHA = sideL
	rL := httptest.NewRecorder()
	apiHealthz(rL, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if rL.Code != http.StatusOK {
		t.Errorf("side L /healthz status = %d; want %d (leader should respond healthy)", rL.Code, http.StatusOK)
	}
	if !strings.Contains(rL.Body.String(), `"role":"leader"`) {
		t.Errorf("side L /healthz body missing role:leader: %s", rL.Body.String())
	}
	if !strings.Contains(rL.Body.String(), `"term":1`) {
		t.Errorf("side L /healthz must expose term=1 (Slice 1c detection material): %s", rL.Body.String())
	}

	// Swap to S and probe.
	globalHA = sideS
	rS := httptest.NewRecorder()
	apiHealthz(rS, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if rS.Code != http.StatusOK {
		t.Errorf("side S /healthz status = %d; want %d (post-promote standby ALSO reports healthy)", rS.Code, http.StatusOK)
	}
	if !strings.Contains(rS.Body.String(), `"role":"leader"`) {
		t.Errorf("side S /healthz body missing role:leader: %s", rS.Body.String())
	}
	if !strings.Contains(rS.Body.String(), `"term":2`) {
		t.Errorf("side S /healthz must expose the higher post-promote term=2: %s", rS.Body.String())
	}

	// EVIDENCE (post-Slice-1): both sides still return 200 OK + role=
	// leader, so a naive load balancer keying only on `leader` still
	// cannot distinguish — that ambiguity remains until write_authority
	// is gated on quorum (mechanism slice). BUT the bodies now carry
	// DIFFERENT terms (1 vs 2), which IS the split-brain detection
	// signal Slice 1c added: an operator/monitor scraping both CPs sees
	// two leaders at different epochs and knows S promoted later.
}

// TestCL4_LeaseMode_SplitBrainStructurallyPrevented — ADR-0005 closure
// evidence. With a fencing lease armed, the double-leader shape pinned
// above CANNOT be constructed through any promotion path: two nodes
// share one lease authority, the second promotion is DENIED while the
// first holds the lease, and /healthz distinguishes the real leader by
// lease_valid + a non-zero fencing epoch.
func TestCL4_LeaseMode_SplitBrainStructurallyPrevented(t *testing.T) {
	defer swapGlobalHA(t)()
	tempHADir(t)

	f := halease.NewFake(time.Minute)
	sideA := leaseStandby(f, "cp-a")
	sideB := leaseStandby(f, "cp-b")

	if err := sideA.PromoteManually(); err != nil {
		t.Fatalf("first promotion (lease free) must succeed: %v", err)
	}
	defer sideA.Stop()
	defer sideB.Stop()

	if err := sideB.PromoteManually(); err == nil {
		t.Fatal("second promotion must be DENIED while side A holds the lease — the CL-4 double leader cannot form in lease mode")
	}
	if sideB.IsLeader() {
		t.Fatal("side B must remain standby after the denied promotion")
	}

	// Distinguishability: the holder's /healthz carries the live lease
	// posture; the denied node still reports role=standby.
	globalHA = sideA
	rA := httptest.NewRecorder()
	apiHealthz(rA, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	body := rA.Body.String()
	if !strings.Contains(body, `"lease_mode":"lease"`) || !strings.Contains(body, `"lease_valid":true`) {
		t.Errorf("holder /healthz must expose the live lease posture: %s", body)
	}
	if !strings.Contains(body, `"epoch":1`) {
		t.Errorf("holder /healthz must expose the fencing epoch: %s", body)
	}

	globalHA = sideB
	rB := httptest.NewRecorder()
	apiHealthz(rB, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if !strings.Contains(rB.Body.String(), `"role":"standby"`) {
		t.Errorf("denied side /healthz must report standby: %s", rB.Body.String())
	}
}

// TestCL4_SplitBrain_NoReconcileLogicExistsOnRejoin pins the absence
// of automatic reconciliation. Two ClusterStore instances diverge,
// and "healing the partition" is a no-op — there is no code path
// that merges them. The test passes today and will fail loudly when
// a future reconcile mechanism is added (the right-hand side will
// gain entries from the left).
func TestCL4_SplitBrain_NoReconcileLogicExistsOnRejoin(t *testing.T) {
	csL := newTestClusterStore(t)
	csS := newTestClusterStore(t)

	// Pre-partition: both sides have the same node baseline. (In a
	// real partition this is the state at t-Δ, but for the test we
	// just install identical initial state.)
	csL.RegisterNode(&EnrolledNode{NodeID: "dp-baseline", CertSerial: "s-baseline", Status: "connected"})
	csS.RegisterNode(&EnrolledNode{NodeID: "dp-baseline", CertSerial: "s-baseline", Status: "connected"})

	// During partition: admin mutations on each side. The two sides
	// can NOT see each other.
	csL.RegisterNode(&EnrolledNode{NodeID: "dp-only-on-L", CertSerial: "s-L-only", Status: "connected"})
	csS.RegisterNode(&EnrolledNode{NodeID: "dp-only-on-S", CertSerial: "s-S-only", Status: "connected"})

	// "Heal the partition." There is no code to call here — no
	// reconcile, no merge, no resync RPC. The partition heal is a
	// no-op in the current codebase. We make this explicit:
	//   (no operation performed)

	// EVIDENCE: each side still has only its own admin mutation.
	if _, ok := csL.GetNode("dp-only-on-S"); ok {
		t.Errorf("L unexpectedly knows about dp-only-on-S — reconcile logic exists? (test out of date)")
	}
	if _, ok := csS.GetNode("dp-only-on-L"); ok {
		t.Errorf("S unexpectedly knows about dp-only-on-L — reconcile logic exists? (test out of date)")
	}

	// Both sides retain their own divergent mutations.
	if _, ok := csL.GetNode("dp-only-on-L"); !ok {
		t.Errorf("L lost its own admin mutation — unrelated regression")
	}
	if _, ok := csS.GetNode("dp-only-on-S"); !ok {
		t.Errorf("S lost its own admin mutation — unrelated regression")
	}
}

// TestCL4_SplitBrain_PersistedHAConfigShowsLeaderOnBothSides pins
// fact #3: after an (opt-in) auto-failover promotion, both nodes'
// haConfig.json files on disk record role="leader". Post-Slice-1 the
// restart path honours the persisted role (haRestartAction): a node
// whose file says "leader" resumes as leader, a node whose file says
// "standby" re-enters standby. So two leader-role files DO each resume
// as leader on restart — the residual split-brain that the mechanism
// slice (fencing/reconcile) must still resolve. There is still no
// "ask the peer who is leading" handshake (the leader records no peer
// address — see ADR-0004), but the node no longer self-asserts leader
// from a standby-role file.
func TestCL4_SplitBrain_PersistedHAConfigShowsLeaderOnBothSides(t *testing.T) {
	// Side L's haConfig directory.
	origDB := clusterDBPathGlobal
	t.Cleanup(func() { clusterDBPathGlobal = origDB })

	// Side L persists role=leader at HA-enable time.
	dirL := t.TempDir()
	clusterDBPathGlobal = filepath.Join(dirL, "cluster.json")
	if err := saveHAConfig(&haConfig{
		Enabled:  true,
		Token:    "shared-token",
		PeerAddr: "cp-s:50051",
		Role:     "leader",
	}); err != nil {
		t.Fatalf("save L haConfig: %v", err)
	}
	cfgL, err := loadHAConfig()
	if err != nil || cfgL.Role != "leader" {
		t.Fatalf("L haConfig after EnableAsLeader: cfg=%+v err=%v; want Role=leader", cfgL, err)
	}

	// Side S, after promote(), also persists role=leader (ha.go:258).
	dirS := t.TempDir()
	clusterDBPathGlobal = filepath.Join(dirS, "cluster.json")
	if err := saveHAConfig(&haConfig{
		Enabled:  true,
		Token:    "shared-token", // same token, both sides
		PeerAddr: "cp-l:50051",
		Role:     "leader", // ← post-promote
	}); err != nil {
		t.Fatalf("save S haConfig: %v", err)
	}
	cfgS, err := loadHAConfig()
	if err != nil || cfgS.Role != "leader" {
		t.Fatalf("S haConfig after promote: cfg=%+v err=%v; want Role=leader", cfgS, err)
	}

	// EVIDENCE: both files claim role=leader, so on restart each
	// resumes as leader (haRestartAction → "leader"). The residual
	// double-leader is detectable via /healthz term but not yet
	// auto-reconciled — that is the failover-mechanism slice's job.
	if cfgL.Role != cfgS.Role {
		t.Errorf("expected BOTH sides to record role=leader (the operator-visible failure mode); got L=%q S=%q", cfgL.Role, cfgS.Role)
	}
}

// ─────────────────────────────────────────────────────────────────────
// CL-5: Rolling Update × HA Failover Behavior Evidence
// ─────────────────────────────────────────────────────────────────────
//
// Pre-fix behaviour (recorded here)
// ----------------------------------
// 1. HAStateBundle (controlplane.go:841) carries ClusterState,
//    CACert/Key, and ConfigSnapshot — but NOT clusterUpdateState.
//    The on-disk cluster_update.json (update_cluster.go:77) is a
//    LOCAL file, not HA-replicated.
// 2. ConfigSnapshot (controlplane.go:70) likewise has no field
//    referencing cluster_update.json or rolling-update state.
// 3. recoverClusterUpdate (update_cluster.go:938) is called once at
//    startup. It reads clusterUpdateFile from local disk. If the
//    new leader's local file is missing/empty (typical for the
//    standby pre-promote), recovery is a no-op and the orchestrator
//    is NOT restarted — runClusterUpdate is only spawned by
//    apiClusterUpdate (admin POST).
// 4. Net effect on failover during updating_dps: the new leader
//    starts blank; the in-flight rolling update STOPS until an
//    operator manually re-issues it.

// TestCL5_HAStateBundle_OmitsClusterUpdateState is a structural
// assertion that the HA replication payload does NOT carry
// rolling-update state. This is the structural reason
// runClusterUpdate cannot survive failover.
func TestCL5_HAStateBundle_OmitsClusterUpdateState(t *testing.T) {
	// Build a representative HAStateBundle.
	bundle := HAStateBundle{
		ClusterState:   json.RawMessage(`{"Nodes":{},"Tokens":{},"Revoked":null}`),
		CACertPEM:      "test-ca-cert",
		CAKeyEncrypted: "test-encrypted",
		Config:         CurrentConfigSnapshot(),
		Version:        42,
	}

	// Marshal + unmarshal — what crosses the wire is what the standby
	// can see. The standby has no way to recover cluster_update.json
	// state from anything in here.
	wire, err := json.Marshal(&bundle)
	if err != nil {
		t.Fatalf("marshal HAStateBundle: %v", err)
	}

	// Search the wire payload for any rolling-update state markers.
	// These are EVIDENCE strings — if they ever appear, CL-5 has
	// been fixed (the bundle now carries update state) and this test
	// must be updated.
	const (
		markerActive      = `"active"`       // ClusterUpdateState.Active json tag
		markerTargetTag   = `"target_tag"`   // ClusterUpdateState.TargetTag json tag
		markerUpdatingDPs = "updating_dps"   // canonical Phase string
		markerCanarySoak  = "canary_soak"    // canonical Phase string
		markerNodesUpd    = `"nodes":`       // ClusterUpdateState.Nodes json tag
		markerErrorBudget = `"error_budget"` // ClusterUpdateState.ErrorBudget json tag
	)
	wireStr := string(wire)
	for _, m := range []string{markerActive, markerTargetTag, markerUpdatingDPs, markerCanarySoak, markerNodesUpd, markerErrorBudget} {
		if strings.Contains(wireStr, m) {
			t.Errorf("HAStateBundle wire payload UNEXPECTEDLY contains %q — CL-5 fix may be in flight; update this test", m)
		}
	}

	// Also inspect the ConfigSnapshot struct fields directly via
	// reflection — even an empty config snapshot must not declare
	// rolling-update fields.
	snapType := reflect.TypeOf(bundle.Config)
	for i := 0; i < snapType.NumField(); i++ {
		f := snapType.Field(i)
		name := strings.ToLower(f.Name)
		if strings.Contains(name, "update") && strings.Contains(name, "phase") {
			t.Errorf("ConfigSnapshot field %q hints at rolling-update state — CL-5 fix may be in flight; update this test", f.Name)
		}
		if strings.Contains(strings.ToLower(string(f.Tag)), "cluster_update") {
			t.Errorf("ConfigSnapshot field %q has cluster_update json tag — CL-5 fix may be in flight; update this test", f.Name)
		}
	}

	// EVIDENCE: the bundle as currently shipped contains no
	// rolling-update state. A standby that promotes mid-update has
	// no way to know there even WAS an update in progress.
}

// TestCL5_FailoverDuringUpdate_NewLeaderRecoveryUsesLocalDiskOnly
// pins recovery semantics: recoverClusterUpdate consumes
// clusterUpdateFile from local disk only. If the new leader's file
// is missing/stale, the in-flight update is effectively dropped.
func TestCL5_FailoverDuringUpdate_NewLeaderRecoveryUsesLocalDiskOnly(t *testing.T) {
	snapshotClusterUpdateState(t)

	// Set up two distinct files: side L (old leader) has a mid-update
	// state on its disk; side S (new leader, just promoted) has a
	// DIFFERENT file path (no overlap, no shared filesystem).
	dirL := t.TempDir()
	dirS := t.TempDir()
	fileL := filepath.Join(dirL, "cluster_update.json")
	fileS := filepath.Join(dirS, "cluster_update.json")

	// Write L's mid-update state to L's local disk. Use the same
	// serialisation path as persist() so the payload is realistic.
	midUpdate := ClusterUpdateState{
		Active:      true,
		TargetTag:   "v9.9.9-cl5-test",
		PreviousTag: "v9.9.8-cl5-test",
		Initiator:   "admin@cl5-test",
		StartedAt:   time.Now().Add(-1 * time.Minute),
		Phase:       "updating_dps",
		ErrorBudget: ErrorBudgetConfig{MaxConsecutive: 3, MaxPercent: 20},
		Nodes: map[string]*NodeUpdateStatus{
			"dp-pending":  {NodeID: "dp-pending", Status: "pending"},
			"dp-updating": {NodeID: "dp-updating", Status: "updating"},
		},
	}
	dataL, err := json.MarshalIndent(&midUpdate, "", "  ")
	if err != nil {
		t.Fatalf("marshal mid-update state: %v", err)
	}
	if err := os.WriteFile(fileL, dataL, 0o600); err != nil {
		t.Fatalf("write L file: %v", err)
	}

	// Side S's disk is empty — a freshly-promoted standby has never
	// participated in any rolling update. This is the canonical
	// CL-5 scenario.
	if _, err := os.Stat(fileS); !os.IsNotExist(err) {
		t.Fatalf("S file unexpectedly exists pre-test: %v", err)
	}

	// Simulate failover: the system now reads from S's local file.
	clusterUpdateFile = fileS

	// Reset in-memory state (the new leader's process starts fresh).
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = false
	clusterUpdateState.Phase = ""
	clusterUpdateState.Nodes = nil
	clusterUpdateState.TargetTag = ""
	clusterUpdateState.mu.Unlock()

	// Run recovery on the new leader.
	recoverClusterUpdate()

	// EVIDENCE: the new leader's clusterUpdateState is still empty.
	// L's mid-update progress has been completely dropped on the
	// floor.
	clusterUpdateState.mu.Lock()
	gotActive := clusterUpdateState.Active
	gotPhase := clusterUpdateState.Phase
	gotTargetTag := clusterUpdateState.TargetTag
	gotNodes := len(clusterUpdateState.Nodes)
	clusterUpdateState.mu.Unlock()

	if gotActive {
		t.Errorf("new leader Active = true; want false (L's update should NOT have been resumed)")
	}
	if gotPhase != "" {
		t.Errorf("new leader Phase = %q; want \"\" (L's Phase=updating_dps should NOT have transferred)", gotPhase)
	}
	if gotTargetTag != "" {
		t.Errorf("new leader TargetTag = %q; want \"\" (L's target tag should NOT have transferred)", gotTargetTag)
	}
	if gotNodes != 0 {
		t.Errorf("new leader Nodes len = %d; want 0 (L's per-node update status should NOT have transferred)", gotNodes)
	}
}

// TestCL5_FailoverDuringUpdate_StaleLocalStateOnNewLeader pins the
// other failure mode: the new leader's local file contains a STALE
// rolling-update state (e.g. from a previous completed update). In
// that case recoverClusterUpdate consumes the stale file and the
// system carries forward stale terminal state until an admin acts.
func TestCL5_FailoverDuringUpdate_StaleLocalStateOnNewLeader(t *testing.T) {
	snapshotClusterUpdateState(t)

	dir := t.TempDir()
	fileS := filepath.Join(dir, "cluster_update.json")

	// Stale terminal state on S's disk: a previous update that
	// completed before HA was even enabled. Active=true triggers the
	// recovery switch; Phase="complete" is one of the terminal
	// branches.
	staleS := ClusterUpdateState{
		Active:      true, // recoverClusterUpdate only acts when Active is true
		TargetTag:   "v0.0.1-stale-previous",
		PreviousTag: "v0.0.0",
		Initiator:   "previous-admin",
		StartedAt:   time.Now().Add(-90 * 24 * time.Hour), // 90 days old
		Phase:       "complete",
		ErrorBudget: ErrorBudgetConfig{MaxConsecutive: 3, MaxPercent: 20},
	}
	dataS, err := json.MarshalIndent(&staleS, "", "  ")
	if err != nil {
		t.Fatalf("marshal stale state: %v", err)
	}
	if err := os.WriteFile(fileS, dataS, 0o600); err != nil {
		t.Fatalf("write S file: %v", err)
	}

	clusterUpdateFile = fileS
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = false
	clusterUpdateState.Phase = ""
	clusterUpdateState.TargetTag = ""
	clusterUpdateState.mu.Unlock()

	recoverClusterUpdate()

	clusterUpdateState.mu.Lock()
	gotActive := clusterUpdateState.Active
	gotPhase := clusterUpdateState.Phase
	gotTargetTag := clusterUpdateState.TargetTag
	clusterUpdateState.mu.Unlock()

	// recoverClusterUpdate for Phase=complete sets Active=false and
	// returns. The Phase remains "complete" in memory (the recovery
	// path does not clear it).
	if gotActive {
		t.Errorf("recover with stale complete-phase: Active = true; want false (recovery should clear Active for terminal phases)")
	}
	if gotPhase != "complete" {
		t.Errorf("recover with stale complete-phase: Phase = %q; want \"complete\" (recovery preserves Phase string)", gotPhase)
	}

	// EVIDENCE: the new leader's status endpoint will now report a
	// stale TargetTag (90-day-old version) because Phase=complete +
	// the TargetTag string is read from the stale on-disk file. This
	// is the operator-visible artifact of failover during/after an
	// update.
	if gotTargetTag != "v0.0.1-stale-previous" {
		t.Errorf("stale TargetTag = %q; want %q (proves the new leader presents stale state to operators until manual action)", gotTargetTag, "v0.0.1-stale-previous")
	}
}

// TestCL5_FailoverDuringUpdate_UpdatingDPsBecomesHaltedOnRecovery
// pins recovery semantics for the specific phase that matters most:
// updating_dps. If a failover happens while DPs are still being
// updated and the NEW leader happens to have the same local file
// state (e.g. shared volume in some deployments), recoverClusterUpdate
// translates updating_dps → halted. This is the CURRENT documented
// recovery behavior for the orchestrator.
//
// In real HA the new leader almost never has L's file (they have
// independent disks), so this branch fires when the operator
// explicitly stages the file. The test pins the recovery output
// for that case.
func TestCL5_FailoverDuringUpdate_UpdatingDPsBecomesHaltedOnRecovery(t *testing.T) {
	snapshotClusterUpdateState(t)

	dir := t.TempDir()
	fileNew := filepath.Join(dir, "cluster_update.json")

	stagedUpdate := ClusterUpdateState{
		Active:      true,
		TargetTag:   "v1.2.3-cl5-staged",
		PreviousTag: "v1.2.2",
		Initiator:   "admin",
		StartedAt:   time.Now().Add(-5 * time.Minute),
		Phase:       "updating_dps",
		ErrorBudget: ErrorBudgetConfig{MaxConsecutive: 3, MaxPercent: 20},
		Nodes: map[string]*NodeUpdateStatus{
			"dp-a": {NodeID: "dp-a", Status: "complete"},
			"dp-b": {NodeID: "dp-b", Status: "updating"},
		},
	}
	data, err := json.MarshalIndent(&stagedUpdate, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(fileNew, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	clusterUpdateFile = fileNew
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = false
	clusterUpdateState.Phase = ""
	clusterUpdateState.mu.Unlock()

	recoverClusterUpdate()

	clusterUpdateState.mu.Lock()
	gotActive := clusterUpdateState.Active
	gotPhase := clusterUpdateState.Phase
	// Capture node statuses too — recoverClusterUpdate does NOT
	// reconcile them, so dp-b stays "updating" even though no
	// orchestrator is touching it.
	dpB := ""
	if n, ok := clusterUpdateState.Nodes["dp-b"]; ok {
		dpB = n.Status
	}
	clusterUpdateState.mu.Unlock()

	// EVIDENCE: recovery for updating_dps → halted + Active=false.
	if gotActive {
		t.Errorf("recover updating_dps: Active = true; want false")
	}
	if gotPhase != "halted" {
		t.Errorf("recover updating_dps: Phase = %q; want \"halted\" (update_cluster.go:908-912)", gotPhase)
	}
	// dp-b's per-node status is left untouched by recovery — pins the
	// known recovery gap (separate item, NOT addressed in this PR).
	if dpB != "updating" {
		t.Errorf("dp-b status after recovery = %q; want %q (recovery does NOT reconcile per-node status — this is the known gap)", dpB, "updating")
	}
}

// avoid unused-helper warnings from contextually-bound but
// presently-unreferenced imports. context is used to keep the
// imports comparable to ha_test.go in case a follow-up adds a
// context-aware test in this file.
var _ = context.Background
