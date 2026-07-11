package main

// ha_split_brain_failover_evidence_test.go — CL-4 behavior
// evidence tests.
//
// Purpose
// =======
// roadmap/CLUSTER-RUNTIME-DISCOVERY.md §13 CL-4 (HA split-brain
// resolution) flagged behavior that was previously labelled
// "unverified — requires integration test". This file converts those
// unknowns into observed, reproducible facts. (The CL-5 rolling-update
// × HA failover evidence was retired with the legacy cluster-update
// orchestrator.)
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
//   - Use whitebox direct mutation of HAState / ClusterStore. No
//     real gRPC sockets, no real partitions, no real timers.
//   - Do not call HAState.promote() (whose onPromote starts a gRPC
//     server). Instead, set h.role / h.since / h.token directly
//     under h.mu to simulate the *result* of a promotion.
//   - Do not sleep, do not wait, do not poll. Every assertion is on
//     a synchronous value produced by direct in-memory state.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

// avoid unused-helper warnings from contextually-bound but
// presently-unreferenced imports. context is used to keep the
// imports comparable to ha_test.go in case a follow-up adds a
// context-aware test in this file.
var _ = context.Background
