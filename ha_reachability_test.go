package main

// ha_reachability_test.go — PR-2 (A3/A8): a standby may automatically promote
// ONLY on positive evidence the leader is unreachable per the failure detector.
// A local inability to validate, persist, decrypt, authenticate, or apply leader
// state is never evidence of unavailability; ambiguous RPC errors default to no
// promotion. See ADR-0012 §6.2 and invariant #4.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// legacyStandby builds an auto-failover-enabled, non-lease standby with a
// working promote context, so a genuine threshold crossing WOULD promote — which
// makes "did not promote" assertions meaningful rather than vacuous.
func legacyStandby() *HAState {
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.autoFailover = true
	h.stopCh = make(chan struct{})
	h.pc = promoteContext{onPromote: func() error { return nil }, set: true}
	h.mu.Unlock()
	return h
}

// 1. Reachable leader + local TLS-material failure must not promote (A3).
// A local client-construction fault (unreadable/undecryptable TLS material) is
// surfaced through tick()'s reconnect; it must hold the streak, never advance it.
func TestReachableLeaderPlusLocalTLSFailureNoPromote(t *testing.T) {
	dir := t.TempDir()
	s := &standbyLoopState{
		h:          legacyStandby(),
		ctx:        context.Background(),
		leaderAddr: "leader:50051",
		// Non-empty but nonexistent TLS material → NewDataPlaneClient fails
		// locally (buildClientTLS/loadDPNodeKeyPair), grpc never dials.
		certFile:  filepath.Join(dir, "missing-cert.pem"),
		keyFile:   filepath.Join(dir, "missing-key.pem"),
		failCount: haStandbyMaxFail - 1, // one short of the promotion threshold
	}
	if s.tick() {
		t.Fatal("local TLS-material fault exited the loop (promoted)")
	}
	if s.failCount != haStandbyMaxFail-1 {
		t.Fatalf("local TLS fault advanced the promotion streak: failCount=%d, want %d", s.failCount, haStandbyMaxFail-1)
	}
	if s.h.IsLeader() {
		t.Fatal("local TLS-material fault promoted the standby")
	}
	if !s.localFaultWarned {
		t.Fatal("local fault was not made operator-visible")
	}
}

// 2. Reachable leader + rejected configuration must not promote.
// A leader that answered but whose config we rejected locally is alive.
func TestReachableLeaderPlusRejectedConfigNoPromote(t *testing.T) {
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background(), failCount: haStandbyMaxFail - 1}
	if s.handleSyncResult(false, leaderReachableProven) {
		t.Fatal("rejected-config (reachable leader) exited the loop (promoted)")
	}
	if s.failCount != 0 {
		t.Fatalf("reachable-leader rejection counted as a leader failure: failCount=%d", s.failCount)
	}
	if s.h.IsLeader() {
		t.Fatal("reachable leader + rejected config promoted the standby")
	}
}

// 3. Reachable leader + local persistence failure must not promote.
// Same evidence class (leader answered; the local apply/persist failed).
func TestReachableLeaderPlusLocalPersistenceFailureNoPromote(t *testing.T) {
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background(), failCount: haStandbyMaxFail - 1}
	if s.handleSyncResult(false, leaderReachableProven) {
		t.Fatal("local persistence failure (reachable leader) promoted the standby")
	}
	if s.failCount != 0 {
		t.Fatalf("local persistence failure counted as a leader failure: failCount=%d", s.failCount)
	}
	if s.h.IsLeader() {
		t.Fatal("local persistence failure promoted the standby")
	}
}

// 4. Malformed / invalid leader response must not promote.
// syncFromLeader maps an unparseable bundle to leaderReachableProven (the leader
// answered) — which, per the state machine, resets the streak and never promotes.
func TestMalformedLeaderResponseNoPromote(t *testing.T) {
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background(), failCount: haStandbyMaxFail - 1}
	// leaderReachableProven is exactly what syncFromLeader returns for a
	// malformed/epoch-rejected bundle (ha.go: json.Unmarshal / verifyBundleEpoch).
	if s.handleSyncResult(false, leaderReachableProven) {
		t.Fatal("malformed leader response promoted the standby")
	}
	if s.h.IsLeader() {
		t.Fatal("malformed leader response promoted the standby")
	}
}

// 5. gRPC Unknown / Internal do not automatically prove unreachability (A8).
func TestAmbiguousGRPCErrorsDoNotProveUnreachability(t *testing.T) {
	for _, code := range []codes.Code{codes.Unknown, codes.Internal, codes.Canceled, codes.DataLoss, codes.Aborted} {
		if got := classifyLeaderReachability(status.Error(code, "ambiguous")); got != leaderReachabilityUnknown {
			t.Fatalf("%s classified %v, want leaderReachabilityUnknown (no promotion)", code, got)
		}
	}
	// And the state machine must hold — neither advance nor reset — and never promote.
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background(), failCount: haStandbyMaxFail - 1}
	if s.handleSyncResult(false, leaderReachabilityUnknown) {
		t.Fatal("ambiguous error promoted the standby")
	}
	if s.failCount != haStandbyMaxFail-1 {
		t.Fatalf("ambiguous error moved the promotion streak: failCount=%d, want %d", s.failCount, haStandbyMaxFail-1)
	}
	if !s.ambiguousWarned {
		t.Fatal("ambiguous leader error was not made operator-visible")
	}
}

// 6a. Genuine transport failure / deadline IS positive unreachability evidence,
// and advances the streak with hysteresis (below threshold → no promotion yet).
func TestGenuineUnreachableAdvancesStreakWithHysteresis(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.DeadlineExceeded} {
		if got := classifyLeaderReachability(status.Error(code, "down")); got != leaderUnreachableProven {
			t.Fatalf("%s classified %v, want leaderUnreachableProven", code, got)
		}
	}
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background()}
	for want := 1; want < haStandbyMaxFail; want++ {
		if s.handleSyncResult(false, leaderUnreachableProven) {
			t.Fatalf("promoted below the failure threshold at streak %d", want)
		}
		if s.failCount != want {
			t.Fatalf("streak = %d, want %d", s.failCount, want)
		}
		if s.h.IsLeader() {
			t.Fatalf("promoted below threshold at streak %d", want)
		}
	}
}

// 6b. At the threshold, genuine unreachability promotes through the real fence.
func TestGenuineUnreachablePromotesAtThreshold(t *testing.T) {
	tempHADir(t)
	h := freshStandby(halease.NewFake(time.Minute))
	defer h.Stop()
	s := &standbyLoopState{h: h, ctx: context.Background(), leaderAddr: "dead-leader:50051", failCount: haStandbyMaxFail - 1}
	if !s.handleSyncResult(false, leaderUnreachableProven) {
		t.Fatal("genuine unreachable at threshold must promote (loop should exit)")
	}
	if !h.IsLeader() {
		t.Fatal("node should be leader after threshold-crossing auto-failover")
	}
}

// 7. Repeated local (and ambiguous) failures never cross the promotion threshold.
func TestRepeatedLocalFailuresNeverCrossPromotionThreshold(t *testing.T) {
	dir := t.TempDir()
	s := &standbyLoopState{
		h:          legacyStandby(),
		ctx:        context.Background(),
		leaderAddr: "leader:50051",
		certFile:   filepath.Join(dir, "missing-cert.pem"),
		keyFile:    filepath.Join(dir, "missing-key.pem"),
	}
	for i := 0; i < haStandbyMaxFail*4; i++ {
		if s.tick() {
			t.Fatalf("repeated local fault promoted at iteration %d", i)
		}
	}
	if s.failCount != 0 {
		t.Fatalf("repeated local faults accumulated a promotion streak: failCount=%d", s.failCount)
	}
	if s.h.IsLeader() {
		t.Fatal("repeated local faults eventually promoted the standby")
	}

	// Same guarantee for repeated ambiguous RPC errors.
	a := &standbyLoopState{h: legacyStandby(), ctx: context.Background()}
	for i := 0; i < haStandbyMaxFail*4; i++ {
		if a.handleSyncResult(false, leaderReachabilityUnknown) {
			t.Fatalf("repeated ambiguous error promoted at iteration %d", i)
		}
	}
	if a.failCount != 0 || a.h.IsLeader() {
		t.Fatalf("repeated ambiguous errors crossed the threshold: failCount=%d leader=%v", a.failCount, a.h.IsLeader())
	}
}

// 8. Local and ambiguous faults are operator-visible, and the warning latches
// re-arm after recovery so a later fault episode warns again.
func TestLocalAndAmbiguousFaultsAreOperatorVisible(t *testing.T) {
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background(), leaderAddr: "leader:50051"}

	s.warnLocalClientFault(errNoLeaderClient)
	if !s.localFaultWarned {
		t.Fatal("local fault did not set the operator-visible latch")
	}
	s.warnAmbiguousLeaderError()
	if !s.ambiguousWarned {
		t.Fatal("ambiguous error did not set the operator-visible latch")
	}

	// A successful sync re-arms both latches (so the next episode is visible too).
	if s.handleSyncResult(true, leaderReachableProven) {
		t.Fatal("successful sync exited the loop")
	}
	if s.localFaultWarned || s.ambiguousWarned {
		t.Fatal("warn latches were not re-armed after recovery")
	}
}

// 9. After a local fault clears, the standby resumes syncing without any unsafe
// promotion — the streak stays at zero and the node remains a standby.
func TestRecoveryAfterLocalFaultResumesWithoutUnsafePromotion(t *testing.T) {
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background()}
	// Simulate an episode of held-off local faults.
	s.localFaultWarned = true
	s.failCount = 0
	// The leader becomes reachable and the sync succeeds.
	if s.handleSyncResult(true, leaderReachableProven) {
		t.Fatal("recovered sync exited the loop (promoted)")
	}
	if s.failCount != 0 {
		t.Fatalf("recovery left a nonzero streak: %d", s.failCount)
	}
	if s.h.IsLeader() {
		t.Fatal("recovery unexpectedly promoted the standby")
	}
	if s.localFaultWarned {
		t.Fatal("recovery did not clear the local-fault latch")
	}
}
