package main

// ha_standby_reentry_sync_test.go — synchronization eligibility refers to the
// CURRENT leader: entering standby clears the evidence of an earlier stint.
//
// The defect (lease mode): A, a standby, syncs at T0 and is promoted. A then
// self-fences and re-enters standby against B, the new leader. B dies before A
// has applied anything from it. lastSyncOK still said T0, so after the 30 s
// re-promotion cooldown and until T0+10 min A passed the eligibility check and
// re-promoted itself — publishing its pre-fence state, without whatever B
// wrote while it led.

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// fencedExLeader builds A: synced at T0, promoted, then fenced out by B and
// back in standby against B. Returns A and the lease backend.
func fencedExLeader(t *testing.T) (*HAState, *halease.Fake) {
	t.Helper()
	tempHADir(t)
	f := halease.NewFake(200 * time.Millisecond)
	a := leaseStandby(f, "cp-a")
	a.SetResyncMaterial(resyncCtx(t), ":50051", "", "", "")
	a.markSyncOK() // T0: A applied a bundle from the ORIGINAL leader
	if !(&standbyLoopState{h: a, leaderAddr: "original-leader.example:50051"}).onMaxFail() {
		t.Fatal("setup: a freshly synced standby must auto-promote when the lease is free")
	}
	t.Cleanup(a.Stop)
	a.RecordStandbyAddr("cp-b.example:50051")

	// B takes the lease: A self-fences and re-enters standby against B.
	f.ExpireForTest()
	if granted, _, _ := f.Acquire(context.Background(), "cp-b"); !granted {
		t.Fatal("setup: B must acquire the lease")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := a.Status(); st.Role == "standby" && st.PeerAddr == "cp-b.example:50051" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st := a.Status(); st.Role != "standby" || st.PeerAddr != "cp-b.example:50051" {
		t.Fatalf("setup: A must be a standby of B after the self-fence; got role=%q peer=%q", st.Role, st.PeerAddr)
	}
	return a, f
}

// bDies frees the lease and moves A past the re-promotion cooldown, so only
// synchronization eligibility is left to decide.
func bDies(a *HAState, f *halease.Fake) {
	f.ExpireForTest()
	a.mu.Lock()
	a.lastSelfFence = time.Now().Add(-haRepromoteCooldown - time.Second)
	a.mu.Unlock()
}

func TestStandbyReentry_FencedExLeaderDoesNotRepromoteOnPreFenceSync(t *testing.T) {
	a, f := fencedExLeader(t)
	if last := a.Status().LastSyncOK; last != "" {
		t.Errorf("re-entering standby must clear the previous stint's sync evidence; last_sync_ok=%q", last)
	}
	if blocked := a.Status().AutoPromoteBlocked; blocked == "" {
		t.Error("a standby that has applied nothing from its current leader must report auto_promote_blocked")
	}

	bDies(a, f) // before A synced anything from B
	if (&standbyLoopState{h: a, leaderAddr: "cp-b.example:50051"}).onMaxFail() || a.IsLeader() {
		t.Fatal("A re-promoted on the sync it made BEFORE it was fenced: it now publishes its pre-fence " +
			"state as leader, without anything B wrote while B led")
	}
	// Break-glass is intact.
	if err := a.PromoteManually(); err != nil {
		t.Fatalf("manual promotion must still recover the cluster: %v", err)
	}
}

// Control: once A has applied a bundle from B, B's death is an ordinary
// failover and A promotes.
func TestStandbyReentry_FencedExLeaderPromotesAfterSyncingFromNewLeader(t *testing.T) {
	a, f := fencedExLeader(t)
	a.markSyncOK() // what syncFromLeader records after applying B's bundle
	bDies(a, f)
	if !(&standbyLoopState{h: a, leaderAddr: "cp-b.example:50051"}).onMaxFail() || !a.IsLeader() {
		t.Fatal("A synced from B and B died: A must auto-promote (availability regression)")
	}
}
