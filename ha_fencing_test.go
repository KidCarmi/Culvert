package main

// ha_fencing_test.go — ADR-0005 S3: epoch fencing at the write sinks +
// DP-side ratchet, tested against halease.Fake.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// installGlobalHA installs h as the process-wide HA state for the test
// (ha_test.go's swapGlobalHA always installs a fresh zero state).
func installGlobalHA(t *testing.T, h *HAState) {
	t.Helper()
	old := globalHA
	globalHA = h
	t.Cleanup(func() { globalHA = old })
}

// fencedLeader returns a lease-mode leader whose lease is NOT held
// (WriteAllowed()==false) — the zombie shape.
func fencedLeader() *HAState {
	h := &HAState{}
	h.mu.Lock()
	h.role = "leader"
	h.lease = halease.NewFake(time.Minute) // provider set, nothing acquired
	h.mu.Unlock()
	return h
}

func TestIssuanceAllowed_Matrix(t *testing.T) {
	tempHADir(t)

	// Standalone (HA off): allowed.
	installGlobalHA(t, &HAState{})
	if ok, _ := haIssuanceAllowed(); !ok {
		t.Error("standalone node must allow issuance")
	}

	// Legacy HA leader (no lease): allowed — role is the only gate available.
	legacyLeader := &HAState{}
	legacyLeader.mu.Lock()
	legacyLeader.role = "leader"
	legacyLeader.mu.Unlock()
	installGlobalHA(t, legacyLeader)
	if ok, _ := haIssuanceAllowed(); !ok {
		t.Error("legacy HA leader must allow issuance")
	}

	// Standby: denied.
	standby := &HAState{}
	standby.mu.Lock()
	standby.role = "standby"
	standby.mu.Unlock()
	installGlobalHA(t, standby)
	if ok, _ := haIssuanceAllowed(); ok {
		t.Error("standby must not allow issuance")
	}

	// Lease-mode leader WITHOUT the lease (zombie shape): denied.
	installGlobalHA(t, fencedLeader())
	if ok, reason := haIssuanceAllowed(); ok {
		t.Error("lease-mode leader without write authority must not allow issuance")
	} else if reason == "" {
		t.Error("denial must carry a reason")
	}

	// Lease-mode leader WITH a live grant: allowed.
	f := halease.NewFake(time.Minute)
	live := leaseStandby(f, "cp-me")
	if err := live.PromoteManually(); err != nil {
		t.Fatalf("PromoteManually: %v", err)
	}
	defer live.Stop()
	installGlobalHA(t, live)
	if ok, _ := haIssuanceAllowed(); !ok {
		t.Error("lease-holding leader must allow issuance")
	}
}

func TestIssuanceRPCs_FencedReturnFailedPrecondition(t *testing.T) {
	tempHADir(t)
	installGlobalHA(t, fencedLeader())
	s := &controlPlaneServer{}

	for name, call := range map[string]func() error{
		"Enroll":          func() error { _, err := s.Enroll(context.Background(), json.RawMessage(`{}`)); return err },
		"RenewCert":       func() error { _, err := s.RenewCert(context.Background(), json.RawMessage(`{}`)); return err },
		"SyncRevocations": func() error { _, err := s.SyncRevocations(context.Background(), json.RawMessage(`{}`)); return err },
	} {
		err := call()
		if err == nil {
			t.Errorf("%s: fenced call must fail", name)
			continue
		}
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition (got err %v)", name, status.Code(err), err)
		}
	}
}

// readErroringProvider fails Read with a transport error (puller-fence path).
type readErroringProvider struct {
	halease.Provider
	readErr error
}

func (r *readErroringProvider) Read(ctx context.Context) (halease.Status, error) {
	if r.readErr != nil {
		return halease.Status{}, r.readErr
	}
	return r.Provider.Read(ctx)
}

func TestVerifyBundleEpoch(t *testing.T) {
	// Legacy (nil provider): always passes.
	legacy := &HAState{}
	if !legacy.verifyBundleEpoch(0) || !legacy.verifyBundleEpoch(7) {
		t.Error("legacy mode must not reject bundles")
	}

	// Lease mode: the backend's current epoch is the floor.
	f := halease.NewFake(time.Minute)
	if granted, st, _ := f.Acquire(context.Background(), "cp-leader"); !granted || st.Epoch != 1 {
		t.Fatal("seed acquire")
	}
	h := &HAState{}
	h.SetLeaseProvider(f, "cp-standby")
	if !h.verifyBundleEpoch(1) {
		t.Error("bundle at the current epoch must be accepted")
	}
	if !h.verifyBundleEpoch(2) {
		t.Error("bundle above the current epoch must be accepted")
	}
	if h.verifyBundleEpoch(0) {
		t.Error("epoch-0 bundle must be rejected while the fence has a real epoch (zombie leader)")
	}

	// Advance the epoch; the old leader's stamp is now stale.
	f.ExpireForTest()
	if granted, st, _ := f.Acquire(context.Background(), "cp-new"); !granted || st.Epoch != 2 {
		t.Fatal("second acquire")
	}
	if h.verifyBundleEpoch(1) {
		t.Error("bundle below the current epoch must be rejected")
	}

	// Backend read failure: fail-closed (skip the sync round).
	hErr := &HAState{}
	hErr.SetLeaseProvider(&readErroringProvider{Provider: f, readErr: errors.New("etcd down")}, "cp-standby")
	if hErr.verifyBundleEpoch(99) {
		t.Error("backend read failure must reject the import (fail-closed)")
	}
}

func TestDPObserveEpoch_Ratchet(t *testing.T) {
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)

	if !dpObserveEpoch("t", 0) {
		t.Error("epoch 0 (legacy) must be accepted")
	}
	if dpLastSeenEpoch.Load() != 0 {
		t.Error("epoch 0 must not move the ratchet")
	}
	if !dpObserveEpoch("t", 5) || dpLastSeenEpoch.Load() != 5 {
		t.Error("first positive epoch must seed the ratchet")
	}
	if !dpObserveEpoch("t", 5) {
		t.Error("equal epoch must be accepted")
	}
	if !dpObserveEpoch("t", 8) || dpLastSeenEpoch.Load() != 8 {
		t.Error("higher epoch must ratchet forward")
	}
	if dpObserveEpoch("t", 6) {
		t.Error("lower epoch must be rejected")
	}
	if dpLastSeenEpoch.Load() != 8 {
		t.Error("a rejected observation must not move the ratchet")
	}
	// Epoch 0 after seeding: still accepted (legacy CP in a mixed cluster),
	// ratchet unchanged.
	if !dpObserveEpoch("t", 0) || dpLastSeenEpoch.Load() != 8 {
		t.Error("epoch 0 after seeding must be accepted without lowering the ratchet")
	}
}

func TestApplyConfigSnapshot_RejectsStaleEpoch(t *testing.T) {
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)
	dpLastSeenEpoch.Store(10)

	// Isolate the blocklist singleton (the first thing applyConfigSnapshot
	// mutates) so the rejection is observable.
	oldList := bl.List()
	t.Cleanup(func() { bl.ReplaceFeedEntries(oldList) })

	applyConfigSnapshot(ConfigSnapshot{
		Version:      99,
		Epoch:        3, // below the ratchet: zombie CP
		BlockedHosts: []string{"stale-epoch-marker.example.com"},
	})
	if bl.IsBlocked("stale-epoch-marker.example.com") {
		t.Fatal("stale-epoch snapshot mutated DP state — the fence failed")
	}

	// Same snapshot at the ratchet: applied.
	applyConfigSnapshot(ConfigSnapshot{
		Version:      100,
		Epoch:        10,
		BlockedHosts: []string{"stale-epoch-marker.example.com"},
	})
	if !bl.IsBlocked("stale-epoch-marker.example.com") {
		t.Fatal("at-ratchet snapshot was not applied")
	}
}
