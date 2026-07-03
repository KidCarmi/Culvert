package main

// ha_lease_test.go — ADR-0005 S2: the fencing lease wired into HA
// leadership, unit-tested against halease.Fake (the etcd backend is proven
// separately by the internal/halease conformance suite).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// leaseStandby builds a promotable standby wired to the given provider.
func leaseStandby(p halease.Provider, id string) *HAState {
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.term = 4
	h.stopCh = make(chan struct{})
	h.pc = promoteContext{onPromote: func() error { return nil }, set: true}
	h.mu.Unlock()
	h.SetLeaseProvider(p, id)
	return h
}

func TestLease_PromoteDeniedWhileHeld(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Minute)
	if granted, _, _ := f.Acquire(context.Background(), "cp-other"); !granted {
		t.Fatal("seed acquire")
	}

	h := leaseStandby(f, "cp-me")
	if err := h.PromoteManually(); err == nil {
		t.Fatal("promotion must fail while another node holds the fencing lease")
	}
	if h.IsLeader() {
		t.Fatal("node must stay standby when the fence denies promotion")
	}
	// The guard is re-armed: once the lease frees up, promotion succeeds.
	f.ExpireForTest()
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("post-expiry promotion: %v", err)
	}
	h.Stop()
}

func TestLease_PromoteGranted_TermCollapsesToEpoch(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Minute)
	// Burn some epochs so epoch ≠ term+1 and the collapse is observable.
	for i := 0; i < 6; i++ {
		_, _, _ = f.Acquire(context.Background(), "burn")
		f.ExpireForTest()
	}

	h := leaseStandby(f, "cp-me")
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("PromoteManually: %v", err)
	}
	defer h.Stop()

	st, _ := f.Read(context.Background())
	if got := h.Status().Term; got != termFromEpoch(st.Epoch) {
		t.Errorf("term = %d, want the fencing epoch %d (collapse, ADR-0005 Finding 6)", got, st.Epoch)
	}
	if !h.WriteAllowed() {
		t.Error("freshly-granted leader must have write authority")
	}
}

func TestLease_LegacyModeUnchanged(t *testing.T) {
	tempHADir(t)
	h := leaseStandby(nil, "") // nil provider = legacy
	h.mu.Lock()
	h.lease = nil
	h.mu.Unlock()
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("legacy promotion: %v", err)
	}
	if got := h.Status().Term; got != 5 {
		t.Errorf("legacy term = %d, want 5 (4+1)", got)
	}
	if !h.WriteAllowed() {
		t.Error("legacy mode must always report write authority at the lease layer")
	}
}

// erroringProvider wraps a Provider and fails Renew with a transport error.
type erroringProvider struct {
	halease.Provider
	renewErr error
}

func (e *erroringProvider) Renew(ctx context.Context, holderID string, epoch int64) (bool, time.Duration, error) {
	if e.renewErr != nil {
		return false, 0, e.renewErr
	}
	return e.Provider.Renew(ctx, holderID, epoch)
}

func TestLease_KeepaliveLoss_SelfFences(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(200 * time.Millisecond)
	h := leaseStandby(f, "cp-me")
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("PromoteManually: %v", err)
	}
	defer h.Stop()

	// Steal the lease: expire it and let another node take it. The next
	// keepalive sees a confirmed loss and must self-fence.
	f.ExpireForTest()
	if granted, _, _ := f.Acquire(context.Background(), "cp-usurper"); !granted {
		t.Fatal("usurper acquire")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !h.IsLeader() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if h.IsLeader() {
		t.Fatal("leader did not self-fence after losing the lease")
	}
	if h.WriteAllowed() {
		t.Error("self-fenced node must have no write authority")
	}
	if h.Status().Role != "standby" {
		t.Errorf("self-fenced role = %q, want standby", h.Status().Role)
	}
}

func TestLease_TransportError_FencesOnlyAfterConfirmedWindow(t *testing.T) {
	tempHADir(t)
	inner := halease.NewFake(30 * time.Minute) // long TTL: window outlives the test
	ep := &erroringProvider{Provider: inner}
	h := leaseStandby(ep, "cp-me")
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("PromoteManually: %v", err)
	}
	defer h.Stop()

	// Drive renew rounds deterministically (the background loop also runs;
	// its outcome is identical). Transport errors while the confirmed
	// window is still open: retried, NO fence.
	ep.renewErr = errors.New("etcd unreachable")
	for i := 0; i < 3; i++ {
		if fenced := h.leaseRenewOnce(); fenced {
			t.Fatal("fenced during a still-confirmed validity window (transport errors must be retried)")
		}
	}
	if !h.IsLeader() || !h.WriteAllowed() {
		t.Fatal("leadership/write authority must hold while the confirmed window is open")
	}

	// Collapse the confirmed window: the very next round must fence.
	h.mu.Lock()
	h.leaseValidFor = haLeaseWriteMargin // window ends immediately
	h.mu.Unlock()
	if fenced := h.leaseRenewOnce(); !fenced {
		t.Fatal("renew round did not self-fence after the confirmed window expired under transport errors")
	}
	if h.IsLeader() {
		t.Fatal("leader still holds the role after self-fence")
	}
}

func TestLease_EnableAsLeader_AcquiresAndFails(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Minute)

	// Held by someone else: genesis enable must fail.
	if granted, _, _ := f.Acquire(context.Background(), "cp-other"); !granted {
		t.Fatal("seed acquire")
	}
	h := &HAState{}
	h.SetLeaseProvider(f, "cp-me")
	if _, err := h.EnableAsLeader("cp-me:50051", false); err == nil {
		t.Fatal("EnableAsLeader must fail while the lease is held elsewhere")
	}

	// Free: genesis enable acquires; term = epoch.
	f.ExpireForTest()
	h2 := &HAState{}
	h2.SetLeaseProvider(f, "cp-me")
	token, err := h2.EnableAsLeader("cp-me:50051", false)
	if err != nil || token == "" {
		t.Fatalf("EnableAsLeader = (%q, %v)", token, err)
	}
	defer h2.Stop()
	st, _ := f.Read(context.Background())
	if got := h2.Status().Term; got != termFromEpoch(st.Epoch) {
		t.Errorf("genesis term = %d, want epoch %d", got, st.Epoch)
	}
	if !h2.WriteAllowed() {
		t.Error("genesis leader must have write authority")
	}
}

func TestLease_ResumeDenied_LeaderKeepsRoleWithoutWriteAuthority(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Minute)
	if granted, _, _ := f.Acquire(context.Background(), "cp-usurper"); !granted {
		t.Fatal("seed acquire")
	}

	h := &HAState{}
	h.SetLeaseProvider(f, "cp-me")
	h.ResumeAsLeader(&haConfig{Enabled: true, Token: "tok", PeerAddr: "peer:50051", Role: "leader", Term: 9})
	defer h.Stop()

	if !h.IsLeader() {
		t.Fatal("resume keeps the persisted leader role (ADR-0004 restart semantics)")
	}
	if h.WriteAllowed() {
		t.Fatal("resume without the lease must have NO write authority (fail-closed, ADR-0005 S2)")
	}
	if got := h.Status().Term; got != 9 {
		t.Errorf("unfenced resume term = %d, want persisted 9 (no collapse without a grant)", got)
	}
}

func TestLease_HealthzSurfacesEpochAndLeaseValidity(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Minute)
	h := leaseStandby(f, "cp-me")
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("PromoteManually: %v", err)
	}
	defer h.Stop()

	resp := map[string]any{}
	addLeaseHealth(resp, h)
	if resp["lease_mode"] != "lease" {
		t.Errorf("lease_mode = %v, want lease", resp["lease_mode"])
	}
	if v, ok := resp["lease_valid"].(bool); !ok || !v {
		t.Errorf("lease_valid = %v, want true", resp["lease_valid"])
	}
	st, _ := f.Read(context.Background())
	if resp["epoch"] != st.Epoch {
		t.Errorf("epoch = %v, want %d", resp["epoch"], st.Epoch)
	}

	// Legacy mode: mode "none", no epoch/valid keys.
	legacy := map[string]any{}
	addLeaseHealth(legacy, &HAState{})
	if legacy["lease_mode"] != "none" {
		t.Errorf("legacy lease_mode = %v, want none", legacy["lease_mode"])
	}
	if _, present := legacy["epoch"]; present {
		t.Error("legacy response must not carry an epoch field")
	}
}
