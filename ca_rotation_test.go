package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// ── CA Rotation Tracking ────────────────────────────────────────────────────

func TestCARotation_StartAndRecord(t *testing.T) {
	cs := newTestClusterStore(t)

	// Register some nodes.
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "s1"})
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-2", Status: "connected", CertSerial: "s2"})
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-3", Status: "revoked", CertSerial: "s3"})

	// Start rotation — should count only non-revoked nodes.
	cs.StartCARotation("new-fp-abc", "old-fp-xyz", time.Now().Add(24*time.Hour))

	rot := cs.CARotationStatus()
	if rot == nil {
		t.Fatal("expected rotation state, got nil")
	}
	if rot.TotalNodes != 2 {
		t.Errorf("expected 2 total nodes (excluding revoked), got %d", rot.TotalNodes)
	}
	if rot.NewFingerprint != "new-fp-abc" {
		t.Errorf("wrong new fingerprint: %s", rot.NewFingerprint)
	}
	if rot.OldFingerprint != "old-fp-xyz" {
		t.Errorf("wrong old fingerprint: %s", rot.OldFingerprint)
	}
	if len(rot.RenewedNodes) != 0 {
		t.Errorf("expected 0 renewed nodes, got %d", len(rot.RenewedNodes))
	}

	// Record first node renewed.
	cs.RecordNodeRenewed("dp-1")
	rot = cs.CARotationStatus()
	if len(rot.RenewedNodes) != 1 {
		t.Errorf("expected 1 renewed node, got %d", len(rot.RenewedNodes))
	}
	if _, ok := rot.RenewedNodes["dp-1"]; !ok {
		t.Error("dp-1 should be in renewed nodes")
	}

	// Record second node.
	cs.RecordNodeRenewed("dp-2")
	rot = cs.CARotationStatus()
	if len(rot.RenewedNodes) != 2 {
		t.Errorf("expected 2 renewed nodes, got %d", len(rot.RenewedNodes))
	}

	// Recording when no rotation active should be no-op.
	cs.ClearCARotation()
	rot = cs.CARotationStatus()
	if rot != nil {
		t.Error("expected nil rotation after clear")
	}
	// Should not panic.
	cs.RecordNodeRenewed("dp-1")
}

func TestCARotation_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")

	cs := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	_ = cs.Load(path)
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "s1"})
	cs.StartCARotation("fp-new", "fp-old", time.Now().Add(time.Hour))
	cs.RecordNodeRenewed("dp-1")

	// Reload.
	cs2 := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	if err := cs2.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	rot := cs2.CARotationStatus()
	if rot == nil {
		t.Fatal("rotation state not persisted")
	}
	if len(rot.RenewedNodes) != 1 {
		t.Errorf("expected 1 renewed node after reload, got %d", len(rot.RenewedNodes))
	}
}

// ── ConfigSnapshot CA Fingerprint ───────────────────────────────────────────

func TestConfigSnapshot_CAFingerprint(t *testing.T) {
	origCA := globalClusterCA
	defer func() { globalClusterCA = origCA }()

	ca := &clusterCA{}
	dir := t.TempDir()
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	globalClusterCA = ca

	snap := CurrentConfigSnapshot()
	if snap.CAFingerprint == "" {
		t.Error("expected non-empty CA fingerprint in config snapshot")
	}
	if len(snap.CAFingerprint) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars", len(snap.CAFingerprint))
	}
}

// ── DP CA Rotation Detection ─────────────────────────────────────────────────

func TestApplyConfigSnapshot_CARotationDetection(t *testing.T) {
	// Save and restore package globals that applyConfigSnapshot mutates so
	// this test does NOT leak into sibling tests (qa-determinism catches the
	// cascade: AddManual on the half-initialised Blocklist left behind here
	// used to panic with "assignment to entry in nil map").
	origBL, origIPF, origRL := bl, ipf, rl
	origCert, _ := lastSeenCAFingerprint.Load().(string)
	t.Cleanup(func() {
		bl = origBL
		ipf = origIPF
		rl = origRL
		lastSeenCAFingerprint.Store(origCert)
	})

	// Reset state.
	lastSeenCAFingerprint.Store("")

	// Drain any existing notification.
	select {
	case <-caRotationNotify:
	default:
	}

	// First snapshot — should NOT trigger rotation (no previous fingerprint).
	snap := ConfigSnapshot{
		Version:       1,
		CAFingerprint: "fp-initial",
	}
	applyConfigSnapshot(snap)

	select {
	case <-caRotationNotify:
		t.Error("should not trigger rotation on first fingerprint")
	default:
		// Good.
	}

	// Same fingerprint — should NOT trigger.
	snap.Version = 2
	applyConfigSnapshot(snap)

	select {
	case <-caRotationNotify:
		t.Error("should not trigger rotation when fingerprint unchanged")
	default:
	}

	// Different fingerprint — SHOULD trigger.
	snap.Version = 3
	snap.CAFingerprint = "fp-rotated"
	applyConfigSnapshot(snap)

	select {
	case <-caRotationNotify:
		// Good — rotation detected.
	case <-time.After(100 * time.Millisecond):
		t.Error("expected caRotationNotify signal on fingerprint change")
	}
}

// ── API: /api/cluster/rotation ──────────────────────────────────────────────

func TestAPIClusterRotation_NoRotation(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)

	// Ensure no rotation active.
	globalClusterStore.ClearCARotation()

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/rotation", nil)
	w := httptest.NewRecorder()

	apiClusterRotation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	if resp["active"] != false {
		t.Errorf("expected active=false, got %v", resp["active"])
	}
}

func TestAPIClusterRotation_Active(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)

	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "s1"})
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-2", Status: "connected", CertSerial: "s2"})
	globalClusterStore.StartCARotation("new-fp", "old-fp", time.Now().Add(24*time.Hour))
	globalClusterStore.RecordNodeRenewed("dp-1")

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/rotation", nil)
	w := httptest.NewRecorder()

	apiClusterRotation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	if resp["active"] != true {
		t.Error("expected active=true")
	}
	if resp["renewed_count"].(float64) != 1 {
		t.Errorf("expected renewed_count=1, got %v", resp["renewed_count"])
	}
	if resp["total_nodes"].(float64) != 2 {
		t.Errorf("expected total_nodes=2, got %v", resp["total_nodes"])
	}
	pending := resp["pending_nodes"].([]any)
	if len(pending) != 1 || pending[0].(string) != "dp-2" {
		t.Errorf("expected pending=[dp-2], got %v", pending)
	}
	if resp["complete"] != false {
		t.Error("expected complete=false (1/2 renewed)")
	}
}

// ── saveLocked ──────────────────────────────────────────────────────────────

func TestClusterStore_SaveLocked(t *testing.T) {
	cs := newTestClusterStore(t)
	cs.RegisterNode(&EnrolledNode{NodeID: "n1", Status: "connected", CertSerial: "s1"})

	// saveLocked should work when called under lock (unlike Save which takes RLock).
	cs.mu.Lock()
	err := cs.saveLocked()
	cs.mu.Unlock()
	if err != nil {
		t.Fatalf("saveLocked: %v", err)
	}
}

// ── Ensure atomic.Value works for fingerprint tracking ──────────────────────

func TestLastSeenCAFingerprint_AtomicValue(t *testing.T) {
	var v atomic.Value
	v.Store("fp-1")
	got, _ := v.Load().(string)
	if got != "fp-1" {
		t.Errorf("expected fp-1, got %s", got)
	}
	v.Store("fp-2")
	got, _ = v.Load().(string)
	if got != "fp-2" {
		t.Errorf("expected fp-2, got %s", got)
	}
}
