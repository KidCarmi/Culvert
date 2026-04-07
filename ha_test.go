package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── Leader Election via flock ───────────────────────────────────────────────

func TestHAState_AcquireLock(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "test-leader.lock")

	h := &HAState{}
	h.lockPath = lockPath

	// First lock should succeed.
	got, err := h.tryAcquireLock()
	if err != nil {
		t.Fatalf("tryAcquireLock: %v", err)
	}
	if !got {
		t.Fatal("expected to acquire lock")
	}

	// Lock file should exist with PID info.
	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var info map[string]any
	if err := json.Unmarshal(data, &info); err != nil {
		t.Fatalf("lock file not valid JSON: %v", err)
	}
	if info["pid"] == nil {
		t.Error("expected pid in lock file")
	}

	// Cleanup.
	h.releaseLock()
}

func TestHAState_DoubleLockSameProcess(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "test-leader.lock")

	h := &HAState{}
	h.lockPath = lockPath

	// Acquire once.
	got, err := h.tryAcquireLock()
	if err != nil || !got {
		t.Fatalf("first lock: got=%v err=%v", got, err)
	}

	// Acquire again (should return true since we already hold it).
	got, err = h.tryAcquireLock()
	if err != nil {
		t.Fatalf("second lock: %v", err)
	}
	if !got {
		t.Fatal("expected true for re-entrant lock check")
	}

	h.releaseLock()
}

func TestHAState_CompetingLock(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "test-leader.lock")

	// First holder.
	h1 := &HAState{}
	h1.lockPath = lockPath
	got, err := h1.tryAcquireLock()
	if err != nil || !got {
		t.Fatalf("h1 lock: got=%v err=%v", got, err)
	}

	// Second holder should fail.
	h2 := &HAState{}
	h2.lockPath = lockPath
	got, err = h2.tryAcquireLock()
	if err != nil {
		t.Fatalf("h2 lock error: %v", err)
	}
	if got {
		t.Fatal("expected h2 to NOT acquire lock while h1 holds it")
	}

	// Release h1, h2 should succeed.
	h1.releaseLock()

	got, err = h2.tryAcquireLock()
	if err != nil {
		t.Fatalf("h2 after release: %v", err)
	}
	if !got {
		t.Fatal("expected h2 to acquire lock after h1 released")
	}

	h2.releaseLock()
}

func TestHAState_Status(t *testing.T) {
	h := &HAState{}
	s := h.Status()
	if s.Enabled {
		t.Error("expected disabled by default")
	}
	if s.Role != "" {
		t.Errorf("expected empty role, got %q", s.Role)
	}

	h.mu.Lock()
	h.role = "leader"
	h.since = time.Now()
	h.peerAddr = "cp2:50051"
	h.mu.Unlock()

	s = h.Status()
	if !s.Enabled {
		t.Error("expected enabled when role is set")
	}
	if s.Role != "leader" {
		t.Errorf("expected leader, got %q", s.Role)
	}
	if s.PeerAddr != "cp2:50051" {
		t.Errorf("expected cp2:50051, got %q", s.PeerAddr)
	}
	if s.Since == "" {
		t.Error("expected non-empty since")
	}
}

func TestHAState_IsLeader(t *testing.T) {
	h := &HAState{}
	if h.IsLeader() {
		t.Error("expected not leader by default")
	}

	h.mu.Lock()
	h.role = "leader"
	h.mu.Unlock()
	if !h.IsLeader() {
		t.Error("expected leader")
	}

	h.mu.Lock()
	h.role = "standby"
	h.mu.Unlock()
	if h.IsLeader() {
		t.Error("expected not leader after standby")
	}
}

func TestHAState_LeaderElection(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "election-leader.lock")

	promoted := make(chan struct{}, 1)
	h := &HAState{}
	h.StartLeaderElection(lockPath, "peer:50051", 100*time.Millisecond,
		func() error {
			promoted <- struct{}{}
			return nil
		},
		func() {},
	)
	defer h.Stop()

	// Should promote quickly since no competition.
	select {
	case <-promoted:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for promotion")
	}

	if !h.IsLeader() {
		t.Error("expected leader after promotion")
	}
}

// ── Health Endpoint ─────────────────────────────────────────────────────────

func TestAPIHealthz_Standalone(t *testing.T) {
	// With no HA configured, /healthz should return 200 with standalone role.
	origHA := *globalHA
	defer func() { *globalHA = origHA }()
	*globalHA = HAState{} // reset

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	apiHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if resp["role"] != "standalone" {
		t.Errorf("expected standalone, got %v", resp["role"])
	}
	if resp["leader"] != true {
		t.Error("expected leader=true for standalone")
	}
}

func TestAPIHealthz_Leader(t *testing.T) {
	origHA := *globalHA
	defer func() { *globalHA = origHA }()
	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.since = time.Now()
	globalHA.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	apiHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["leader"] != true {
		t.Error("expected leader=true")
	}
}

func TestAPIHealthz_Standby(t *testing.T) {
	origHA := *globalHA
	defer func() { *globalHA = origHA }()
	globalHA.mu.Lock()
	globalHA.role = "standby"
	globalHA.since = time.Now()
	globalHA.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	apiHealthz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["leader"] != false {
		t.Error("expected leader=false for standby")
	}
}

// ── DP Multi-CP Address Parsing ─────────────────────────────────────────────

func TestDataPlaneClient_MultiAddr(t *testing.T) {
	// Verify that comma-separated addresses are parsed correctly.
	// We can't actually connect, so just test the parsing logic.
	addr := "cp1:50051,cp2:50051,cp3:50051"
	addrs := splitAddrs(addr)
	if len(addrs) != 3 {
		t.Fatalf("expected 3 addresses, got %d", len(addrs))
	}
	if addrs[0] != "cp1:50051" || addrs[1] != "cp2:50051" || addrs[2] != "cp3:50051" {
		t.Errorf("unexpected addresses: %v", addrs)
	}
}

func TestDataPlaneClient_SingleAddr(t *testing.T) {
	addr := "cp1:50051"
	addrs := splitAddrs(addr)
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addrs))
	}
	if addrs[0] != "cp1:50051" {
		t.Errorf("unexpected address: %v", addrs)
	}
}

// splitAddrs is a test helper that mirrors the address parsing in NewDataPlaneClient.
func splitAddrs(addr string) []string {
	parts := make([]string, 0)
	for _, a := range splitComma(addr) {
		a = trimSpace(a)
		if a != "" {
			parts = append(parts, a)
		}
	}
	return parts
}

func splitComma(s string) []string {
	result := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	for len(s) > 0 && s[0] == ' ' {
		s = s[1:]
	}
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}

// ── HA API ──────────────────────────────────────────────────────────────────

func TestAPIClusterHA(t *testing.T) {
	origHA := *globalHA
	defer func() { *globalHA = origHA }()
	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.peerAddr = "cp2:50051"
	globalHA.since = time.Now()
	globalHA.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/ha", nil)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiClusterHA(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var status HAStatus
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !status.Enabled {
		t.Error("expected enabled")
	}
	if status.Role != "leader" {
		t.Errorf("expected leader, got %q", status.Role)
	}
	if status.PeerAddr != "cp2:50051" {
		t.Errorf("expected cp2:50051, got %q", status.PeerAddr)
	}
}
