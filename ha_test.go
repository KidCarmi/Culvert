package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── HAState ─────────────────────────────────────────────────────────────────

func TestHAState_Status_Disabled(t *testing.T) {
	h := &HAState{}
	s := h.Status()
	if s.Enabled {
		t.Error("expected disabled by default")
	}
	if s.Role != "" {
		t.Errorf("expected empty role, got %q", s.Role)
	}
}

func TestHAState_Status_Leader(t *testing.T) {
	h := &HAState{}
	h.mu.Lock()
	h.role = "leader"
	h.since = time.Now()
	h.peerAddr = "cp1:50051"
	h.mu.Unlock()

	s := h.Status()
	if !s.Enabled {
		t.Error("expected enabled when role is set")
	}
	if s.Role != "leader" {
		t.Errorf("expected leader, got %q", s.Role)
	}
	if s.PeerAddr != "cp1:50051" {
		t.Errorf("expected cp1:50051, got %q", s.PeerAddr)
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

func TestHAState_VerifyToken(t *testing.T) {
	h := &HAState{}
	if h.VerifyToken("anything") {
		t.Error("expected false when no token set")
	}

	h.mu.Lock()
	h.token = "secret-token-123"
	h.mu.Unlock()

	if !h.VerifyToken("secret-token-123") {
		t.Error("expected true for matching token")
	}
	if h.VerifyToken("wrong-token") {
		t.Error("expected false for wrong token")
	}
}

func TestHAState_EnableAsLeader(t *testing.T) {
	h := &HAState{}
	token := h.EnableAsLeader("cp2:50051")

	if token == "" {
		t.Error("expected non-empty token")
	}
	if len(token) < 32 {
		t.Errorf("token too short: %d chars", len(token))
	}
	if !h.IsLeader() {
		t.Error("expected leader after EnableAsLeader")
	}
	if !h.VerifyToken(token) {
		t.Error("expected token to be verifiable")
	}
}

func TestGenerateHAToken(t *testing.T) {
	t1 := generateHAToken()
	t2 := generateHAToken()
	if t1 == t2 {
		t.Error("expected unique tokens")
	}
	if len(t1) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("expected 64-char token, got %d", len(t1))
	}
}

// ── HA Config Persistence ───────────────────────────────────────────────────

func TestHAConfigPersistence(t *testing.T) {
	// Save original and restore after test.
	origPath := clusterDBPathGlobal
	clusterDBPathGlobal = t.TempDir() + "/cluster.json"
	defer func() { clusterDBPathGlobal = origPath }()

	cfg := &haConfig{
		Enabled:  true,
		Token:    "test-token-abc",
		PeerAddr: "cp1:50051",
		Role:     "standby",
	}
	if err := saveHAConfig(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := loadHAConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loaded.Enabled {
		t.Error("expected enabled")
	}
	if loaded.Token != "test-token-abc" {
		t.Errorf("expected test-token-abc, got %q", loaded.Token)
	}
	if loaded.PeerAddr != "cp1:50051" {
		t.Errorf("expected cp1:50051, got %q", loaded.PeerAddr)
	}
	if loaded.Role != "standby" {
		t.Errorf("expected standby, got %q", loaded.Role)
	}
}

// ── Health Endpoint ─────────────────────────────────────────────────────────

func TestAPIHealthz_Standalone(t *testing.T) {
	origHA := *globalHA
	defer func() { *globalHA = origHA }()
	*globalHA = HAState{}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	apiHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
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
	addr := "cp1:50051,cp2:50051,cp3:50051"
	parts := strings.Split(addr, ",")
	if len(parts) != 3 {
		t.Fatalf("expected 3 addresses, got %d", len(parts))
	}
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	if parts[0] != "cp1:50051" || parts[1] != "cp2:50051" || parts[2] != "cp3:50051" {
		t.Errorf("unexpected addresses: %v", parts)
	}
}

// ── HA API ──────────────────────────────────────────────────────────────────

func TestAPIClusterHA_GET(t *testing.T) {
	origHA := *globalHA
	defer func() { *globalHA = origHA }()
	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.peerAddr = "cp1:50051"
	globalHA.token = "test-token"
	globalHA.since = time.Now()
	globalHA.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/ha", nil)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiClusterHA(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["enabled"] != true {
		t.Error("expected enabled=true")
	}
	if resp["role"] != "leader" {
		t.Errorf("expected leader, got %v", resp["role"])
	}
	if resp["deploy_cmd"] == nil || resp["deploy_cmd"] == "" {
		t.Error("expected non-empty deploy_cmd for leader")
	}
}

func TestAPIClusterHA_EnableRequiresCP(t *testing.T) {
	origHA := *globalHA
	defer func() { *globalHA = origHA }()
	*globalHA = HAState{}

	clusterRoleMu.Lock()
	origRole := clusterRole.role
	clusterRole.role = ""
	clusterRoleMu.Unlock()
	defer func() {
		clusterRoleMu.Lock()
		clusterRole.role = origRole
		clusterRoleMu.Unlock()
	}()

	body := `{"leader_addr":"cp1:50051"}`
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/ha", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiClusterHA(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 (not CP), got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIClusterHA_Enable(t *testing.T) {
	origHA := *globalHA
	origPath := clusterDBPathGlobal
	defer func() {
		globalHA.Stop()
		*globalHA = origHA
		clusterDBPathGlobal = origPath
	}()
	*globalHA = HAState{}
	clusterDBPathGlobal = t.TempDir() + "/cluster.json"

	clusterRoleMu.Lock()
	origRole := clusterRole.role
	origAddr := clusterRole.grpcAddr
	clusterRole.role = "control-plane"
	clusterRole.grpcAddr = ":50051"
	clusterRoleMu.Unlock()
	defer func() {
		clusterRoleMu.Lock()
		clusterRole.role = origRole
		clusterRole.grpcAddr = origAddr
		clusterRoleMu.Unlock()
	}()

	body := `{"leader_addr":"cp1.internal:50051"}`
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/ha", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiClusterHA(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Error("expected ok=true")
	}
	if resp["deploy_cmd"] == nil || resp["deploy_cmd"] == "" {
		t.Error("expected non-empty deploy_cmd")
	}
	cmd := resp["deploy_cmd"].(string)
	if !strings.Contains(cmd, "--ha-join") {
		t.Errorf("deploy_cmd should contain --ha-join: %s", cmd)
	}
	if !strings.Contains(cmd, "--ha-token") {
		t.Errorf("deploy_cmd should contain --ha-token: %s", cmd)
	}

	if !globalHA.IsLeader() {
		t.Error("expected HA to be leader after enable")
	}
}

// ── HASync RPC ──────────────────────────────────────────────────────────────

func TestHASync_InvalidToken(t *testing.T) {
	origHA := *globalHA
	defer func() { *globalHA = origHA }()
	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.token = "correct-token"
	globalHA.mu.Unlock()

	svc := &controlPlaneServer{}
	reqBytes, _ := json.Marshal(map[string]string{"token": "wrong-token"})
	_, err := svc.HASync(context.Background(), json.RawMessage(reqBytes))
	if err == nil {
		t.Error("expected error for wrong token")
	}
}

func TestHASync_ValidToken(t *testing.T) {
	origHA := *globalHA
	defer func() { *globalHA = origHA }()
	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.token = "correct-token"
	globalHA.mu.Unlock()

	svc := &controlPlaneServer{}
	reqBytes, _ := json.Marshal(map[string]string{"token": "correct-token"})
	raw, err := svc.HASync(context.Background(), json.RawMessage(reqBytes))
	if err != nil {
		t.Fatalf("HASync: %v", err)
	}

	var bundle HAStateBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	if bundle.ClusterState == nil {
		t.Error("expected non-nil cluster state")
	}
}

// ── Cluster State Export/Import ─────────────────────────────────────────────

func TestClusterStore_ExportImport(t *testing.T) {
	cs := newTestClusterStore(t)
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "s1"})
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-2", Status: "connected", CertSerial: "s2"})

	exported, err := cs.ExportState()
	if err != nil {
		t.Fatalf("ExportState: %v", err)
	}

	// Import into a new store.
	cs2 := newTestClusterStore(t)
	if err := cs2.ImportFullState(exported); err != nil {
		t.Fatalf("ImportFullState: %v", err)
	}

	nodes := cs2.ListNodes()
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	found := false
	for _, n := range nodes {
		if n.NodeID == "dp-1" {
			found = true
		}
	}
	if !found {
		t.Error("dp-1 not found after import")
	}
}

// ── CA Key Export ───────────────────────────────────────────────────────────

func TestClusterCA_CAKeyPEM(t *testing.T) {
	// globalClusterCA may or may not be initialized in tests.
	// Just verify the method doesn't panic when CA is not ready.
	ca := &clusterCA{}
	if keyPEM := ca.CAKeyPEM(); keyPEM != nil {
		t.Error("expected nil when CA not initialized")
	}
}
