package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// swapGlobalHA replaces globalHA with a fresh HAState and returns a cleanup
// function that restores the original pointer. This avoids copying the
// sync.RWMutex (which go vet forbids).
func swapGlobalHA(t *testing.T) func() {
	t.Helper()
	orig := globalHA
	globalHA = &HAState{}
	return func() { globalHA = orig }
}

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

// TestHAState_Status_PromotedLeaderOmitsStaleSyncFailCount pins a promotion-race
// scenario: onMaxFail's auto-failover path calls setFail(N) (recording the
// failure streak that triggered promotion) and only afterwards does promote()
// flip h.role to "leader" — nothing resets syncFailCount in between. Status()
// must not let that stale standby-side counter leak onto a leader's status,
// since apiClusterStatus (ui_cluster.go) embeds Status() verbatim regardless
// of role, unlike apiClusterHA which additionally gates on role itself.
func TestHAState_Status_PromotedLeaderOmitsStaleSyncFailCount(t *testing.T) {
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.syncFailCount = haStandbyMaxFail // simulates setFail(N) just before promote()
	h.mu.Unlock()

	h.mu.Lock()
	h.role = "leader" // promote() flips role; syncFailCount is left as-is
	h.mu.Unlock()

	s := h.Status()
	if s.Role != "leader" {
		t.Fatalf("expected leader, got %q", s.Role)
	}
	if s.SyncFailCount != 0 {
		t.Errorf("promoted leader must not report a stale standby sync_fail_count, got %d", s.SyncFailCount)
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
	token, err := h.EnableAsLeader("cp2:50051", false)
	if err != nil {
		t.Fatalf("EnableAsLeader: %v", err)
	}

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
	// ADR-0004: auto-failover is OFF unless explicitly enabled.
	if h.autoFailoverEnabled() {
		t.Error("auto-failover must default to OFF")
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
	defer swapGlobalHA(t)()

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
	defer swapGlobalHA(t)()
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
	defer swapGlobalHA(t)()
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
	defer swapGlobalHA(t)()
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

func TestAPIClusterHA_GET_StandbySyncHealth(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA.mu.Lock()
	globalHA.role = "standby"
	globalHA.peerAddr = "cp1:50051"
	globalHA.since = time.Now()
	globalHA.syncFailCount = 2
	globalHA.lastSyncOK = time.Now().Add(-30 * time.Second)
	globalHA.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/ha", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleViewer))
	w := httptest.NewRecorder()
	apiClusterHA(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["role"] != "standby" {
		t.Fatalf("expected standby, got %v", resp["role"])
	}
	failCount, _ := resp["sync_fail_count"].(float64)
	if int(failCount) != 2 {
		t.Errorf("expected sync_fail_count=2, got %v", resp["sync_fail_count"])
	}
	maxFail, _ := resp["sync_max_fail"].(float64)
	if int(maxFail) != haStandbyMaxFail {
		t.Errorf("expected sync_max_fail=%d, got %v", haStandbyMaxFail, resp["sync_max_fail"])
	}
	if resp["last_sync_ok"] == nil || resp["last_sync_ok"] == "" {
		t.Error("expected non-empty last_sync_ok")
	}
	if resp["deploy_cmd"] != nil {
		t.Error("standby should not carry a leader-only deploy_cmd")
	}
}

func TestAPIClusterHA_GET_LeaderOmitsStandbySyncFields(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.since = time.Now()
	globalHA.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/ha", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleViewer))
	w := httptest.NewRecorder()
	apiClusterHA(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["sync_fail_count"]; ok {
		t.Error("leader response should not carry standby-only sync_fail_count")
	}
}

func TestStandbyLoopState_SetFail_MirrorsOntoHAState(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA.mu.Lock()
	globalHA.role = "standby" // Status() only surfaces SyncFailCount for a standby
	globalHA.mu.Unlock()
	s := &standbyLoopState{h: globalHA}

	s.setFail(2)
	if got := globalHA.Status().SyncFailCount; got != 2 {
		t.Errorf("expected HAState.syncFailCount=2, got %d", got)
	}

	s.setFail(0)
	if got := globalHA.Status().SyncFailCount; got != 0 {
		t.Errorf("expected HAState.syncFailCount=0 after reset, got %d", got)
	}
}

func TestAPIClusterHA_EnableRequiresCP(t *testing.T) {
	defer swapGlobalHA(t)()

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
	cleanup := swapGlobalHA(t)
	origPath := clusterDBPathGlobal
	clusterDBPathGlobal = t.TempDir() + "/cluster.json"
	defer func() {
		globalHA.Stop()
		cleanup()
		clusterDBPathGlobal = origPath
	}()

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
	defer swapGlobalHA(t)()
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
	defer swapGlobalHA(t)()
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

// ── HA encrypt/decrypt (1.6 fix) ──────────────────────────────────────────

func TestHAEncryptDecryptKey(t *testing.T) {
	token := "my-ha-secret-token-12345"
	plaintext := []byte("-----BEGIN EC PRIVATE KEY-----\nfake-key-data\n-----END EC PRIVATE KEY-----\n")

	encrypted, err := haEncryptKey(plaintext, token)
	if err != nil {
		t.Fatalf("haEncryptKey: %v", err)
	}
	if encrypted == "" {
		t.Fatal("expected non-empty encrypted string")
	}

	decrypted, err := haDecryptKey(encrypted, token)
	if err != nil {
		t.Fatalf("haDecryptKey: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}

	// Wrong token should fail.
	_, err = haDecryptKey(encrypted, "wrong-token")
	if err == nil {
		t.Error("expected error with wrong token")
	}
}

func TestHASync_EncryptsCAKey(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.token = "test-token-123"
	globalHA.mu.Unlock()

	svc := &controlPlaneServer{}
	reqBytes, _ := json.Marshal(map[string]string{"token": "test-token-123"})
	raw, err := svc.HASync(context.Background(), json.RawMessage(reqBytes))
	if err != nil {
		t.Fatalf("HASync: %v", err)
	}

	var bundle HAStateBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	// CA-3 PR5: the plaintext CA key field is removed entirely. Assert the wire
	// payload carries no ca_key_pem field at all (stronger than "empty").
	if bytes.Contains(raw, []byte("ca_key_pem")) {
		t.Error("HA bundle wire payload must not contain a ca_key_pem field (plaintext fallback removed)")
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
	ca := &clusterCA{}
	if keyPEM := ca.CAKeyPEM(); keyPEM != nil {
		t.Error("expected nil when CA not initialized")
	}
}

// ── DP Auto-Discovery of CP Addresses ───────────────────────────────────────

func TestUpdateDPAddresses(t *testing.T) {
	c := &DataPlaneClient{
		addrs: []string{"cp1:50051"},
	}
	activeDPClient.Store(c)
	defer activeDPClient.Store(nil)

	updateDPAddresses([]string{"cp1:50051", "cp2:50051"})

	c.mu.Lock()
	got := c.addrs
	c.mu.Unlock()

	if len(got) != 2 {
		t.Fatalf("expected 2 addrs, got %d", len(got))
	}
	if got[0] != "cp1:50051" || got[1] != "cp2:50051" {
		t.Errorf("unexpected addrs: %v", got)
	}
}

func TestUpdateDPAddresses_NoChange(t *testing.T) {
	c := &DataPlaneClient{
		addrs: []string{"cp1:50051", "cp2:50051"},
	}
	activeDPClient.Store(c)
	defer activeDPClient.Store(nil)

	updateDPAddresses([]string{"cp1:50051", "cp2:50051"})

	c.mu.Lock()
	got := c.addrs
	c.mu.Unlock()

	if len(got) != 2 {
		t.Fatalf("expected 2 addrs, got %d", len(got))
	}
}

func TestBuildCPAddressList_NoHA(t *testing.T) {
	defer swapGlobalHA(t)()

	addrs := buildCPAddressList()
	if addrs != nil {
		t.Errorf("expected nil when HA disabled, got %v", addrs)
	}
}

func TestBuildCPAddressList_WithHA(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.peerAddr = "cp1.internal:50051"
	globalHA.mu.Unlock()

	clusterRoleMu.Lock()
	origAddr := clusterRole.grpcAddr
	clusterRole.grpcAddr = ":50051"
	clusterRoleMu.Unlock()
	defer func() {
		clusterRoleMu.Lock()
		clusterRole.grpcAddr = origAddr
		clusterRoleMu.Unlock()
	}()

	addrs := buildCPAddressList()
	if len(addrs) < 1 {
		t.Fatal("expected at least 1 address")
	}
	if addrs[0] != "cp1.internal:50051" {
		t.Errorf("expected cp1.internal:50051 first, got %v", addrs)
	}
}

func TestSlicesEqual(t *testing.T) {
	if !slicesEqual([]string{"a", "b"}, []string{"a", "b"}) {
		t.Error("expected equal")
	}
	if slicesEqual([]string{"a"}, []string{"a", "b"}) {
		t.Error("expected not equal (different length)")
	}
	if slicesEqual([]string{"a", "b"}, []string{"a", "c"}) {
		t.Error("expected not equal (different content)")
	}
}
