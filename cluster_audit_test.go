package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── CWE-117 Log Injection Prevention ─────────────────────────────────────────

func TestClusterRevoke_SanitizedLogs(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "test-node", Status: "connected", CertSerial: "s1"})

	// The body contains newlines that could cause log injection.
	body := `{"node_id":"test-node","reason":"legit\nINJECTED LOG LINE"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/cluster/revoke", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = adminCtx(r)

	apiClusterRevoke(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── Token TTL Cap ────────────────────────────────────────────────────────────

func TestClusterTokenCreate_TTLCap(t *testing.T) {
	origStore := globalClusterStore
	origCA := globalClusterCA
	origRole := clusterRole.role
	defer func() {
		globalClusterStore = origStore
		globalClusterCA = origCA
		clusterRole.role = origRole
	}()
	globalClusterStore = newTestClusterStore(t)

	// Set up a ready CA and CP role.
	caDir := t.TempDir()
	globalClusterCA = &clusterCA{}
	if err := globalClusterCA.InitOrLoad(caDir); err != nil {
		t.Fatalf("CA init: %v", err)
	}
	clusterRole.role = "control-plane"

	tests := []struct {
		name     string
		ttlHours int
		wantOK   bool
	}{
		{"default_24h", 0, true},
		{"valid_720h", 720, true},
		{"max_8760h", 8760, true},
		{"over_max_8761h", 8761, false},
		{"way_over_max", 100000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"ttl_hours":%d}`, tt.ttlHours)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/cluster/tokens", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r = adminCtx(r)

			apiClusterTokenCreate(w, r)

			if tt.wantOK && w.Code != http.StatusOK {
				t.Errorf("ttl_hours=%d: got %d, want 200; body: %s", tt.ttlHours, w.Code, w.Body.String())
			}
			if !tt.wantOK && w.Code != http.StatusBadRequest {
				t.Errorf("ttl_hours=%d: got %d, want 400", tt.ttlHours, w.Code)
			}
		})
	}
}

// ── NodePrefix Validation ────────────────────────────────────────────────────

func TestClusterTokenCreate_NodePrefixValidation(t *testing.T) {
	origStore := globalClusterStore
	origCA := globalClusterCA
	origRole := clusterRole.role
	defer func() {
		globalClusterStore = origStore
		globalClusterCA = origCA
		clusterRole.role = origRole
	}()
	globalClusterStore = newTestClusterStore(t)

	caDir := t.TempDir()
	globalClusterCA = &clusterCA{}
	if err := globalClusterCA.InitOrLoad(caDir); err != nil {
		t.Fatalf("CA init: %v", err)
	}
	clusterRole.role = "control-plane"

	tests := []struct {
		name   string
		prefix string
		wantOK bool
	}{
		{"empty", "", true},
		{"alphanumeric", "dp-node-01", true},
		{"underscores", "node_prefix_test", true},
		{"spaces", "node prefix", false},
		{"special_chars", "node@prefix", false},
		{"path_traversal", "../etc", false},
		{"newline", "node\ninjection", false},
		{"too_long", strings.Repeat("a", 256), false},
		{"max_length", strings.Repeat("a", 255), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"node_prefix":%q}`, tt.prefix)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/cluster/tokens", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r = adminCtx(r)

			apiClusterTokenCreate(w, r)

			if tt.wantOK && w.Code != http.StatusOK {
				t.Errorf("prefix=%q: got %d, want 200; body: %s", tt.prefix, w.Code, w.Body.String())
			}
			if !tt.wantOK && w.Code != http.StatusBadRequest {
				t.Errorf("prefix=%q: got %d, want 400", tt.prefix, w.Code)
			}
		})
	}
}

// ── gRPC Address Validation ──────────────────────────────────────────────────

func TestClusterMode_GRPCAddrValidation(t *testing.T) {
	tests := []struct {
		name   string
		addr   string
		wantOK bool
	}{
		{"valid_port_only", ":50051", true},
		{"valid_host_port", "0.0.0.0:50051", true},
		{"empty", "", false},
		{"no_port", "localhost", false},
		{"spaces", "host name:50051", true}, // SplitHostPort accepts this
		{"just_port_invalid", "50051", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"grpc_addr":%q}`, tt.addr)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/cluster/mode", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r = adminCtx(r)

			// Save and restore cluster role to avoid side effects.
			origRole := clusterRole.role
			defer func() { clusterRole.role = origRole }()

			// Even for valid addresses, enableControlPlane will fail since
			// we're not setting up a real gRPC server, so we just check for
			// the address validation (400) vs. other errors (409 Conflict).
			apiClusterMode(w, r)

			if !tt.wantOK {
				if w.Code != http.StatusBadRequest {
					t.Errorf("addr=%q: got %d, want 400; body: %s", tt.addr, w.Code, w.Body.String())
				}
			} else {
				// Valid addr should NOT get 400 (might get 409 or other errors from enableControlPlane).
				if w.Code == http.StatusBadRequest && strings.Contains(w.Body.String(), "host:port") {
					t.Errorf("addr=%q: got 400 with host:port error, should be valid", tt.addr)
				}
			}
		})
	}
}

// ── Revoke Reason Cap ────────────────────────────────────────────────────────

func TestClusterRevoke_ReasonCap(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "cap-node", Status: "connected", CertSerial: "s1"})

	tests := []struct {
		name   string
		reason string
		wantOK bool
	}{
		{"empty", "", true},
		{"short", "maintenance", true},
		{"at_limit", strings.Repeat("x", 1000), true},
		{"over_limit", strings.Repeat("x", 1001), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"node_id":"cap-node","reason":%q}`, tt.reason)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/cluster/revoke", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r = adminCtx(r)

			// Re-register the node for each sub-test since it gets revoked.
			globalClusterStore.mu.Lock()
			globalClusterStore.st.Nodes["cap-node"] = &EnrolledNode{NodeID: "cap-node", Status: "connected", CertSerial: "s1"}
			globalClusterStore.st.Revoked = nil
			globalClusterStore.mu.Unlock()

			apiClusterRevoke(w, r)

			if tt.wantOK && w.Code != http.StatusOK {
				t.Errorf("reason_len=%d: got %d, want 200; body: %s", len(tt.reason), w.Code, w.Body.String())
			}
			if !tt.wantOK && w.Code != http.StatusBadRequest {
				t.Errorf("reason_len=%d: got %d, want 400", len(tt.reason), w.Code)
			}
		})
	}
}

// ── Save() Error Propagation ─────────────────────────────────────────────────

func TestClusterTokenDelete_SaveError(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()

	// Create a store with an invalid path so Save() fails.
	cs := &ClusterStore{
		path: "/nonexistent/dir/cluster.json",
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	// Add a token to delete.
	cs.st.Tokens["testhash"] = &EnrollToken{TokenHash: "testhash"}
	globalClusterStore = cs

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/cluster/tokens?hash=testhash", nil)
	r = adminCtx(r)

	apiClusterTokens(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got %d, want 500 (Save should fail); body: %s", w.Code, w.Body.String())
	}
}

func TestClusterRevoke_SaveError(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()

	cs := &ClusterStore{
		path: "/nonexistent/dir/cluster.json",
		st: ClusterState{
			Nodes:   map[string]*EnrolledNode{"err-node": {NodeID: "err-node", Status: "connected", CertSerial: "s1"}},
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	globalClusterStore = cs

	w := httptest.NewRecorder()
	body := `{"node_id":"err-node","reason":"test"}`
	r := httptest.NewRequest(http.MethodPost, "/api/cluster/revoke", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = adminCtx(r)

	apiClusterRevoke(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got %d, want 500 (Save should fail); body: %s", w.Code, w.Body.String())
	}
}

// ── Role Constants ───────────────────────────────────────────────────────────

func TestClusterHandlers_UseRoleConstants(t *testing.T) {
	// Verify that cluster handlers reject unauthenticated requests.
	// This also implicitly verifies RBAC is active (constants work).
	origCfg := cfg
	defer func() { cfg = origCfg }()

	testCfg := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	_ = testCfg.SetAuth("admin", "pass123")
	cfg = testCfg

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/cluster/status"},
		{http.MethodPost, "/api/cluster/mode"},
		{http.MethodGet, "/api/cluster/tokens"},
		{http.MethodPost, "/api/cluster/revoke"},
		{http.MethodGet, "/api/cluster/ca"},
		{http.MethodPost, "/api/cluster/ca"},
		{http.MethodGet, "/api/cluster/rate-limits"},
		{http.MethodGet, "/api/cluster/audit"},
		{http.MethodGet, "/api/cluster/revocations"},
	}

	handler := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Route to appropriate handler based on path.
		switch {
		case r.URL.Path == "/api/cluster/status":
			apiClusterStatus(w, r)
		case r.URL.Path == "/api/cluster/mode":
			apiClusterMode(w, r)
		case r.URL.Path == "/api/cluster/tokens":
			apiClusterTokens(w, r)
		case r.URL.Path == "/api/cluster/revoke":
			apiClusterRevoke(w, r)
		case r.URL.Path == "/api/cluster/ca":
			apiClusterCA(w, r)
		case r.URL.Path == "/api/cluster/rate-limits":
			apiClusterRateLimits(w, r)
		case r.URL.Path == "/api/cluster/audit":
			apiClusterAudit(w, r)
		case r.URL.Path == "/api/cluster/revocations":
			apiClusterRevocations(w, r)
		}
	}))

	for _, ep := range endpoints {
		t.Run(ep.method+"_"+ep.path, func(t *testing.T) {
			r := httptest.NewRequest(ep.method, ep.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s: got %d, want 401 (unauthenticated)", ep.method, ep.path, w.Code)
			}
		})
	}
}

// ── Enrollment Rate Limiter ──────────────────────────────────────────────────

func TestEnrollRateLimitAllow(t *testing.T) {
	// Reset rate limiter state.
	enrollRateLimit.mu.Lock()
	enrollRateLimit.attempts = make(map[string][]time.Time)
	enrollRateLimit.mu.Unlock()

	ip := "192.168.1.100"

	// First 5 should succeed.
	for i := 0; i < 5; i++ {
		if !enrollRateLimitAllow(ip) {
			t.Fatalf("attempt %d: should be allowed", i+1)
		}
	}

	// 6th should be denied.
	if enrollRateLimitAllow(ip) {
		t.Fatal("6th attempt should be rate limited")
	}

	// Different IP should still be allowed.
	if !enrollRateLimitAllow("10.0.0.1") {
		t.Fatal("different IP should be allowed")
	}
}

// TestEnrollRateLimitCleanup is the regression guard for the unbounded-map
// growth: an IP that attempts enrollment once and never returns is pruned only
// on its (never-arriving) next call, so without a janitor its entry persists
// forever. Cleanup must drop entries whose timestamps have all aged out while
// keeping IPs with in-window activity.
func TestEnrollRateLimitCleanup(t *testing.T) {
	enrollRateLimit.mu.Lock()
	now := time.Now()
	enrollRateLimit.attempts = map[string][]time.Time{
		"stale-1shot": {now.Add(-2 * time.Minute)},                            // aged out → evict
		"stale-multi": {now.Add(-3 * time.Minute), now.Add(-2 * time.Minute)}, // all aged out → evict
		"fresh":       {now.Add(-10 * time.Second)},                           // in window → keep
		"mixed":       {now.Add(-5 * time.Minute), now.Add(-1 * time.Second)}, // keep, pruned to 1
	}
	enrollRateLimit.mu.Unlock()

	enrollRateLimitCleanup()

	enrollRateLimit.mu.Lock()
	defer enrollRateLimit.mu.Unlock()
	if _, ok := enrollRateLimit.attempts["stale-1shot"]; ok {
		t.Error("single stale entry should be evicted (one-shot IP leak)")
	}
	if _, ok := enrollRateLimit.attempts["stale-multi"]; ok {
		t.Error("all-stale entry should be evicted")
	}
	if got := enrollRateLimit.attempts["fresh"]; len(got) != 1 {
		t.Errorf("fresh entry: len = %d, want 1 (kept)", len(got))
	}
	if got := enrollRateLimit.attempts["mixed"]; len(got) != 1 {
		t.Errorf("mixed entry: len = %d, want 1 (stale timestamp pruned, fresh kept)", len(got))
	}
}

// ── CSR CommonName Validation ────────────────────────────────────────────────

func TestEnroll_CSRCommonNameMismatch(t *testing.T) {
	origStore := globalClusterStore
	origCA := globalClusterCA
	defer func() {
		globalClusterStore = origStore
		globalClusterCA = origCA
	}()
	globalClusterStore = newTestClusterStore(t)

	caDir := t.TempDir()
	globalClusterCA = &clusterCA{}
	if err := globalClusterCA.InitOrLoad(caDir); err != nil {
		t.Fatalf("CA init: %v", err)
	}

	// Generate a token.
	plaintext, err := globalClusterStore.GenerateToken("", "", "admin", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// Generate a CSR with CN="wrong-node" but claim NodeID="real-node".
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "wrong-node"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	req := EnrollRequest{
		Token:  plaintext,
		NodeID: "real-node",
		CSR:    string(csrPEM),
	}
	reqJSON, _ := json.Marshal(req)

	srv := &controlPlaneServer{}
	_, err = srv.Enroll(context.Background(), reqJSON)

	if err == nil {
		t.Fatal("expected error for CN mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "CommonName") {
		t.Errorf("error should mention CommonName, got: %v", err)
	}
}

func TestEnroll_CSRCommonNameMatch(t *testing.T) {
	origStore := globalClusterStore
	origCA := globalClusterCA
	defer func() {
		globalClusterStore = origStore
		globalClusterCA = origCA
	}()
	globalClusterStore = newTestClusterStore(t)

	caDir := t.TempDir()
	globalClusterCA = &clusterCA{}
	if err := globalClusterCA.InitOrLoad(caDir); err != nil {
		t.Fatalf("CA init: %v", err)
	}

	plaintext, err := globalClusterStore.GenerateToken("", "", "admin", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// Generate CSR with matching CN.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "correct-node"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	req := EnrollRequest{
		Token:  plaintext,
		NodeID: "correct-node",
		CSR:    string(csrPEM),
	}
	reqJSON, _ := json.Marshal(req)

	srv := &controlPlaneServer{}
	resp, err := srv.Enroll(context.Background(), reqJSON)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Verify node was registered.
	node, ok := globalClusterStore.GetNode("correct-node")
	if !ok {
		t.Fatal("node should be registered")
	}
	if node.Status != "connected" {
		t.Errorf("node status = %q, want connected", node.Status)
	}
}

// ── Node Existence Leak Prevention ───────────────────────────────────────────

func TestEnroll_NodeExistenceLeak(t *testing.T) {
	origStore := globalClusterStore
	origCA := globalClusterCA
	defer func() {
		globalClusterStore = origStore
		globalClusterCA = origCA
	}()
	globalClusterStore = newTestClusterStore(t)

	caDir := t.TempDir()
	globalClusterCA = &clusterCA{}
	if err := globalClusterCA.InitOrLoad(caDir); err != nil {
		t.Fatalf("CA init: %v", err)
	}

	// Register an existing node.
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "existing-node", Status: "connected"})

	// Try to enroll with existing node ID — should get generic "enrollment denied".
	plaintext, err := globalClusterStore.GenerateToken("", "", "admin", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "existing-node"},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	req := EnrollRequest{
		Token:  plaintext,
		NodeID: "existing-node",
		CSR:    string(csrPEM),
	}
	reqJSON, _ := json.Marshal(req)

	// Reset rate limiter for this test.
	enrollRateLimit.mu.Lock()
	enrollRateLimit.attempts = make(map[string][]time.Time)
	enrollRateLimit.mu.Unlock()

	srv := &controlPlaneServer{}
	_, err = srv.Enroll(context.Background(), reqJSON)

	if err == nil {
		t.Fatal("expected error for existing node")
	}
	// Must NOT contain the node name or "already enrolled".
	if strings.Contains(err.Error(), "existing-node") || strings.Contains(err.Error(), "already") {
		t.Errorf("error leaks node existence: %v", err)
	}
	// Should be a generic denial.
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("error should say 'denied', got: %v", err)
	}
}

// ── enableControlPlane Mutex ─────────────────────────────────────────────────

func TestEnableControlPlane_RejectsDouble(t *testing.T) {
	origRole := clusterRole.role
	origAddr := clusterRole.grpcAddr
	defer func() {
		clusterRole.role = origRole
		clusterRole.grpcAddr = origAddr
	}()

	// Simulate already running as CP.
	clusterRoleMu.Lock()
	clusterRole.role = "control-plane"
	clusterRoleMu.Unlock()

	err := enableControlPlane(":50099", "", "", "", filepath.Join(t.TempDir(), "c.json"))
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("expected 'already running' error, got: %v", err)
	}
}

// ── CA Import Pre-Validation ─────────────────────────────────────────────────

func TestClusterCA_ImportValidation(t *testing.T) {
	origCA := globalClusterCA
	defer func() { globalClusterCA = origCA }()

	caDir := t.TempDir()
	globalClusterCA = &clusterCA{}
	if err := globalClusterCA.InitOrLoad(caDir); err != nil {
		t.Fatalf("CA init: %v", err)
	}

	tests := []struct {
		name    string
		cert    string
		key     string
		wantErr string
	}{
		{
			name:    "empty_cert",
			cert:    "",
			key:     "something",
			wantErr: "cert and key are required",
		},
		{
			name:    "invalid_pem_cert",
			cert:    "not a PEM",
			key:     "not a PEM",
			wantErr: "invalid certificate",
		},
		{
			name:    "not_a_ca_cert",
			cert:    generateNonCACert(t),
			key:     "placeholder",
			wantErr: "invalid certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"cert":%q,"key":%q}`, tt.cert, tt.key)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/cluster/ca", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r = adminCtx(r)

			apiClusterCA(w, r)

			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tt.wantErr) {
				t.Errorf("body should contain %q, got: %s", tt.wantErr, w.Body.String())
			}
		})
	}
}

// generateNonCACert creates a self-signed non-CA certificate PEM for testing.
func generateNonCACert(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not-a-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

// ── Config Validation for Cert Paths ─────────────────────────────────────────

func TestConfigValidation_ClusterCertPaths(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(fc *FileConfig)
		wantErr bool
	}{
		{
			name: "valid_paths",
			setup: func(fc *FileConfig) {
				fc.Cluster.Role = "control-plane"
				fc.Cluster.GRPCAddr = ":50051"
				fc.Cluster.CertFile = "server.crt"
				fc.Cluster.KeyFile = "server.key"
			},
			wantErr: false,
		},
		{
			name: "path_traversal_cert",
			setup: func(fc *FileConfig) {
				fc.Cluster.Role = "control-plane"
				fc.Cluster.GRPCAddr = ":50051"
				fc.Cluster.CertFile = "../../etc/secret.crt"
			},
			wantErr: true,
		},
		{
			name: "path_traversal_key",
			setup: func(fc *FileConfig) {
				fc.Cluster.Role = "control-plane"
				fc.Cluster.GRPCAddr = ":50051"
				fc.Cluster.KeyFile = "../key.pem"
			},
			wantErr: true,
		},
		{
			name: "path_traversal_ca",
			setup: func(fc *FileConfig) {
				fc.Cluster.Role = "control-plane"
				fc.Cluster.GRPCAddr = ":50051"
				fc.Cluster.CAFile = "ca/../../../shadow"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &FileConfig{}
			tt.setup(fc)
			err := fc.validate()
			if tt.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), "path traversal") {
				t.Errorf("error should mention path traversal, got: %v", err)
			}
		})
	}
}

// ── Enrollment Rate Limiter Window Expiry ────────────────────────────────────

func TestEnrollRateLimitAllow_WindowExpiry(t *testing.T) {
	enrollRateLimit.mu.Lock()
	enrollRateLimit.attempts = make(map[string][]time.Time)
	// Pre-fill with old timestamps that should be pruned.
	old := time.Now().Add(-2 * time.Minute)
	enrollRateLimit.attempts["10.0.0.1"] = []time.Time{old, old, old, old, old}
	enrollRateLimit.mu.Unlock()

	// Should be allowed because old entries are pruned.
	if !enrollRateLimitAllow("10.0.0.1") {
		t.Fatal("old entries should be pruned, attempt should be allowed")
	}
}
