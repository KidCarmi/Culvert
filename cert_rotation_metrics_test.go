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

// TestCARotationCounter_AutoRotateIncrements: a successful auto-rotation
// (RotateIfNeeded) bumps culvert_ca_rotations_total. Forces near-expiry on a
// fresh CertManager so rotation fires; caPath="" skips SaveCA (no disk).
func TestCARotationCounter_AutoRotateIncrements(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	cm.caCert.NotAfter = time.Now().Add(24 * time.Hour) // within caRotationOverlap

	before := statCARotations.Load()
	if !cm.RotateIfNeeded("", "") {
		t.Fatal("RotateIfNeeded should have rotated a near-expiry CA")
	}
	if got := statCARotations.Load(); got != before+1 {
		t.Errorf("culvert_ca_rotations_total = %d, want %d after auto-rotation", got, before+1)
	}
}

// TestCARotationCounter_InitCADoesNotIncrement: plain InitCA (startup/init) must
// NOT bump the rotation counter — only real rotation paths do.
func TestCARotationCounter_InitCADoesNotIncrement(t *testing.T) {
	before := statCARotations.Load()
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if got := statCARotations.Load(); got != before {
		t.Errorf("culvert_ca_rotations_total = %d, want %d (InitCA must not count as a rotation)", got, before)
	}
}

// TestCARotationCounter_ManualRotateIncrements: the two-step apiCARotate admin
// flow bumps culvert_ca_rotations_total on confirmed rotation.
func TestCARotationCounter_ManualRotateIncrements(t *testing.T) {
	oldMgr := certMgr
	oldPath := caRuntime.path
	t.Cleanup(func() {
		certMgr = oldMgr
		caRuntime.path = oldPath
	})
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	certMgr = cm
	caRuntime.path = "" // skip SaveCA → no disk

	admin := func(body string) *http.Request {
		r := httptest.NewRequestWithContext(
			context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin),
			http.MethodPost, "/api/ca/rotate", bytes.NewReader([]byte(body)))
		return r
	}

	// Step 1: request a confirmation token (no rotation yet).
	w1 := httptest.NewRecorder()
	apiCARotate(w1, admin("{}"))
	if w1.Code != http.StatusOK {
		t.Fatalf("step 1 status = %d, want 200", w1.Code)
	}
	var resp struct {
		Token string `json:"confirmation_token"`
	}
	if err := json.Unmarshal(w1.Body.Bytes(), &resp); err != nil || resp.Token == "" {
		t.Fatalf("step 1 did not return a confirmation_token: err=%v body=%s", err, w1.Body.String())
	}

	// Step 2: confirm → rotation should occur and increment the counter.
	before := statCARotations.Load()
	w2 := httptest.NewRecorder()
	apiCARotate(w2, admin(`{"confirm":true,"confirmation_token":"`+resp.Token+`"}`))
	if w2.Code != http.StatusOK {
		t.Fatalf("step 2 status = %d, want 200 (body=%s)", w2.Code, w2.Body.String())
	}
	if got := statCARotations.Load(); got != before+1 {
		t.Errorf("culvert_ca_rotations_total = %d, want %d after manual rotation", got, before+1)
	}
}

// TestClusterCARotationCounter_ImportCAIncrements: the cluster ImportCA
// chokepoint (shared by auto-rotation and manual import) bumps
// culvert_cluster_ca_rotations_total.
func TestClusterCARotationCounter_ImportCAIncrements(t *testing.T) {
	ca := &clusterCA{}
	if err := ca.InitOrLoad(t.TempDir()); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	before := statClusterCARotations.Load()
	newCertPEM, newKeyPEM := seedClusterCAFiles(t)
	if err := ca.ImportCA(newCertPEM, newKeyPEM); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	if got := statClusterCARotations.Load(); got != before+1 {
		t.Errorf("culvert_cluster_ca_rotations_total = %d, want %d after ImportCA", got, before+1)
	}
}

// TestCARotationMetrics_Rendered: /metrics exposes both rotation counter
// families with their HELP/TYPE lines and current values.
func TestCARotationMetrics_Rendered(t *testing.T) {
	oldTok := metricsToken
	oldMgr := certMgr
	t.Cleanup(func() {
		metricsToken = oldTok
		certMgr = oldMgr
	})
	metricsToken = ""
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	certMgr = cm

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", http.NoBody)
	handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("handleMetrics status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_ca_rotations_total counter",
		"culvert_ca_rotations_total ",
		"# TYPE culvert_cluster_ca_rotations_total counter",
		"culvert_cluster_ca_rotations_total ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}
