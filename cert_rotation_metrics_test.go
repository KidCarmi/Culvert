package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// TestCARotationCounter_AutoRotateIncrements: a successful auto-rotation
// (RotateIfNeeded) bumps culvert_ca_rotations_total. Forces near-expiry on a
// fresh CertManager so rotation fires; caPath="" skips SaveCA (no disk).
func TestCARotationCounter_AutoRotateIncrements(t *testing.T) {
	cm := ca.New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	cm.CACertForTest().NotAfter = time.Now().Add(24 * time.Hour) // within caRotationOverlap

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
	cm := ca.New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if got := statCARotations.Load(); got != before {
		t.Errorf("culvert_ca_rotations_total = %d, want %d (InitCA must not count as a rotation)", got, before)
	}
}

// TestCARotationCounter_ManualRotateIncrements: the fenced, challenge-bound
// apiCARotate admin flow (FE-6B.0) bumps culvert_ca_rotations_total on a
// DURABLE rotation, and only then.
func TestCARotationCounter_ManualRotateIncrements(t *testing.T) {
	fe6b0Node(t)
	mux := fe6b0Mux()
	before := statCARotations.Load()
	if _, m := fe6b0RotateOK(t, mux, fe6b0OpID()); m["persisted"] != true {
		t.Fatalf("rotation result = %v", m)
	}
	if got := statCARotations.Load(); got != before+1 {
		t.Errorf("culvert_ca_rotations_total = %d, want %d after manual rotation", got, before+1)
	}
}

// TestClusterCARotationCounter_ImportCAIncrements: the cluster ImportCA
// chokepoint (shared by auto-rotation and manual import) bumps
// culvert_cluster_ca_rotations_total.
func TestClusterCARotationCounter_ImportCAIncrements(t *testing.T) {
	cca := &clusterCA{}
	if err := cca.InitOrLoad(t.TempDir()); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	before := statClusterCARotations.Load()
	newCertPEM, newKeyPEM := seedClusterCAFiles(t)
	if err := cca.ImportCA(newCertPEM, newKeyPEM); err != nil {
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
	cm := ca.New()
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
