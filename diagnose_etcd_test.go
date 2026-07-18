package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// TestClassifyEtcdProbe drives every branch of the pure classifier without an
// etcd: not-configured, reachable-with-holder, reachable-free, and unreachable.
func TestClassifyEtcdProbe(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	t.Run("not configured", func(t *testing.T) {
		d := classifyEtcdProbe(false, halease.Status{}, 0, nil, now)
		if d.Configured || !d.OK || d.Status != "n/a" {
			t.Fatalf("not-configured: got configured=%v ok=%v status=%q", d.Configured, d.OK, d.Status)
		}
		if d.Reachable || d.Error != "" {
			t.Fatalf("not-configured must not report reachability/error: %+v", d)
		}
	})

	t.Run("reachable with holder", func(t *testing.T) {
		st := halease.Status{Holder: "cp-1", Epoch: 42, ValidFor: 3 * time.Second}
		d := classifyEtcdProbe(true, st, 12*time.Millisecond, nil, now)
		if !d.Configured || !d.OK || !d.Reachable || d.Status != "ok" {
			t.Fatalf("reachable: got %+v", d)
		}
		if d.Holder != "cp-1" || d.Epoch != 42 || d.ValidForMs != 3000 || d.LatencyMs != 12 {
			t.Fatalf("reachable fields wrong: %+v", d)
		}
	})

	t.Run("reachable but lease free", func(t *testing.T) {
		d := classifyEtcdProbe(true, halease.Status{Epoch: 7}, time.Millisecond, nil, now)
		if !d.OK || !d.Reachable || d.Holder != "" || d.Note == "" {
			t.Fatalf("free lease should be OK+reachable with a note: %+v", d)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		d := classifyEtcdProbe(true, halease.Status{}, 5*time.Second, context.DeadlineExceeded, now)
		if d.OK || d.Reachable || d.Status != "error" || d.Error == "" {
			t.Fatalf("unreachable should be not-OK with a bounded error: %+v", d)
		}
	})
}

// TestProbeLeaseBackend covers the HAState accessor: nil provider → clean
// not-configured; a live provider → passthrough of the Read result. Uses a local
// HAState so it never mutates (or races) the globalHA singleton.
func TestProbeLeaseBackend(t *testing.T) {
	// No provider armed.
	h := &HAState{}
	if configured, _, err := h.probeLeaseBackend(context.Background()); configured || err != nil {
		t.Fatalf("nil provider: got configured=%v err=%v, want false/nil", configured, err)
	}

	// A held Fake lease.
	fake := halease.NewFake(30 * time.Second)
	if granted, _, err := fake.Acquire(context.Background(), "node-x"); !granted || err != nil {
		t.Fatalf("fake acquire: granted=%v err=%v", granted, err)
	}
	h.SetLeaseProvider(fake, "node-x")
	configured, st, err := h.probeLeaseBackend(context.Background())
	if !configured || err != nil {
		t.Fatalf("armed provider: configured=%v err=%v", configured, err)
	}
	if st.Holder != "node-x" || st.Epoch != 1 {
		t.Fatalf("read passthrough wrong: %+v", st)
	}
}

// TestDiagnoseEtcd_Gates covers method + RBAC on the handler. It runs against the
// live singletons (default: no lease armed → configured=false), asserting only
// the gate outcomes, not the body.
func TestDiagnoseEtcd_Gates(t *testing.T) {
	// GET → 405.
	gRec := httptest.NewRecorder()
	apiDiagnoseEtcd(gRec, roleReq(RoleOperator, http.MethodGet, "/api/diagnose/etcd", nil))
	if gRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d want 405", gRec.Code)
	}
	// Viewer < operator → 403.
	vRec := httptest.NewRecorder()
	apiDiagnoseEtcd(vRec, roleReq(RoleViewer, http.MethodPost, "/api/diagnose/etcd", nil))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("viewer code=%d want 403", vRec.Code)
	}
	// Operator POST → 200 with a typed body.
	oRec := httptest.NewRecorder()
	apiDiagnoseEtcd(oRec, roleReq(RoleOperator, http.MethodPost, "/api/diagnose/etcd", nil))
	if oRec.Code != http.StatusOK {
		t.Fatalf("operator code=%d want 200 (body=%q)", oRec.Code, oRec.Body.String())
	}
}
