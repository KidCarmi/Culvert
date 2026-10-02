package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The /ready and /health surfaces must tell "services running", "setup
// complete" and "ready to enforce" apart (appliance readiness F). Both rows
// are report-only on the default verdict and gating under ?strict=1.
func TestReadiness_SetupAndPostureRows(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	t.Cleanup(func() { setDefaultPolicyAction("deny") })

	// Fresh install shape: no admin, no rules, passthrough.
	setDefaultPolicyAction("allow")
	rep, code := computeReadiness()
	if code != 200 {
		t.Fatalf("report-only rows must not gate the default verdict; code=%d checks=%+v", code, rep.Checks)
	}
	if c := rep.Checks["setup_complete"]; c == nil || c.Status != "fail" {
		t.Fatalf("setup_complete must fail before setup: %+v", c)
	}
	if c := rep.Checks["policy_posture"]; c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "passthrough") {
		t.Fatalf("policy_posture must report passthrough on a fresh install: %+v", c)
	}
	h := computeHealth()
	if h.SetupComplete || h.PolicyDefaultAction != "allow" {
		t.Fatalf("/health must mirror the posture: %+v", h)
	}

	// Strict callers gate on them.
	rr := httptest.NewRecorder()
	handleReady(rr, httptest.NewRequest("GET", "/ready?strict=1", nil))
	if rr.Code != 503 {
		t.Fatalf("strict readiness must fail before setup/enforcement, got %d", rr.Code)
	}

	// Setup completed + default-deny: both rows ok.
	if err := cfg.SetAuth("admin", "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
	setDefaultPolicyAction("deny")
	rep, _ = computeReadiness()
	if c := rep.Checks["setup_complete"]; c == nil || c.Status != "ok" {
		t.Fatalf("setup_complete must be ok after setup: %+v", c)
	}
	if c := rep.Checks["policy_posture"]; c == nil || c.Status != "ok" || c.Detail != "default-deny" {
		t.Fatalf("policy_posture must be ok under default-deny: %+v", c)
	}
	if h := computeHealth(); !h.SetupComplete || h.PolicyDefaultAction != "deny" {
		t.Fatalf("/health must mirror the posture: %+v", h)
	}
}
