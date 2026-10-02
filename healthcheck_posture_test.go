package main

import (
	"net/http"
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
	handleReady(rr, httptest.NewRequest("GET", "/ready?strict=1", http.NoBody))
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

// Disabled rules are skipped by evaluation, so a rulebase whose every rule is
// disabled under default-allow is passthrough and must not read as enforcing
// (Codex P2, PR #1528).
func TestReadiness_PostureCountsOnlyEnabledRules(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	t.Cleanup(func() { setDefaultPolicyAction("deny") })
	setDefaultPolicyAction("allow")
	off := false
	policyStore.Add(PolicyRule{Name: "disabled-only", Action: "block", DestFQDN: "*", Enabled: &off})
	if _, n := policyPosture(); n != 0 {
		t.Fatalf("a disabled rule counted toward the posture: %d", n)
	}
	rep, _ := computeReadiness()
	if c := rep.Checks["policy_posture"]; c == nil || c.Status != "fail" {
		t.Fatalf("all-disabled rules under default-allow must be passthrough: %+v", c)
	}
	// CONTROL: one enabled rule is enough to leave passthrough.
	policyStore.Add(PolicyRule{Name: "live", Action: "block", DestFQDN: "*"})
	if _, n := policyPosture(); n != 1 {
		t.Fatalf("enabled rule count = %d, want 1", n)
	}
	if c, _ := computeReadiness(); c.Checks["policy_posture"].Status != "ok" {
		t.Fatalf("one enabled rule must read as enforcing: %+v", c.Checks["policy_posture"])
	}
}
