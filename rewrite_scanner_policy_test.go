package main

import (
	"bytes"
	"testing"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// Rewriter matchesHost tests moved to internal/rewrite (ADR-0002) — matchesHost
// is unexported and now lives in package rewrite.

// ─── ContentScanner extras ────────────────────────────────────────────────────

func TestDPIBlock_IncrementsStat(t *testing.T) {
	before := statDPIBlocked
	var buf bytes.Buffer
	dpiBlock(h1BlockResponder{w: &buf}, "test.com", "pattern")
	after := statDPIBlocked
	if after <= before {
		t.Error("dpiBlock should increment statDPIBlocked")
	}
}

// ─── Policy store extras ──────────────────────────────────────────────────────

func TestPolicyStore_VersionAndBump(t *testing.T) {
	ps := &PolicyStore{}
	v0, _ := ps.policyVersion()
	ps.Add(PolicyRule{Priority: 100, Action: "allow"})
	v1, ts1 := ps.policyVersion()
	if v1 <= v0 {
		t.Error("version should increase after Add")
	}
	if ts1 == "" {
		t.Error("updatedAt should be set after Add")
	}
}

func TestMatchSource_AllEmpty(t *testing.T) {
	// Rule with no source constraints should match everything
	rule := &PolicyRule{}
	if !matchSource(rule, "1.2.3.4", "user@corp.com", "oidc", []string{"admin"}) {
		t.Error("rule with empty source constraints should match any input")
	}
}

func TestMatchSource_AuthSource(t *testing.T) {
	rule := &PolicyRule{AuthSource: "ldap"}
	if !matchSource(rule, "", "", "LDAP", nil) {
		t.Error("AuthSource match should be case-insensitive")
	}
	if matchSource(rule, "", "", "oidc", nil) {
		t.Error("AuthSource mismatch should return false")
	}
}

func TestContainsGroupCI_Empty(t *testing.T) {
	if containsGroupCI(nil, "admins") {
		t.Error("empty group list should not match")
	}
	if containsGroupCI([]string{}, "admins") {
		t.Error("empty group list should not match")
	}
}

// ─── SSLBypassMatcher ─────────────────────────────────────────────────────────

// TestSSLBypassMatcher_AddRemoveMatches + CompileBypassPattern moved to
// internal/sslbypass (ADR-0002, policy.go decomposition Phase B).

// ─── SecurityScanner with YARA ────────────────────────────────────────────────

func TestSecurityScanner_ScanBody_WithYARA(t *testing.T) {
	// Install a YARA rule that matches "EICAR"
	y := &YARARuleSet{}
	_, _ = y.LoadSource(yaraRule("Detect", `        $a = "EICAR"`, "any of them"))

	// Temporarily swap globalYARA
	old := globalYARA
	globalYARA = y
	defer func() { globalYARA = old }()

	ss := newEnabledScanner(secscan.Deps{Yara: yaraRuleSetMatcher{y}})
	result := ss.ScanBody([]byte("contains EICAR pattern"))
	if result == nil {
		t.Error("ScanBody should detect YARA match")
	}
	if result != nil && result.Source != "yara" {
		t.Errorf("ScanBody result source = %q, want 'yara'", result.Source)
	}
}

func TestSecurityScanner_ScanBody_CachesClean(t *testing.T) {
	ss := newEnabledScanner(secscan.Deps{})
	// No ClamAV, no YARA — body scan enabled = false
	// (BodyScanEnabled needs enabled=true AND (clam!=nil OR yara enabled))
	// So for this test, just confirm clean data returns nil
	result := ss.ScanBody([]byte("clean data"))
	if result != nil {
		t.Errorf("ScanBody with no scanners should return nil, got %+v", result)
	}
}

// ─── matchFQDN extras ────────────────────────────────────────────────────────

func TestMatchFQDN_TrailingDot(t *testing.T) {
	if !matchFQDN("example.com.", "example.com") {
		t.Error("trailing dot in pattern should be normalized")
	}
	if !matchFQDN("example.com", "example.com.") {
		t.Error("trailing dot in host should be normalized")
	}
}
