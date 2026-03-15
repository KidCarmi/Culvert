package main

import (
	"bytes"
	"testing"
)

// ─── Rewriter extras ─────────────────────────────────────────────────────────

func TestRewriter_matchesHost_CaseInsensitive(t *testing.T) {
	r := &RewriteRule{Host: "Example.COM"}
	if !r.matchesHost("example.com") {
		t.Error("matchesHost should be case-insensitive")
	}
}

func TestRewriter_matchesHost_WildcardExact(t *testing.T) {
	// *.example.com: "example.com" itself should match (without www.)
	r := &RewriteRule{Host: "*.example.com"}
	if !r.matchesHost("example.com") {
		t.Error("wildcard pattern should also match the bare domain")
	}
}

// ─── ContentScanner extras ────────────────────────────────────────────────────

func TestDPIBlock_IncrementsStat(t *testing.T) {
	before := statDPIBlocked
	var buf bytes.Buffer
	dpiBlock(&buf, "test.com", "pattern")
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

func TestSSLBypassMatcher_AddRemoveMatches(t *testing.T) {
	s := &SSLBypassMatcher{}

	if err := s.Add("*.example.com"); err != nil {
		t.Fatalf("Add wildcard error: %v", err)
	}
	if err := s.Add("exact.test.com"); err != nil {
		t.Fatalf("Add exact error: %v", err)
	}

	list := s.List()
	if len(list) < 2 {
		t.Errorf("List should have 2 entries, got %d", len(list))
	}
	if !s.Matches("sub.example.com") {
		t.Error("should match wildcard pattern")
	}
	if !s.Matches("exact.test.com") {
		t.Error("should match exact pattern")
	}
	if s.Matches("other.com") {
		t.Error("should not match unrelated host")
	}

	if !s.Remove("exact.test.com") {
		t.Error("Remove should return true for existing pattern")
	}
	if s.Matches("exact.test.com") {
		t.Error("removed pattern should no longer match")
	}
}

func TestSSLBypassMatcher_CompileBypassPattern(t *testing.T) {
	_, err := compileBypassPattern("*.valid.com")
	if err != nil {
		t.Errorf("compileBypassPattern valid: %v", err)
	}
}

// ─── SecurityScanner with YARA ────────────────────────────────────────────────

func TestSecurityScanner_ScanBody_WithYARA(t *testing.T) {
	// Install a YARA rule that matches "EICAR"
	y := &YARARuleSet{}
	rules, _ := parseYARASrc(yaraRule("Detect", `        $a = "EICAR"`, "any of them"))
	y.rules = rules

	// Temporarily swap globalYARA
	old := globalYARA
	globalYARA = y
	defer func() { globalYARA = old }()

	ss := &SecurityScanner{cache: newHashCache(100, 0), enabled: true}
	result := ss.ScanBody([]byte("contains EICAR pattern"))
	if result == nil {
		t.Error("ScanBody should detect YARA match")
	}
	if result != nil && result.Source != "yara" {
		t.Errorf("ScanBody result source = %q, want 'yara'", result.Source)
	}
}

func TestSecurityScanner_ScanBody_CachesClean(t *testing.T) {
	ss := &SecurityScanner{cache: newHashCache(100, 0), enabled: true}
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
