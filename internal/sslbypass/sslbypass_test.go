package sslbypass

// Engine tests, consolidated in-package from package main's policy_test.go
// (glob/regex matching, Set, Load with invalid JSON) and
// rewrite_scanner_policy_test.go (Add/Remove/Matches round-trip, pattern
// compilation) with the extraction (ADR-0002, policy.go decomposition
// Phase B).

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatcher_GlobMatches(t *testing.T) {
	m := &Matcher{}
	_ = m.Add("*.corp.local")
	_ = m.Add("exact.example.com")

	cases := []struct {
		host string
		want bool
	}{
		{"app.corp.local", true},
		{"corp.local", true}, // apex
		{"other.example.com", false},
		{"exact.example.com", true},
		{"sub.exact.example.com", true}, // MatchFQDN: bare domain also matches subdomains (Palo Alto style)
		{"unrelated.com", false},
	}
	for _, c := range cases {
		got := m.Matches(c.host)
		if got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestMatcher_RegexMatches(t *testing.T) {
	m := &Matcher{}
	if err := m.Add(`~^.*\.gov\.il$`); err != nil {
		t.Fatalf("Add regex: %v", err)
	}

	cases := []struct {
		host string
		want bool
	}{
		{"gov.il", false}, // doesn't have a subdomain prefix
		{"tax.gov.il", true},
		{"deep.sub.gov.il", true},
		{"evil-gov.il", false},
	}
	for _, c := range cases {
		got := m.Matches(c.host)
		if got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestMatcher_Set(t *testing.T) {
	m := &Matcher{}
	_ = m.Add("old.com")

	if err := m.Set([]string{"new1.com", "new2.com"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	list := m.List()
	if len(list) != 2 || list[0] != "new1.com" || list[1] != "new2.com" {
		t.Errorf("unexpected list after Set: %v", list)
	}
}

func TestMatcher_LoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte("bad json"), 0o600)

	m := &Matcher{}
	if err := m.Load(path); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestMatcher_AddRemoveMatches(t *testing.T) {
	m := &Matcher{}

	if err := m.Add("*.example.com"); err != nil {
		t.Fatalf("Add wildcard error: %v", err)
	}
	if err := m.Add("exact.test.com"); err != nil {
		t.Fatalf("Add exact error: %v", err)
	}

	list := m.List()
	if len(list) < 2 {
		t.Errorf("List should have 2 entries, got %d", len(list))
	}
	if !m.Matches("sub.example.com") {
		t.Error("should match wildcard pattern")
	}
	if !m.Matches("exact.test.com") {
		t.Error("should match exact pattern")
	}
	if m.Matches("other.com") {
		t.Error("should not match unrelated host")
	}

	if !m.Remove("exact.test.com") {
		t.Error("Remove should return true for existing pattern")
	}
	if m.Matches("exact.test.com") {
		t.Error("removed pattern should no longer match")
	}
}

func TestCompilePattern(t *testing.T) {
	if _, err := compilePattern("*.valid.com"); err != nil {
		t.Errorf("compilePattern valid glob: %v", err)
	}
	if _, err := compilePattern("~[invalid"); err == nil {
		t.Error("compilePattern invalid regex should error")
	}
}
