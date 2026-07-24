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

// TestMatcher_NormalizedPatternMatches pins the compile-time-normalization
// contract behind pattern.norm: an admin-entered glob that needs
// normalization (uppercase, trailing dot, Unicode/IDN) must keep matching the
// canonicalized request host exactly as it did when Matches normalized the
// pattern on every call via MatchFQDN. NormalizeHost is pure, so precompute
// and per-call normalization are byte-identical — this test is the wall
// against a future edit that stores the raw pattern in norm.
func TestMatcher_NormalizedPatternMatches(t *testing.T) {
	m := &Matcher{}
	for _, p := range []string{"*.Corp.Example.COM.", "münchen.example"} {
		if err := m.Add(p); err != nil {
			t.Fatalf("Add(%q): %v", p, err)
		}
	}

	cases := []struct {
		host string
		want bool
	}{
		{"app.corp.example.com", true},         // case + trailing dot normalized at compile
		{"APP.CORP.EXAMPLE.COM", true},         // host side normalized per call
		{"xn--mnchen-3ya.example", true},       // IDN pattern matches punycode host
		{"sub.xn--mnchen-3ya.example", true},   // bare-domain glob includes subdomains
		{"münchen.example", true},              // Unicode host normalizes to the same form
		{"xn--mnchen-3ya.example.evil", false}, // suffix confusion must not match
	}
	for _, c := range cases {
		if got := m.Matches(c.host); got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// TestMatcher_TrailingDotHostMatches pins the two-pass normalization parity
// flagged in the PR #918 Codex review: NormalizeHost is not idempotent for a
// host with an empty trailing DNS label ("example.com.." normalizes to
// "example.com.", not "example.com"), and such hosts pass the request path's
// NormalizeHostStrict gate. The pre-precompute code re-normalized the host
// inside per-pattern MatchFQDN, so these hosts matched their bypass pattern —
// an explicitly bypassed CONNECT destination must not silently become
// inspected. The expectations below are the measured OLD behavior (two
// normalization passes total: ≥3 trailing dots did not match then either).
func TestMatcher_TrailingDotHostMatches(t *testing.T) {
	m := &Matcher{}
	if err := m.Add("example.com"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"example.com.", true},        // single root-anchor dot
		{"example.com..", true},       // empty trailing label — the review case
		{"sub.example.com..", true},   // subdomain variant
		{"EXAMPLE.com..", true},       // plus case normalization
		{"example.com...", false},     // two passes were never enough pre-change either
		{"example.com..evil", false},  // dots in the middle must not collapse
		{"evil-example.com..", false}, // suffix confusion must not match
	}
	for _, c := range cases {
		if got := m.Matches(c.host); got != c.want {
			t.Errorf("Matches(%q) = %v, want %v (old two-pass semantics)", c.host, got, c.want)
		}
	}
}

// TestMatcher_EmptyFastPath pins the empty-list fast path: a matcher with no
// patterns (the unconfigured default) must report no match for any host.
func TestMatcher_EmptyFastPath(t *testing.T) {
	m := &Matcher{}
	if m.Matches("anything.example.com") {
		t.Error("empty matcher must not match")
	}
	// And after removing the last pattern the fast path re-engages.
	_ = m.Add("*.example.com")
	if !m.Matches("a.example.com") {
		t.Error("pattern should match before removal")
	}
	m.Remove("*.example.com")
	if m.Matches("a.example.com") {
		t.Error("must not match after the last pattern is removed")
	}
}
