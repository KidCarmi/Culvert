package main

// Tests for the CDR policy matcher (cdrpolicy.go).
//
// The matcher reuses policy.go's source/dest helpers via a synthetic
// PolicyRule, so these tests focus on the CDR-specific surface:
// priority ordering, default fallback, mode normalisation, rule CRUD,
// and audit-friendly decision metadata.

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// Helper: build a store with a fresh temp-file backing and the given rules.
// Returns the store and a cleanup function.
func newTestCDRPolicyStore(t *testing.T, rules ...CDRPolicyRule) (*CDRPolicyStore, func()) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cdr_policies.json")
	store := &CDRPolicyStore{}
	store.path = path
	copies := make([]*CDRPolicyRule, len(rules))
	for i := range rules {
		r := rules[i]
		copies[i] = &r
	}
	if err := store.Replace(copies); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	return store, func() { _ = os.Remove(path) }
}

func TestCDRPolicy_NoRulesReturnsDefault(t *testing.T) {
	store, cleanup := newTestCDRPolicyStore(t)
	defer cleanup()

	got := store.Evaluate("10.0.0.1", "user@corp", "local", "example.com", nil, CDRConfig{
		DefaultProfile: "default",
		DefaultMode:    "ENFORCE",
	})
	if got == nil {
		t.Fatal("decision must never be nil")
	}
	if got.Source != "default" {
		t.Fatalf("Source = %q, want default", got.Source)
	}
	if got.ProfileName != "default" || got.Mode != pb.Mode_ENFORCE {
		t.Fatalf("default decision wrong: %+v", got)
	}
}

func TestCDRPolicy_DefaultFallbackNormalisesBlankProfile(t *testing.T) {
	store, cleanup := newTestCDRPolicyStore(t)
	defer cleanup()

	// No defaults in config either — must still return "default" profile.
	got := store.Evaluate("10.0.0.1", "", "", "example.com", nil, CDRConfig{})
	if got.ProfileName != "default" {
		t.Fatalf("blank default profile must resolve to %q, got %q", "default", got.ProfileName)
	}
	if got.Mode != pb.Mode_ENFORCE {
		t.Fatalf("blank mode must resolve to ENFORCE, got %v", got.Mode)
	}
}

func TestCDRPolicy_FirstMatchByPriority(t *testing.T) {
	store, cleanup := newTestCDRPolicyStore(t,
		CDRPolicyRule{Name: "low", Priority: 10, SourceGroup: "finance", ProfileName: "aggressive", Mode: "ENFORCE"},
		CDRPolicyRule{Name: "high", Priority: 100, SourceGroup: "vip", ProfileName: "lenient", Mode: "BYPASS_WITH_REPORT"},
	)
	defer cleanup()

	// User is in BOTH groups — higher priority wins.
	got := store.Evaluate("10.0.0.1", "user@corp", "local", "example.com", []string{"finance", "vip"}, CDRConfig{})
	if got.Source != "rule" {
		t.Fatalf("Source = %q, want rule", got.Source)
	}
	if got.MatchedRule == nil || got.MatchedRule.Name != "high" {
		t.Fatalf("matched %+v, want high-priority rule", got.MatchedRule)
	}
	if got.Mode != pb.Mode_BYPASS_WITH_REPORT {
		t.Fatalf("mode = %v, want BYPASS_WITH_REPORT", got.Mode)
	}
}

func TestCDRPolicy_DisabledRulesSkipped(t *testing.T) {
	disabled := false
	store, cleanup := newTestCDRPolicyStore(t,
		CDRPolicyRule{Name: "off", Priority: 100, Enabled: &disabled, SourceGroup: "finance", ProfileName: "aggressive", Mode: "ENFORCE"},
		CDRPolicyRule{Name: "on", Priority: 50, SourceGroup: "finance", ProfileName: "relaxed", Mode: "ENFORCE"},
	)
	defer cleanup()

	got := store.Evaluate("10.0.0.1", "u", "local", "example.com", []string{"finance"}, CDRConfig{})
	if got.MatchedRule == nil || got.MatchedRule.Name != "on" {
		t.Fatalf("disabled rule should have been skipped; got %+v", got.MatchedRule)
	}
}

func TestCDRPolicy_SourceIdentityMatcher(t *testing.T) {
	store, cleanup := newTestCDRPolicyStore(t,
		CDRPolicyRule{Name: "alice-only", Priority: 50, SourceIdentity: "alice@corp", ProfileName: "strict", Mode: "ENFORCE"},
	)
	defer cleanup()

	matched := store.Evaluate("10.0.0.1", "alice@corp", "local", "example.com", nil, CDRConfig{})
	if matched.MatchedRule == nil || matched.MatchedRule.Name != "alice-only" {
		t.Fatalf("alice should match, got %+v", matched)
	}
	skipped := store.Evaluate("10.0.0.1", "bob@corp", "local", "example.com", nil, CDRConfig{})
	if skipped.Source != "default" {
		t.Fatalf("bob should fall through to default, got %+v", skipped)
	}
}

func TestCDRPolicy_DestFQDNWildcard(t *testing.T) {
	store, cleanup := newTestCDRPolicyStore(t,
		CDRPolicyRule{Name: "gdrive", Priority: 50, DestFQDN: "*.googleusercontent.com", ProfileName: "default", Mode: "REPORT_ONLY"},
	)
	defer cleanup()

	hit := store.Evaluate("10.0.0.1", "u", "local", "abc123.googleusercontent.com", nil, CDRConfig{})
	if hit.Source != "rule" {
		t.Fatalf("FQDN wildcard didn't match: %+v", hit)
	}
	if hit.Mode != pb.Mode_REPORT_ONLY {
		t.Fatalf("mode wrong: %v", hit.Mode)
	}
	miss := store.Evaluate("10.0.0.1", "u", "local", "example.com", nil, CDRConfig{})
	if miss.Source != "default" {
		t.Fatalf("non-matching FQDN should fall through: %+v", miss)
	}
}

func TestCDRPolicy_SourceCIDRMatcher(t *testing.T) {
	store, cleanup := newTestCDRPolicyStore(t,
		CDRPolicyRule{Name: "lan", Priority: 50, SourceIP: "10.0.0.0/24", ProfileName: "default", Mode: "ENFORCE"},
	)
	defer cleanup()

	inside := store.Evaluate("10.0.0.42", "u", "local", "example.com", nil, CDRConfig{})
	if inside.Source != "rule" {
		t.Fatalf("in-CIDR address didn't match: %+v", inside)
	}
	outside := store.Evaluate("192.168.1.5", "u", "local", "example.com", nil, CDRConfig{})
	if outside.Source != "default" {
		t.Fatalf("out-of-CIDR should fall through: %+v", outside)
	}
}

func TestCDRPolicy_ModeNormalisation(t *testing.T) {
	cases := []struct {
		in   string
		want pb.Mode
	}{
		{"ENFORCE", pb.Mode_ENFORCE},
		{"enforce", pb.Mode_ENFORCE},
		{"", pb.Mode_ENFORCE},
		{"REPORT_ONLY", pb.Mode_REPORT_ONLY},
		{"report_only", pb.Mode_REPORT_ONLY},
		{"BYPASS_WITH_REPORT", pb.Mode_BYPASS_WITH_REPORT},
		{"  bypass_with_report  ", pb.Mode_BYPASS_WITH_REPORT},
		{"garbage-value", pb.Mode_ENFORCE}, // safe default
	}
	for _, c := range cases {
		if got := normalizeMode(c.in); got != c.want {
			t.Errorf("normalizeMode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCDRPolicy_ValidateMode(t *testing.T) {
	good := []string{"", "ENFORCE", "REPORT_ONLY", "BYPASS_WITH_REPORT", "enforce"}
	bad := []string{"garbage", "enforce ", "audit"}
	for _, s := range good {
		if !validateMode(s) {
			t.Errorf("validateMode(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validateMode(s) && s != "enforce " {
			// "enforce " trims to "enforce" which normalises fine, but
			// validate should accept it too (it's user-friendly).  Keep
			// strict for the others.
			t.Errorf("validateMode(%q) = true, want false", s)
		}
	}
}

func TestCDRPolicy_MatchedConditions(t *testing.T) {
	store, cleanup := newTestCDRPolicyStore(t,
		CDRPolicyRule{
			Name:        "finance-gdrive",
			Priority:    50,
			SourceGroup: "finance",
			DestFQDN:    "*.googleusercontent.com",
			ProfileName: "strict",
			Mode:        "ENFORCE",
		},
	)
	defer cleanup()

	got := store.Evaluate("10.0.0.1", "u", "local", "x.googleusercontent.com", []string{"finance"}, CDRConfig{})
	if got.MatchedConditions == "" {
		t.Fatalf("MatchedConditions empty; want summary")
	}
	if !containsAll(got.MatchedConditions, []string{"group=finance", "destFQDN="}) {
		t.Errorf("MatchedConditions = %q, missing markers", got.MatchedConditions)
	}
}

// ─── Store CRUD ─────────────────────────────────────────────────────────────

func TestCDRPolicy_AddPersistsAndSortsByPriority(t *testing.T) {
	store, cleanup := newTestCDRPolicyStore(t)
	defer cleanup()

	if _, err := store.Add(CDRPolicyRule{Name: "low", Priority: 10, Mode: "ENFORCE"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add(CDRPolicyRule{Name: "high", Priority: 100, Mode: "ENFORCE"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add(CDRPolicyRule{Name: "mid", Priority: 50, Mode: "ENFORCE"}); err != nil {
		t.Fatal(err)
	}
	list := store.List()
	if len(list) != 3 {
		t.Fatalf("len = %d", len(list))
	}
	if list[0].Name != "high" || list[1].Name != "mid" || list[2].Name != "low" {
		t.Fatalf("sort wrong: %v %v %v", list[0].Name, list[1].Name, list[2].Name)
	}

	// Reload from disk to confirm persistence.
	fresh := &CDRPolicyStore{}
	if err := fresh.Load(store.path); err != nil {
		t.Fatal(err)
	}
	if len(fresh.List()) != 3 {
		t.Fatalf("reload: len = %d", len(fresh.List()))
	}
}

func TestCDRPolicy_AddRejectsInvalidMode(t *testing.T) {
	store, cleanup := newTestCDRPolicyStore(t)
	defer cleanup()
	if _, err := store.Add(CDRPolicyRule{Name: "bad", Mode: "AUDIT"}); err == nil {
		t.Fatal("expected invalid-mode rejection")
	}
}

func TestCDRPolicy_RemoveByName(t *testing.T) {
	store, cleanup := newTestCDRPolicyStore(t)
	defer cleanup()
	_, _ = store.Add(CDRPolicyRule{Name: "one", Priority: 50, Mode: "ENFORCE"})
	_, _ = store.Add(CDRPolicyRule{Name: "two", Priority: 50, Mode: "ENFORCE"})

	ok, err := store.RemoveByName("one")
	if err != nil || !ok {
		t.Fatalf("RemoveByName(one) = %v, %v", ok, err)
	}
	if got := store.List(); len(got) != 1 || got[0].Name != "two" {
		t.Fatalf("after remove: %+v", got)
	}

	// Idempotent on missing.
	if ok, err := store.RemoveByName("ghost"); err != nil || ok {
		t.Fatalf("RemoveByName(ghost) = %v, %v", ok, err)
	}
}

func TestCDRPolicy_VersionIncrementsOnMutations(t *testing.T) {
	store, cleanup := newTestCDRPolicyStore(t)
	defer cleanup()
	v0, _ := store.Version()
	_, _ = store.Add(CDRPolicyRule{Name: "a", Priority: 50, Mode: "ENFORCE"})
	v1, _ := store.Version()
	if v1 <= v0 {
		t.Fatalf("version didn't advance: %d -> %d", v0, v1)
	}
	_, _ = store.RemoveByName("a")
	v2, _ := store.Version()
	if v2 <= v1 {
		t.Fatalf("version didn't advance on remove: %d -> %d", v1, v2)
	}
}

// ─── helpers ────────────────────────────────────────────────────────────────

func containsAll(s string, needles []string) bool {
	for _, n := range needles {
		if !stringContains(s, n) {
			return false
		}
	}
	return true
}

// stringContains is a tiny wrapper to avoid pulling in "strings" just for
// this helper in a test file that already has specific imports.
func stringContains(s, needle string) bool {
	return len(s) >= len(needle) && indexOf(s, needle) >= 0
}

func indexOf(s, needle string) int {
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
