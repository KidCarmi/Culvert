package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

func fileProfileRule(name, profileID string) PolicyRule {
	return PolicyRule{Name: name, FileFiltering: true, FileProfile: FileProfileName("Executables"), FileProfileID: profileID}
}

func withEmptyProfileStore(t *testing.T) {
	t.Helper()
	orig := globalProfileStore
	t.Cleanup(func() { globalProfileStore = orig })
	globalProfileStore = &FileProfileStore{}
}

func TestFileProfileUnresolvedDiagnostics_DanglingWarns(t *testing.T) {
	withEmptyProfileStore(t)
	prev := atomic.SwapInt64(&statFileProfileUnresolvedBlocked, 3)
	t.Cleanup(func() { atomic.StoreInt64(&statFileProfileUnresolvedBlocked, prev) })

	checks := fileProfileUnresolvedDiagnostics([]PolicyRule{fileProfileRule("block-exe", "gone-id")})
	c := diagHas(t, checks, "policy_file_profile_unresolved", diagWarn)
	if !strings.Contains(c.Message, "block-exe") || !strings.Contains(c.Message, "3 transactions") {
		t.Errorf("message should name the rule and blocked count, got %q", c.Message)
	}
	if c.OperatorAction == "" {
		t.Error("warn row must carry an operator action")
	}
}

func TestFileProfileUnresolvedDiagnostics_ResolvedOrInertIsSilent(t *testing.T) {
	withEmptyProfileStore(t)
	p, err := globalProfileStore.Create("Executables", []string{".exe"})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	disabled := fileProfileRule("disabled", "gone-id")
	disabled.Enabled = &off
	legacy := fileProfileRule("legacy", "") // name-only, no authoritative ID
	rules := []PolicyRule{fileProfileRule("ok", p.ID), disabled, legacy, {Name: "plain"}}
	if got := fileProfileUnresolvedDiagnostics(rules); got != nil {
		t.Errorf("resolved/disabled/legacy rules must not warn, got %+v", got)
	}
}

func TestFileProfileUnresolvedDiagnostics_BoundsListedNames(t *testing.T) {
	withEmptyProfileStore(t)
	var rules []PolicyRule
	for i := 0; i < fileProfileDiagMaxNames+3; i++ {
		rules = append(rules, fileProfileRule(fmt.Sprintf("r%d", i), "gone-id"))
	}
	c := diagHas(t, fileProfileUnresolvedDiagnostics(rules), "policy_file_profile_unresolved", diagWarn)
	if !strings.Contains(c.Message, "and 3 more") || strings.Contains(c.Message, "r7") {
		t.Errorf("listing must be bounded, got %q", c.Message)
	}
}
