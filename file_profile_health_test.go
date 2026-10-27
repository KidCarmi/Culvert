package main

import (
	"strings"
	"sync/atomic"
	"testing"
)

func TestFileProfileResolutionRow(t *testing.T) {
	if c := fileProfileResolutionRow(nil, 0); c.Code != "file_profile_resolution" || c.Status != diagOK || c.OperatorAction != "" {
		t.Fatalf("no dangling rule: got %+v, want ok row without action", c)
	}
	c := fileProfileResolutionRow([]string{"block-exe"}, 3)
	if c.Status != diagWarn || c.OperatorAction == "" || !strings.Contains(c.Message, "block-exe") {
		t.Fatalf("dangling rule: got %+v, want warn row naming the rule with an action", c)
	}
	if strings.Contains(c.Message, "transaction") || !strings.Contains(c.Message, "3 fail-closed evaluation(s)") {
		t.Fatalf("counter must be described as evaluations, not transactions: %q", c.Message)
	}
	if !strings.Contains(c.OperatorAction, "Access Rules") || !strings.Contains(c.OperatorAction, "by ID") {
		t.Fatalf("action must point to re-pointing the rule and warn that a same-name profile does not repair it: %q", c.OperatorAction)
	}
}

// TestCheckFileProfileResolution_ClearsAfterRepair pins that the row tracks the
// CURRENT dangling reference, not the monotonic counter: once the profile is
// back, the warning clears without a restart even though the counter stays.
func TestCheckFileProfileResolution_ClearsAfterRepair(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	dcProfileStoreIsolate(t)
	origCount := atomic.LoadInt64(&statFileProfileUnresolvedBlocked)
	t.Cleanup(func() { atomic.StoreInt64(&statFileProfileUnresolvedBlocked, origCount) })

	disabled := false
	policyStore.Add(PolicyRule{Name: "fp-dangling-disabled", Action: ActionAllow, Enabled: &disabled,
		FileFiltering: true, FileProfile: "gone", FileProfileID: "fp-missing-id"})
	if c := checkFileProfileResolution(); c.Status != diagOK {
		t.Fatalf("a disabled rule never matches, so its dangling reference must not warn: %+v", c)
	}
	// Drop/Block_Page/Redirect terminate before any file-profile evaluation,
	// and auth rules never reach Stage 2: none of them can fail closed.
	for _, a := range []PolicyAction{ActionDrop, ActionBlockPage, ActionRedirect} {
		policyStore.Add(PolicyRule{Name: "fp-dangling-" + string(a), Action: a,
			FileFiltering: true, FileProfile: "gone", FileProfileID: "fp-missing-id"})
	}
	policyStore.Add(PolicyRule{Name: "fp-dangling-auth", RuleType: ruleTypeAuth, Action: ActionAllow,
		FileFiltering: true, FileProfile: "gone", FileProfileID: "fp-missing-id"})
	if c := checkFileProfileResolution(); c.Status != diagOK {
		t.Fatalf("rules that never evaluate a file profile must not warn: %+v", c)
	}
	policyStore.Add(PolicyRule{Name: "fp-dangling-rule", Action: ActionAllow,
		FileFiltering: true, FileProfile: "gone", FileProfileID: "fp-missing-id"})
	atomic.StoreInt64(&statFileProfileUnresolvedBlocked, 2)

	c := checkFileProfileResolution()
	if c.Status != diagWarn || !strings.Contains(c.Message, "1 enabled Allow rule(s)") || !strings.Contains(c.Message, "fp-dangling-rule") {
		t.Fatalf("dangling reference: got %+v, want warn naming fp-dangling-rule", c)
	}

	if err := globalProfileStore.ReplaceAll([]FileExtProfile{{ID: "fp-missing-id", Name: "gone", Extensions: []string{"exe"}}}); err != nil {
		t.Fatalf("restore profile: %v", err)
	}
	c = checkFileProfileResolution()
	if c.Status != diagOK {
		t.Fatalf("repaired reference must clear the warning while the counter stays at 2, got %+v", c)
	}
	if strings.Contains(c.Message, "repaired") || strings.Contains(c.Message, "every policy rule") || !strings.Contains(c.Message, "2 fail-closed") {
		t.Fatalf("OK row must describe only enforced rules and not assume how it cleared: %q", c.Message)
	}
}

func TestCheckFileProfileResolution_RegisteredInOperatorContract(t *testing.T) {
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "file_profile_resolution" {
			return
		}
	}
	t.Fatal("file_profile_resolution missing from /api/diagnostics contract")
}
