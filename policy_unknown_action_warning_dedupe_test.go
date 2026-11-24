package main

import (
	"strings"
	"testing"
)

// The retention warning for an unknown-action rule (POL-004) says "matching
// traffic will be blocked". These tests pin WHEN it is said: once per fact, and
// only by a store that enforces. They do not touch what the rule does to
// traffic; policy_unknown_action_e2e_test.go owns that.

const retainedWarning = "with unrecognized action"

func retainedWarnings(sink *syncBuf) int { return strings.Count(sink.String(), retainedWarning) }

// diagRowPresent reports whether Diagnostics lists retained unknown-action rules
// for the running policy.
func diagRowPresent() bool {
	for _, c := range checkPolicyRulesUnknownAction(policyStore) {
		if c.Code == "policy_rules_unknown_action" {
			return true
		}
	}
	return false
}

func TestRetainedWarning_UnchangedRepublishIsSilent(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	policyStore.ReplaceAll(nil)

	first := captureLoggerForTest(t)
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "future", DestFQDN: "a.example.com", Action: "Quarantine"},
		{Priority: 2, Name: "known", DestFQDN: "b.example.com", Action: ActionAllow},
	})
	if n := retainedWarnings(first); n != 1 {
		t.Fatalf("first appearance announced %d time(s), want 1; log:\n%s", n, first.String())
	}
	if !diagRowPresent() {
		t.Fatal("Diagnostics row missing after the first publish")
	}

	// A control-plane republish sends back what the store holds, IDs included.
	held := policyStore.List()
	again := captureLoggerForTest(t)
	for i := 0; i < 3; i++ {
		policyStore.ReplaceAll(held)
	}
	if n := retainedWarnings(again); n != 0 {
		t.Errorf("three unchanged republishes announced %d time(s), want 0; log:\n%s", n, again.String())
	}
	if !diagRowPresent() {
		t.Error("Diagnostics row must stay for as long as the rule is in the running policy")
	}
	if got := policyStore.List(); len(got) != 2 || got[0].Action != "Quarantine" {
		t.Errorf("republish changed the rulebase: %+v", got)
	}
}

func TestRetainedWarning_ChangedOrReturningRuleIsAnnouncedAgain(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	policyStore.ReplaceAll(nil)
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "future", DestFQDN: "a.example.com", Action: "Quarantine"}})
	held := policyStore.List()

	// Same rule, different unknown action: the operator was told "Quarantine".
	changed := captureLoggerForTest(t)
	mut := append([]PolicyRule(nil), held...)
	mut[0].Action = "Isolate"
	policyStore.ReplaceAll(mut)
	if n := retainedWarnings(changed); n != 1 || !strings.Contains(changed.String(), `"Isolate"`) {
		t.Errorf("a changed action announced %d time(s), want 1 naming the new action; log:\n%s", n, changed.String())
	}

	// Gone, then back: the earlier announcement no longer describes the store.
	gone := captureLoggerForTest(t)
	policyStore.ReplaceAll(nil)
	if n := retainedWarnings(gone); n != 0 {
		t.Errorf("removing the rule announced %d time(s), want 0", n)
	}
	if diagRowPresent() {
		t.Error("Diagnostics row must clear when no retained rule is left")
	}
	back := captureLoggerForTest(t)
	policyStore.ReplaceAll(mut)
	if n := retainedWarnings(back); n != 1 {
		t.Errorf("a returning rule announced %d time(s), want 1; log:\n%s", n, back.String())
	}

	// A second retained rule next to an already-announced one: only the new one.
	added := captureLoggerForTest(t)
	policyStore.ReplaceAll(append(policyStore.List(), PolicyRule{Priority: 9, Name: "future-2", DestFQDN: "z.example.com", Action: "Sandbox"}))
	if n := retainedWarnings(added); n != 1 || !strings.Contains(added.String(), `"future-2"`) {
		t.Errorf("adding a second retained rule announced %d time(s), want 1 for the new rule only; log:\n%s", n, added.String())
	}
}

// A draft forks the running rulebase into the candidate store. Nothing in a
// candidate is enforced, so the fork must not say traffic will be blocked; the
// commit publishes to the running store, which already announced the rule.
func TestRetainedWarning_DraftForkAndCommitAreSilent(t *testing.T) {
	setupProxyTest(t)
	draftTestSetup(t)
	if !newDraftCandidateStore().staging || !policyDraft.cand.staging {
		t.Fatal("the draft candidate store must be a staging store")
	}
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "future", DestFQDN: "a.example.com", Action: "Quarantine"},
		{Priority: 2, Name: "known", DestFQDN: "b.example.com", Action: ActionAllow},
	})

	fork := captureLoggerForTest(t)
	cand := policyDraft.stageTarget("tester")
	if got := cand.List(); len(got) != 2 || got[0].Action != "Quarantine" {
		t.Fatalf("the fork must still carry the retained rule intact, got %+v", got)
	}
	if n := retainedWarnings(fork); n != 0 {
		t.Errorf("the draft fork announced %d time(s), want 0; log:\n%s", n, fork.String())
	}

	// What a commit does to the running store: publish the candidate.
	commit := captureLoggerForTest(t)
	policyStore.ReplaceAll(cand.List())
	if n := retainedWarnings(commit); n != 0 {
		t.Errorf("publishing a candidate that carries the rule through announced %d time(s), want 0; log:\n%s", n, commit.String())
	}
	if !diagRowPresent() {
		t.Error("Diagnostics row missing after the commit")
	}
}

// Load is a door of its own (startup, reload): it announces every retained rule
// each time, whatever the store held before.
func TestRetainedWarning_LoadAlwaysAnnounces(t *testing.T) {
	setupProxyTest(t)
	body := `[{"id":"11111111-1111-4111-8111-111111111111","priority":1,"name":"future","destFQDN":"a.example.com","action":"Quarantine"}]`
	sink := captureLoggerForTest(t)
	ps := loadIntoFreshStore(t, body)
	if n := retainedWarnings(sink); n != 1 {
		t.Fatalf("load announced %d time(s), want 1; log:\n%s", n, sink.String())
	}
	reload := captureLoggerForTest(t)
	if err := ps.Load(writePolicyFileForDropTest(t, body)); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if n := retainedWarnings(reload); n != 1 {
		t.Errorf("a reload of the same file announced %d time(s), want 1; log:\n%s", n, reload.String())
	}
}
