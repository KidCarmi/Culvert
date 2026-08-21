package main

// Codex-review fix (PR #1181): ensureDurableTarget must prove target
// membership UNDER the coordinator lock used for persistence, and Accepted
// may never be latched without the exact target existing in the draft
// candidate or the running policy — across concurrent revert, delete, and
// commit interleavings.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

// plAcceptingWithStagedRule drives a seeded recommendation to the accepting
// state WITH its translated rule durably staged in the draft candidate —
// exactly the crash window before FinalizeAccept (the M5B fixtures' shape).
func plAcceptingWithStagedRule(t *testing.T) (recID string, targetID string) {
	t.Helper()
	recID = plSeedRecommendation(t)
	setRequireCommit(true)
	eng := policyLearnEngine.Load()
	rec, err := eng.BeginAccept(recID, newRuleID())
	if err != nil {
		t.Fatalf("BeginAccept: %v", err)
	}
	rule := plTranslateRecommendation(&rec)
	stampRuleMetadataForWrite(&rule, nil, "codexfix")
	ver, _ := effectivePolicyVersion()
	if _, err := policyDraft.stageDurableAppend("codexfix", ver, rule); err != nil {
		t.Fatalf("stageDurableAppend: %v", err)
	}
	return recID, rec.TargetRuleID
}

// assertAcceptedImpliesTarget pins the latch invariant: state accepted ⇒ the
// EXACT TargetRuleID exists in the draft candidate or the running policy.
func assertAcceptedImpliesTarget(t *testing.T, recID string) {
	t.Helper()
	rec, ok := policyLearnEngine.Load().RecommendationByID(recID)
	if !ok {
		t.Fatalf("recommendation %s vanished", recID)
	}
	if rec.State != policylearn.RecStateAccepted {
		return
	}
	if plFindTargetRule(rec.TargetRuleID) == nil {
		t.Fatalf("Accepted latched without the exact target %s in candidate or running", rec.TargetRuleID)
	}
}

// TestCodexFix_EnsureDurableTargetProvesMembershipUnderLock: the durability
// proof must FAIL for a target that is no longer in the locked candidate.
// Pre-fix, ensureDurableTarget happily re-persisted whatever the candidate
// then held (even an inactive draft) and reported the vanished target durable.
func TestCodexFix_EnsureDurableTargetProvesMembershipUnderLock(t *testing.T) {
	plDurableDraftHarness(t)
	_, targetID := plAcceptingWithStagedRule(t)

	if err := policyDraft.ensureDurableTarget(targetID, nil); err != nil {
		t.Fatalf("staged member reported not durable: %v", err)
	}

	// Concurrent-revert interleave, made deterministic: the target vanishes
	// between an unlocked lookup and the locked proof.
	policyDraft.clear()
	err := policyDraft.ensureDurableTarget(targetID, nil)
	if !errors.Is(err, errDraftTargetMissing) {
		t.Fatalf("vanished target reported durable (err=%v) — membership not proven under the lock", err)
	}
}

// TestCodexFix_AcceptRetryAfterRevertNeverLatchesWithoutTarget: revert
// variant — the staged rule is reverted away before the admin retry. The
// retry must either refuse (409 family) or REDO the mutation; in every
// outcome accepted ⇒ target present.
func TestCodexFix_AcceptRetryAfterRevertNeverLatchesWithoutTarget(t *testing.T) {
	plDurableDraftHarness(t)
	recID, targetID := plAcceptingWithStagedRule(t)

	policyDraft.clear() // concurrent revert
	ver, _ := effectivePolicyVersion()
	out, err := plAcceptRecommendation(policyLearnEngine.Load(), recID, ver, "codexfix")
	if err == nil {
		// Redo arm: the mutation was re-executed — the target must exist.
		if out.RuleID != targetID || plFindTargetRule(targetID) == nil {
			t.Fatalf("accept succeeded without recreating target %s (got %q)", targetID, out.RuleID)
		}
	}
	assertAcceptedImpliesTarget(t, recID)
	assertDurableAcceptedInvariant(t, recID)
}

// TestCodexFix_AcceptRetryAfterTargetDeleteNeverLatchesWithoutTarget: delete
// variant — only the staged rule (not the whole draft) is removed.
func TestCodexFix_AcceptRetryAfterTargetDeleteNeverLatchesWithoutTarget(t *testing.T) {
	plDurableDraftHarness(t)
	recID, targetID := plAcceptingWithStagedRule(t)

	if !policyWriteStore("codexfix").DeleteByID(targetID) {
		t.Fatalf("test setup: could not delete staged rule %s", targetID)
	}
	ver, _ := effectivePolicyVersion()
	out, err := plAcceptRecommendation(policyLearnEngine.Load(), recID, ver, "codexfix")
	if err == nil {
		if out.RuleID != targetID || plFindTargetRule(targetID) == nil {
			t.Fatalf("accept succeeded without recreating target %s", targetID)
		}
	}
	assertAcceptedImpliesTarget(t, recID)
	assertDurableAcceptedInvariant(t, recID)
}

// TestCodexFix_AcceptRetryAfterCommitFinalizesAgainstRunning: commit variant —
// the draft (carrying the staged rule) is committed before the retry; the
// acceptance happened through the canonical commit path, so the retry
// finalizes against the RUNNING copy.
func TestCodexFix_AcceptRetryAfterCommitFinalizesAgainstRunning(t *testing.T) {
	plDurableDraftHarness(t)
	recID, targetID := plAcceptingWithStagedRule(t)

	// Mirror apiPolicyDraftCommit's activation core and its load-bearing
	// ordering: running gains the candidate BEFORE the draft clears.
	policyStore.ReplaceAll(policyDraft.candidateList())
	policyDraft.clear()

	ver, _ := effectivePolicyVersion()
	out, err := plAcceptRecommendation(policyLearnEngine.Load(), recID, ver, "codexfix")
	if err != nil {
		t.Fatalf("retry after commit: %v", err)
	}
	if out.RuleID != targetID {
		t.Fatalf("finalized rule %q, want the committed target %s", out.RuleID, targetID)
	}
	if policyStore.findByIDCopy(targetID) == nil {
		t.Fatalf("committed target %s missing from running", targetID)
	}
	assertAcceptedImpliesTarget(t, recID)
}

// TestCodexFix_AcceptRetryStaleFenceAborts: revert + STALE fence — the retry
// must abort back to generated (409 family), never latch.
func TestCodexFix_AcceptRetryStaleFenceAborts(t *testing.T) {
	plDurableDraftHarness(t)
	recID, _ := plAcceptingWithStagedRule(t)

	policyDraft.clear()
	_, err := plAcceptRecommendation(policyLearnEngine.Load(), recID, -1, "codexfix")
	if err == nil {
		t.Fatal("stale-fence retry after revert succeeded")
	}
	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State == policylearn.RecStateAccepted {
		t.Fatal("stale-fence retry latched Accepted")
	}
	assertAcceptedImpliesTarget(t, recID)
}

// TestCodexFix_ContentDriftAtDurabilityPointRefused (Codex re-review): the
// content comparison is re-proven INSIDE the durability critical section — a
// matcher that rejects at the locked moment must surface as content drift,
// never persist-and-report-durable.
func TestCodexFix_ContentDriftAtDurabilityPointRefused(t *testing.T) {
	plDurableDraftHarness(t)
	recID, targetID := plAcceptingWithStagedRule(t)

	// Locked-moment drift, made deterministic: the matcher stands in for the
	// concurrent draft update that invalidated the earlier unlocked check.
	err := policyDraft.ensureDurableTarget(targetID, func(*PolicyRule) bool { return false })
	if !errors.Is(err, errDraftTargetContentDrift) {
		t.Fatalf("drifted content reported durable (err=%v)", err)
	}

	// Full-flow variant: mutate the staged rule's content, then retry — the
	// accept must refuse with the integrity conflict, never latch.
	mutated := *plFindTargetRule(targetID)
	mutated.Action = ActionBlockPage
	if !policyWriteStore("codexfix").UpdateByID(targetID, mutated) {
		t.Fatalf("test setup: could not mutate staged rule %s", targetID)
	}
	ver, _ := effectivePolicyVersion()
	_, err = plAcceptRecommendation(policyLearnEngine.Load(), recID, ver, "codexfix")
	if !errors.Is(err, errAcceptIntegrityConflict) {
		t.Fatalf("mutated target accepted (err=%v)", err)
	}
	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State == policylearn.RecStateAccepted {
		t.Fatal("content drift latched Accepted")
	}
}

// TestCodexFix_CommitFenceRecheckedInsideActivation (Codex round 3): the
// handler's unlocked ?ifVersion precondition can be invalidated by a
// stageDurableAppend landing between the handler's read and the commit's
// critical section — the commit would then activate a candidate carrying a
// staged rule the operator never reviewed. commitActivate must re-verify the
// asserted candidate version INSIDE the same coordinator lock the durable
// append uses, and conflict instead of activating.
func TestCodexFix_CommitFenceRecheckedInsideActivation(t *testing.T) {
	plDurableDraftHarness(t)
	setRequireCommit(true)

	mkRule := func(name string) PolicyRule {
		disabled := false
		r := PolicyRule{
			ID:           newRuleID(),
			Name:         name,
			SourceGroup:  "fence",
			DestCategory: "m5b-cat",
			Action:       ActionAllow,
			SSLAction:    SSLInspect,
			Enabled:      &disabled,
		}
		stampRuleMetadataForWrite(&r, nil, "codexfix")
		return r
	}

	ver, _ := effectivePolicyVersion()
	if _, err := policyDraft.stageDurableAppend("codexfix", ver, mkRule("fence-reviewed")); err != nil {
		t.Fatalf("stageDurableAppend: %v", err)
	}
	reviewed, _ := policyDraft.candidateVersion() // the version the operator reviewed

	// The interleaved durable append (a learning accept) the operator did NOT see.
	ver2, _ := effectivePolicyVersion()
	unseen, err := policyDraft.stageDurableAppend("codexfix", ver2, mkRule("fence-unseen"))
	if err != nil {
		t.Fatalf("stageDurableAppend (interleave): %v", err)
	}

	if _, err := policyDraft.commitActivate(&reviewed); !errors.Is(err, errDraftVersionConflict) {
		t.Fatalf("stale reviewed version committed anyway (err=%v)", err)
	}
	if policyStore.findByIDCopy(unseen.ID) != nil {
		t.Fatal("conflicted commit still activated the unreviewed rule into RUNNING")
	}
	if !policyDraft.active() {
		t.Fatal("conflicted commit cleared the draft")
	}

	// With the CURRENT candidate version the commit proceeds.
	cur, _ := policyDraft.candidateVersion()
	if _, err := policyDraft.commitActivate(&cur); err != nil {
		t.Fatalf("current-version commit: %v", err)
	}
	if policyStore.findByIDCopy(unseen.ID) == nil {
		t.Fatal("committed rule missing from RUNNING")
	}
}

// TestCodexFix_CommitAppendNeverVanishesRule (Codex re-review): the commit's
// snapshot→activate→clear now shares one coordinator critical section with
// the durable append, so a successfully appended rule can land only entirely
// before the snapshot (published to running) or entirely after the clear
// (in a freshly opened draft) — never in the vanished middle. Bounded
// concurrent stress; run under -race.
func TestCodexFix_CommitAppendNeverVanishesRule(t *testing.T) {
	plDurableDraftHarness(t)
	setRequireCommit(true)
	for i := 0; i < 40; i++ {
		ver, _ := effectivePolicyVersion()
		disabled := false
		rule := PolicyRule{
			ID:           newRuleID(),
			Name:         fmt.Sprintf("codexfix-stress-%d", i),
			SourceGroup:  "stress",
			DestCategory: "m5b-cat",
			Action:       ActionAllow,
			SSLAction:    SSLInspect,
			Enabled:      &disabled,
		}
		stampRuleMetadataForWrite(&rule, nil, "codexfix")
		commitDone := make(chan struct{})
		go func() {
			_, _ = policyDraft.commitActivate(nil) // may 4xx-equivalent when no draft — fine
			close(commitDone)
		}()
		added, err := policyDraft.stageDurableAppend("codexfix", ver, rule)
		<-commitDone
		if err != nil {
			continue // fence conflict: the commit won the interleave; nothing was appended
		}
		if plFindTargetRule(added.ID) == nil {
			t.Fatalf("iteration %d: appended rule %s vanished (in neither candidate nor running)", i, added.ID)
		}
	}
}
