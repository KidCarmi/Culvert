package main

// Codex-review fix (PR #1181): ensureDurableTarget must prove target
// membership UNDER the coordinator lock used for persistence, and Accepted
// may never be latched without the exact target existing in the draft
// candidate or the running policy — across concurrent revert, delete, and
// commit interleavings.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// TestCodexFix_CommitRetainsDraftWhenRunningPersistFails (Codex round 8):
// activation must be durable-or-nothing. A swallowed running-policy write
// failure used to clear the draft anyway — new policy in memory, old policy
// on disk, no draft — so a restart silently reverted the commit and a
// learning acceptance finalized against a target with no durable home.
func TestCodexFix_CommitRetainsDraftWhenRunningPersistFails(t *testing.T) {
	draftDir := plDurableDraftHarness(t)
	rulesDir := t.TempDir()
	prevPath := policyStore.path
	policyStore.path = filepath.Join(rulesDir, "policy_rules.json")
	t.Cleanup(func() { policyStore.path = prevPath })
	setRequireCommit(true)

	disabled := false
	rule := PolicyRule{
		ID: newRuleID(), Name: "commit-durability", SourceGroup: "g", DestCategory: "m5b-cat",
		Action: ActionAllow, SSLAction: SSLInspect, Enabled: &disabled,
	}
	stampRuleMetadataForWrite(&rule, nil, "codexfix")
	ver, _ := effectivePolicyVersion()
	added, err := policyDraft.stageDurableAppend("codexfix", ver, rule)
	if err != nil {
		t.Fatalf("stageDurableAppend: %v", err)
	}

	// Block the running-policy write: the target path becomes a non-empty
	// directory, so the atomic rename fails.
	if err := os.MkdirAll(filepath.Join(policyStore.path, "x"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := policyDraft.commitActivate(nil); !errors.Is(err, errDraftPersistFailed) {
		t.Fatalf("failed running persist did not refuse the commit (err=%v)", err)
	}
	if !policyDraft.active() {
		t.Fatal("failed commit cleared the draft")
	}
	if plFindTargetRule(added.ID) == nil {
		t.Fatal("failed commit lost the staged rule")
	}
	if policyStore.findByIDCopy(added.ID) != nil {
		t.Fatal("failed commit left the activation in the in-memory running store")
	}
	if _, err := os.Stat(filepath.Join(draftDir, "policy_draft.json")); err != nil {
		t.Fatalf("failed commit removed policy_draft.json: %v", err)
	}
	// Codex round 9: the rollback's ReplaceAll advances the running
	// generation, so without a re-base the retained draft is base-stale and
	// the HANDLER path 409s every retry — stranding the draft behind a
	// discard-and-recreate.
	if policyDraft.baseGenerationStale() {
		t.Fatal("failed commit left the retained draft base-stale — the handler would 409 every retry")
	}

	// Fault cleared: the retried commit lands durably.
	if err := os.RemoveAll(policyStore.path); err != nil {
		t.Fatal(err)
	}
	if _, err := policyDraft.commitActivate(nil); err != nil {
		t.Fatalf("retry after fault clears: %v", err)
	}
	if policyStore.findByIDCopy(added.ID) == nil {
		t.Fatal("retried commit missing from running")
	}
	if _, err := os.Stat(policyStore.path); err != nil {
		t.Fatalf("retried commit not durable: %v", err)
	}
}

// TestCodexFix_DurableProofPersistsVerifiedSnapshot (Codex round 8): ordinary
// draft CRUD mutates the candidate under its OWN store lock, not c.mu — a
// writer landing between the durability proof and the persist used to get its
// ALTERED content persisted under a proof that verified something else. The
// proof and the durable bytes must be one consistent snapshot.
func TestCodexFix_DurableProofPersistsVerifiedSnapshot(t *testing.T) {
	draftDir := plDurableDraftHarness(t)
	_, targetID := plAcceptingWithStagedRule(t)
	verified := *plFindTargetRule(targetID)

	err := policyDraft.ensureDurableTarget(targetID, func(r *PolicyRule) bool {
		ok := r.Action == verified.Action
		// The racing ordinary writer, made deterministic: it lands AFTER the
		// proof read its snapshot and BEFORE the persist (it needs only the
		// candidate store's lock, which is free here).
		mutated := verified
		mutated.Action = ActionBlockPage
		if !policyDraft.cand.UpdateByID(targetID, mutated) {
			t.Errorf("test setup: concurrent mutation failed")
		}
		return ok
	})
	if err != nil {
		t.Fatalf("verified target reported not durable: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(draftDir, "policy_draft.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Rules []PolicyRule `json:"rules"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	for i := range p.Rules {
		if p.Rules[i].ID != targetID {
			continue
		}
		if p.Rules[i].Action != verified.Action {
			t.Fatalf("durable file carries UNVERIFIED content (action %q, proof verified %q)",
				p.Rules[i].Action, verified.Action)
		}
		return
	}
	t.Fatalf("target %s missing from the durable draft", targetID)
}

// TestCodexFix_AcceptRefusedWhenDraftModeDisarmedAtStagingMoment (round 11):
// the accept's unlocked Require-Commit check races the admin disarm path —
// the mode must be re-verified INSIDE the durable append's critical section,
// and the disarm must serialize on the same lock, so a staged rule can never
// land in a draft behind a disarmed mode.
func TestCodexFix_AcceptRefusedWhenDraftModeDisarmedAtStagingMoment(t *testing.T) {
	plDurableDraftHarness(t)
	setRequireCommit(true)

	// The disarm landing between the handler's check and the staging moment,
	// made deterministic: the locked primitive must refuse.
	setRequireCommit(false)
	disabled := false
	rule := PolicyRule{
		ID: newRuleID(), Name: "disarm-race", SourceGroup: "g", DestCategory: "m5b-cat",
		Action: ActionAllow, SSLAction: SSLInspect, Enabled: &disabled,
	}
	stampRuleMetadataForWrite(&rule, nil, "codexfix")
	ver, _ := effectivePolicyVersion()
	if _, err := policyDraft.stageDurableAppendArmed("codexfix", ver, rule); !errors.Is(err, errDraftModeDisarmed) {
		t.Fatalf("disarmed draft mode did not refuse the armed append (err=%v)", err)
	}
	if policyDraft.active() {
		t.Fatal("refused append still opened a draft")
	}

	// And the disarm side: with an ACTIVE draft the atomic disarm refuses.
	setRequireCommit(true)
	if _, err := policyDraft.stageDurableAppendArmed("codexfix", ver, rule); err != nil {
		t.Fatalf("armed append: %v", err)
	}
	if err := policyDraft.disarmRequireCommit(); err == nil {
		t.Fatal("disarm succeeded with an active draft")
	}
	if !requireCommitEnabled() {
		t.Fatal("failed disarm still cleared the flag")
	}
}

// TestPolicyContentIdentityCached_DefaultActionInvalidates (Codex round 14):
// the memo must key on the default action too — its setter flips an atomic
// WITHOUT advancing the policy generation, so a generation-only key served
// the stale hash through a deny→allow→deny flip and the per-observation
// churn check never latched the transient allow window.
func TestPolicyContentIdentityCached_DefaultActionInvalidates(t *testing.T) {
	prev := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(prev) })

	setDefaultPolicyAction("deny")
	h1 := policyContentIdentityCached()
	setDefaultPolicyAction("allow") // no rule change: generation does NOT move
	h2 := policyContentIdentityCached()
	if h2 == h1 {
		t.Fatal("default-action flip served the stale cached content hash — the transient window would never latch churn")
	}
	setDefaultPolicyAction("deny")
	h3 := policyContentIdentityCached()
	if h3 != h1 {
		t.Fatalf("restored default action did not restore the content hash (h1=%s h3=%s)", h1, h3)
	}
}

// TestPolicyContentIdentity_IgnoresProvenanceStamps (Codex round 4): the
// policy CONTENT hash pins what the policy SAYS — stampRuleMetadataForWrite
// restamps ModifiedAt/By on EVERY save, so a semantically identical re-save
// must not change the hash (it staled every recommendation), exactly as the
// draft comparator sameRuleContent already canonicalizes. Semantic changes
// still change it.
func TestPolicyContentIdentity_IgnoresProvenanceStamps(t *testing.T) {
	plDurableDraftHarness(t)
	enabled := true
	r := PolicyRule{
		ID: newRuleID(), Name: "content-hash", SourceGroup: "g", DestCategory: "m5b-cat",
		Action: ActionAllow, SSLAction: SSLInspect, Enabled: &enabled,
		CreatedAt: "2026-08-01T00:00:00Z", ModifiedAt: "2026-08-21T10:00:00Z", ModifiedBy: "alice",
	}
	policyStore.ReplaceAll([]PolicyRule{r})
	base := policyContentIdentity()

	resaved := r
	resaved.ModifiedAt = "2026-08-21T11:11:11Z"
	resaved.ModifiedBy = "bob"
	policyStore.ReplaceAll([]PolicyRule{resaved})
	if policyContentIdentity() != base {
		t.Fatal("provenance-only re-save changed the policy content hash")
	}

	resaved.HitCount = 42
	resaved.LastHit = "2026-08-21T11:12:00Z"
	policyStore.ReplaceAll([]PolicyRule{resaved})
	if policyContentIdentity() != base {
		t.Fatal("hit churn changed the policy content hash")
	}

	resaved.Action = ActionBlockPage
	policyStore.ReplaceAll([]PolicyRule{resaved})
	if policyContentIdentity() == base {
		t.Fatal("semantic change did not change the policy content hash")
	}
}

// TestPolicyContentMemoized_MidHashFlipNeverPoisonsMemo (Codex round 18):
// policyContentIdentity re-reads live state, so a key component moving
// between the memo-key read and the hash completion used to store the NEW
// content's hash under the OLD key. The poisoned entry then answered every
// later read matching the old key — e.g. a transient default-allow window
// served the deny hash, so observations stamped during it claimed the
// baseline identity and the churn check never latched. The seam-injected
// core deterministically interleaves the flip mid-hash: the post-flip hash
// must never publish under the pre-flip key.
func TestPolicyContentMemoized_MidHashFlipNeverPoisonsMemo(t *testing.T) {
	prev := policyContentMemo.Load()
	policyContentMemo.Store(nil)
	t.Cleanup(func() { policyContentMemo.Store(prev) })

	k1 := policyContentKey{gen: 7, catgroupRev: 3, defaultRev: 1}
	k2 := policyContentKey{gen: 7, catgroupRev: 3, defaultRev: 2}
	keyCalls := 0
	keyNow := func() policyContentKey {
		keyCalls++
		if keyCalls == 1 {
			return k1 // the read that opens the bracket
		}
		return k2 // the admin flip lands before the hash completes
	}
	hash := func() string { return "H2" } // hash() observes the post-flip state

	if got := policyContentMemoized(keyNow, hash); got != "H2" {
		t.Fatalf("memoized = %q, want the post-flip hash H2", got)
	}
	m := policyContentMemo.Load()
	if m == nil {
		t.Fatal("no memo entry published")
	}
	if m.key == k1 {
		t.Fatal("post-flip hash stored under the pre-flip key — poisoned memo entry")
	}
	if m.key != k2 || m.hash != "H2" {
		t.Fatalf("memo = {%+v %q}, want a consistent {k2, H2}", m.key, m.hash)
	}
}

// TestSetDefaultPolicyAction_RoundTripMovesRevision (Codex rounds 18/19):
// the default action value is two-state, so value equality across a bracket
// cannot prove it held throughout (allow→deny→allow lands back on the same
// value — ABA). The memo key therefore carries the packed state word, whose
// set counter every mutation must advance — and because value and counter
// share ONE atomic word, a reader can never observe the new value with the
// old change signal (the round-19 descheduled-setter window).
func TestSetDefaultPolicyAction_RoundTripMovesRevision(t *testing.T) {
	prev := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(prev) })

	before := defaultPolicyActionState.Load()
	setDefaultPolicyAction("allow")
	mid := defaultPolicyActionState.Load()
	setDefaultPolicyAction("deny")
	after := defaultPolicyActionState.Load()
	if moved := (after >> 1) - (before >> 1); moved < 2 {
		t.Fatalf("round trip advanced the set counter by %d, want ≥2 — ABA invisible to the memo key", moved)
	}
	// The value rides the SAME word as the counter: each observed word must
	// carry the action just set, so value and signal cannot be out of step.
	if mid&1 != 1 || after&1 != 0 {
		t.Fatalf("packed word carries the wrong action (mid=%b after=%b)", mid, after)
	}
	if mid <= before || after <= mid {
		t.Fatalf("packed word not strictly increasing (%d, %d, %d)", before, mid, after)
	}
}

// TestPolicyContentIdentity_CategoryGroupMembership (Codex round 17): a rule
// with DestCategoryGroup resolves the group's CURRENT membership at
// evaluation time, so group edits change enforcement without touching the
// rulebase, the policy generation, or the category epoch. The content
// identity must cover the groups — and the memo must key on the group store's
// revision so the cached path sees the edit immediately. Canonicalization is
// pinned too: provenance restamps, display case, and member order must not
// stale (the identity is restart-stable content, never a counter).
func TestPolicyContentIdentity_CategoryGroupMembership(t *testing.T) {
	plDurableDraftHarness(t)
	snapshotGlobalCategoryGroups(t)

	enabled := true
	policyStore.ReplaceAll([]PolicyRule{{
		ID: newRuleID(), Name: "group-rule", SourceGroup: "g",
		DestCategoryGroup: "Prod Allowed", Action: ActionAllow, SSLAction: SSLInspect, Enabled: &enabled,
	}})
	if _, err := globalCategoryGroups.Add("Prod Allowed", []string{"saas", "devtools"}); err != nil {
		t.Fatal(err)
	}
	base := policyContentIdentityCached()

	// Membership edit: enforcement changes; nothing else moves. Both the
	// direct hash and the CACHED path must change (the memo key carries the
	// group revision — a generation+action key served the stale hash).
	if err := globalCategoryGroups.Update("Prod Allowed", []string{"saas"}); err != nil {
		t.Fatal(err)
	}
	if policyContentIdentityCached() == base {
		t.Fatal("category-group membership edit did not change the cached policy content identity")
	}

	// Restore the membership with different case and order: canonically the
	// same content, so the identity must return to base (restart-stable, no
	// false-stale on spelling).
	if err := globalCategoryGroups.Update("Prod Allowed", []string{"DevTools", "SaaS"}); err != nil {
		t.Fatal(err)
	}
	if policyContentIdentityCached() != base {
		t.Fatal("canonically identical group membership produced a different identity (false stale)")
	}
}

// TestEffectivePolicySnapshot_CoherentUnderConcurrentCommit (round 15): the
// tester's rules and rulebase label must come from ONE coordinator-locked
// view — separate engagement/list/label reads interleaving with a commit
// could evaluate an EMPTY candidate or mislabel a draft snapshot "running".
// Bounded stress under -race: the snapshot must never observe an empty
// rulebase and its label must match its content.
func TestEffectivePolicySnapshot_CoherentUnderConcurrentCommit(t *testing.T) {
	plDurableDraftHarness(t)
	setRequireCommit(true)
	for i := 0; i < 40; i++ {
		disabled := false
		rule := PolicyRule{
			ID: newRuleID(), Name: fmt.Sprintf("snap-stress-%d", i), SourceGroup: "g",
			DestCategory: "m5b-cat", Action: ActionAllow, SSLAction: SSLInspect, Enabled: &disabled,
		}
		stampRuleMetadataForWrite(&rule, nil, "codexfix")
		ver, _ := effectivePolicyVersion()
		if _, err := policyDraft.stageDurableAppend("codexfix", ver, rule); err != nil {
			t.Fatalf("stage: %v", err)
		}
		commitDone := make(chan struct{})
		go func() {
			_, _ = policyDraft.commitActivate(nil)
			close(commitDone)
		}()
		rules, label := effectivePolicySnapshot()
		<-commitDone
		if len(rules) == 0 {
			t.Fatalf("iteration %d: snapshot observed an EMPTY rulebase mid-commit (label=%q)", i, label)
		}
		if label != "draft" && label != "running" {
			t.Fatalf("iteration %d: unknown rulebase label %q", i, label)
		}
	}
}

// TestCodexFix_OrdinaryDraftEditNeverVanishesUnderCommit (round 16): an
// ordinary CRUD handler mutates the candidate under the store's own lock, so
// a commit's snapshot→clear could swallow the edit while the handler
// reported success. The writeGate serializes the handler's whole
// mutate-then-finalize sequence with the commit; bounded stress under -race
// using the exact handler bracket.
func TestCodexFix_OrdinaryDraftEditNeverVanishesUnderCommit(t *testing.T) {
	plDurableDraftHarness(t)
	setRequireCommit(true)
	for i := 0; i < 40; i++ {
		disabled := false
		rule := PolicyRule{
			ID: newRuleID(), Name: fmt.Sprintf("edit-stress-%d", i), SourceGroup: "g",
			DestCategory: "m5b-cat", Action: ActionAllow, SSLAction: SSLInspect, Enabled: &disabled,
		}
		stampRuleMetadataForWrite(&rule, nil, "codexfix")
		ver, _ := effectivePolicyVersion()
		if _, err := policyDraft.stageDurableAppend("codexfix", ver, rule); err != nil {
			t.Fatalf("stage: %v", err)
		}

		commitDone := make(chan struct{})
		go func() {
			// The commit handler's bracket: exclusive gate around activation.
			policyDraft.writeGate.Lock()
			_, _ = policyDraft.commitActivate(nil)
			policyDraft.writeGate.Unlock()
			close(commitDone)
		}()

		// The ordinary handler's bracket: mutate + finalize under the read side.
		mutated := rule
		mutated.Action = ActionBlockPage
		beginPolicyWrite()
		ok := policyWriteStore("codexfix").UpdateByID(rule.ID, mutated)
		if ok {
			if policyDraftEngaged() {
				policyDraft.persist()
			} else {
				policyStore.Save()
			}
		}
		endPolicyWrite()
		<-commitDone

		if !ok {
			continue // the commit won and cleared the draft before the handler's store fetch — the edit was refused, not swallowed
		}
		got := plFindTargetRule(rule.ID)
		if got == nil {
			t.Fatalf("iteration %d: successful edit vanished (in neither candidate nor running)", i)
		}
		if got.Action != ActionBlockPage {
			t.Fatalf("iteration %d: successful edit's content lost (action=%q)", i, got.Action)
		}
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

// TestCodexFix_AcceptTransactionHoldsPolicyWriteGate (round 26): the whole
// acceptance transaction must hold the coordinator's policy WRITE gate —
// ordinary CRUD (read side) and commit/revert (write side) could otherwise
// interleave between the version fence and the durable append (bypassing the
// optimistic conflict) or between the append and the accepted latch (latching
// accepted with an absent target). Pinned behaviorally: an in-flight policy
// write (read side held, as every CRUD handler holds it) must block the
// acceptance until released.
func TestCodexFix_AcceptTransactionHoldsPolicyWriteGate(t *testing.T) {
	plDurableDraftHarness(t)
	recID, _ := plAcceptingWithStagedRule(t)

	beginPolicyWrite() // an ordinary CRUD write in flight
	done := make(chan struct{})
	go func() {
		defer close(done)
		ver, _ := effectivePolicyVersion()
		_, _ = plAcceptRecommendation(policyLearnEngine.Load(), recID, ver, "codexfix")
	}()
	select {
	case <-done:
		endPolicyWrite()
		t.Fatal("acceptance completed while an ordinary policy write held the gate — the transaction is not serialized")
	case <-time.After(100 * time.Millisecond):
	}
	endPolicyWrite()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("acceptance never completed after the gate was released")
	}
	assertAcceptedImpliesTarget(t, recID)
}

// ── Codex round 29: late-loss charge vs the acceptance transaction ─────────

// plSeedRecWithWindow is plSeedRecommendation with the session's
// acceptance-window generation captured while it is OPEN, so a test can
// deliver a LATE captured-window decision after the session completes.
func plSeedRecWithWindow(t *testing.T) (recID string, gen uint64) {
	t.Helper()
	if err := catStore.Set("m5b-cat", []string{"m5b.example"}, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = catStore.Delete("m5b-cat") })
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin,
		`{"enabled":true,"recommendable_categories":["m5b-cat"]}`); w.Code != 200 {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	plStartSession(t)
	g, ok := policyLearnEngine.Load().CaptureWindow()
	if !ok {
		t.Fatal("CaptureWindow refused with an active session")
	}
	plObserve(t, "m5b-user@corp.example", []string{"m5b-team"}, "m5b.example")
	sessID := plCompleteSession(t)
	if w := plDo(apiPolicyLearningGenerate, http.MethodPost, "/api/policy-learning/recommendations/generate", RoleOperator,
		`{"session_id":"`+sessID+`"}`); w.Code != 200 {
		t.Fatalf("generate: %d %s", w.Code, w.Body.String())
	}
	recs := plRecsGET(t)
	if len(recs.Recommendations) != 1 {
		t.Fatalf("seed: %d recommendations", len(recs.Recommendations))
	}
	return recs.Recommendations[0].ID, g
}

// plLateDecision delivers one captured-window decision AFTER its window
// closed, through the production Observe path (admission → charge — the same
// route a request goroutine's stale learnDecisionCtx takes).
func plLateDecision(t *testing.T, gen uint64) {
	t.Helper()
	policyLearnEngine.Load().Observe(policylearn.Observation{
		WindowGen: gen, Host: "late.example", Method: "GET", Status: "OK", At: time.Now().Unix(),
	})
}

// TestCodexFix_LateChargeInvalidatesAcceptingIntentBeforeMutation (round 29):
// a late loss charge landing between BeginAccept and the draft mutation used
// to be skipped by the supersession walk (accepting ≠ generated), so the
// acceptance created and finalized a rule from evidence whose loss accounting
// had just changed. The accept must refuse (409 family), the intent must
// resolve to superseded, and NO draft rule may exist.
func TestCodexFix_LateChargeInvalidatesAcceptingIntentBeforeMutation(t *testing.T) {
	plDurableDraftHarness(t)
	recID, gen := plSeedRecWithWindow(t)
	setRequireCommit(true)
	eng := policyLearnEngine.Load()
	rec, err := eng.BeginAccept(recID, newRuleID())
	if err != nil {
		t.Fatal(err)
	}

	plLateDecision(t, gen)

	ver, _ := effectivePolicyVersion()
	if _, err := plAcceptRecommendation(eng, recID, ver, "codexfix"); !errors.Is(err, policylearn.ErrAcceptInvalidatedByLateLoss) {
		t.Fatalf("accept after late-loss charge = %v, want ErrAcceptInvalidatedByLateLoss", err)
	}
	got, ok := eng.RecommendationByID(recID)
	if !ok || got.State != policylearn.RecStateSuperseded {
		t.Fatalf("invalidated intent state = %s, want superseded", got.State)
	}
	if plFindTargetRule(rec.TargetRuleID) != nil {
		t.Fatalf("a draft rule %s exists for an invalidated intent", rec.TargetRuleID)
	}
}

// TestCodexFix_LateChargeAfterAppendCompensatesDraftRule (round 29): the
// charge lands AFTER the draft rule was durably staged but before the
// finalize latch — the engine-atomic FinalizeAccept refusal must hold and the
// root must compensate the candidate rule away (draft-only) before latching
// superseded.
func TestCodexFix_LateChargeAfterAppendCompensatesDraftRule(t *testing.T) {
	plDurableDraftHarness(t)
	recID, gen := plSeedRecWithWindow(t)
	setRequireCommit(true)
	eng := policyLearnEngine.Load()
	rec, err := eng.BeginAccept(recID, newRuleID())
	if err != nil {
		t.Fatal(err)
	}
	rule := plTranslateRecommendation(&rec)
	stampRuleMetadataForWrite(&rule, nil, "codexfix")
	ver, _ := effectivePolicyVersion()
	if _, err := policyDraft.stageDurableAppend("codexfix", ver, rule); err != nil {
		t.Fatalf("stageDurableAppend: %v", err)
	}

	plLateDecision(t, gen)

	ver2, _ := effectivePolicyVersion()
	if _, err := plAcceptRecommendation(eng, recID, ver2, "codexfix"); !errors.Is(err, policylearn.ErrAcceptInvalidatedByLateLoss) {
		t.Fatalf("resume after late-loss charge = %v, want ErrAcceptInvalidatedByLateLoss", err)
	}
	got, ok := eng.RecommendationByID(recID)
	if !ok || got.State != policylearn.RecStateSuperseded {
		t.Fatalf("invalidated intent state = %s, want superseded", got.State)
	}
	if plFindTargetRule(rec.TargetRuleID) != nil {
		t.Fatalf("candidate still carries rule %s after the compensating removal", rec.TargetRuleID)
	}
}
