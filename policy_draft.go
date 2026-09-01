package main

// policy_draft.go — Candidate/commit (draft/staging) for the Stage-2 policy
// rulebase (P3 policy-draft / gap G2). Authority: docs/design/POLICY-DRAFT-DESIGN.md.
//
// Opt-in: the persisted RequireCommit setting (default false) gates the whole
// feature. When OFF, policyWriteStore()==policyStore and every policy write
// path is byte-identical to the pre-feature live-write behavior — the
// coordinator below is never consulted. When ON, rulebase writes stage into a
// single shared candidate (a second *PolicyStore, persisted to policy_draft.json
// so a draft survives a restart) and an explicit commit activates them.
//
// Enforcement (policyStore.Evaluate) and every proxy hot-path read ALWAYS use
// policyStore directly and are untouched by this file.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// ── Opt-in flag ────────────────────────────────────────────────────────────

var requireCommitFlag atomicBoolShim

func requireCommitEnabled() bool { return requireCommitFlag.Load() }
func setRequireCommit(v bool)    { requireCommitFlag.Store(v) }

// atomicBoolShim is a tiny mutex-guarded bool (avoids importing sync/atomic just
// for one flag and keeps the zero value usable). Read-heavy, write-rare.
type atomicBoolShim struct {
	mu sync.RWMutex
	v  bool
}

func (a *atomicBoolShim) Load() bool   { a.mu.RLock(); defer a.mu.RUnlock(); return a.v }
func (a *atomicBoolShim) Store(v bool) { a.mu.Lock(); a.v = v; a.mu.Unlock() }

// ── Coordinator ────────────────────────────────────────────────────────────

// draftState is the persisted metadata for the single shared candidate.
type draftState struct {
	Active         bool   `json:"active"`         // a draft diverging from running exists
	Actor          string `json:"actor"`          // admin who opened the current draft
	StartedAt      string `json:"startedAt"`      // RFC3339 UTC
	BaseGeneration int64  `json:"baseGeneration"` // policyStore generation the draft forked from
}

// policyDraftCoordinator owns the candidate rulebase and its lifecycle.
type policyDraftCoordinator struct {
	mu    sync.Mutex
	cand  *PolicyStore // candidate rules; in-memory (path=""), persisted by this coordinator
	state draftState
	path  string // policy_draft.json ("" ⇒ in-memory, no persistence)

	// writeGate serializes ORDINARY policy-write handler sequences (read
	// side, via beginPolicyWrite/endPolicyWrite) with the commit/revert API
	// entry points (exclusive side) — see beginPolicyWrite (Codex round 16).
	writeGate sync.RWMutex
}

var policyDraft = &policyDraftCoordinator{cand: &PolicyStore{}}

// initPolicyDraft wires the coordinator's persistence path (sibling of the
// policy file) and reloads any draft left pending by a prior run. A "" policy
// path (in-memory mode) leaves the draft in-memory too.
func initPolicyDraft(policyPath string) {
	policyDraft.mu.Lock()
	defer policyDraft.mu.Unlock()
	if policyPath == "" {
		policyDraft.path = ""
		return
	}
	policyDraft.path = filepath.Join(filepath.Dir(policyPath), "policy_draft.json")
	data, err := os.ReadFile(policyDraft.path)
	if err != nil {
		return // no pending draft
	}
	var p struct {
		State draftState   `json:"state"`
		Rules []PolicyRule `json:"rules"`
	}
	if json.Unmarshal(data, &p) != nil || !p.State.Active {
		return
	}
	policyDraft.cand.ReplaceAll(p.Rules)
	policyDraft.state = p.State
	logger.Printf("PolicyDraft: reloaded pending draft (%d rules) opened by %s", len(p.Rules), sanitizeLog(p.State.Actor))
}

// active reports whether a dirty draft exists.
func (c *policyDraftCoordinator) active() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.Active
}

// snapshotState returns a copy of the draft metadata.
func (c *policyDraftCoordinator) snapshotState() draftState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// stageTarget returns the candidate store for a policy WRITE, opening the draft
// (seeding it from running) on the first write of a new draft. Only called when
// RequireCommit is on.
func (c *policyDraftCoordinator) stageTarget(actor string) *PolicyStore {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.state.Active {
		// Fork the candidate from the current running rulebase.
		baseGen, _ := policyStore.policyVersion()
		c.cand.ReplaceAll(policyStore.List())
		c.state = draftState{
			Active:         true,
			Actor:          actor,
			StartedAt:      time.Now().UTC().Format(time.RFC3339),
			BaseGeneration: baseGen,
		}
	}
	return c.cand
}

// candidateList / candidateVersion expose the candidate for the effective-read
// helpers (list rendering + optimistic concurrency while drafting).
func (c *policyDraftCoordinator) candidateList() []PolicyRule { return c.cand.List() }
func (c *policyDraftCoordinator) candidateVersion() (version int64, updatedAt string) {
	return c.cand.policyVersion()
}

// persist writes the candidate + state to disk (or clears the file when the
// draft is no longer active). Best-effort; a persistence failure is logged but
// does not fail the API mutation (the in-memory draft is still authoritative
// for this process).
func (c *policyDraftCoordinator) persist() {
	// Capture everything and write under the SAME lock (see persistLocked) —
	// reading c.cand.List() after releasing c.mu races a concurrent clear()
	// (commit / revert by another admin): clear could empty the candidate and
	// delete the file in between, so we'd re-create policy_draft.json with
	// state.Active=true and zero rules — a corrupt draft that, on restart,
	// renders an empty rulebase and (baseGeneration permitting) lets a commit
	// wipe running. This wrapper keeps the LEGACY best-effort posture (log,
	// don't fail the mutation); durable callers use persistLocked directly.
	c.mu.Lock()
	err := c.persistLocked()
	c.mu.Unlock()
	if err != nil {
		logger.Printf("PolicyDraft: %v", err)
	}
}

// persistLocked serializes state+candidate and writes atomically, RETURNING
// the outcome (M5B.1: the durable-append primitive must know whether the
// candidate is recoverable after a restart; the legacy persist() wrapper keeps
// logging it away). Caller holds c.mu.
func (c *policyDraftCoordinator) persistLocked() error {
	return c.persistSnapshotLocked(c.cand.List())
}

// persistSnapshotLocked writes ONE GIVEN candidate snapshot (Codex fix):
// ordinary draft CRUD mutates the candidate store under its OWN lock, not
// c.mu, so a persist that re-reads c.cand.List() can capture content that
// changed after the caller verified it. Callers that prove content (the
// durability proof) pass the exact snapshot they verified, making the proof
// and the durable bytes one consistent view; a racing ordinary update's own
// persist() follows serialized behind c.mu with its content, as a later
// mutation. Caller holds c.mu.
func (c *policyDraftCoordinator) persistSnapshotLocked(rules []PolicyRule) error {
	if c.path == "" {
		return nil // in-memory mode: no durable domain exists by configuration
	}
	if !c.state.Active {
		_ = os.Remove(c.path)
		return nil
	}
	p := struct {
		State draftState   `json:"state"`
		Rules []PolicyRule `json:"rules"`
	}{State: c.state, Rules: rules}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}
	if err := fileutil.AtomicWrite(c.path, data, 0o600); err != nil {
		if errors.Is(err, fileutil.ErrReplacedNotSynced) {
			// Post-rename failure: policy_draft.json already carries the new
			// content, so the durable domain HOLDS the write — reporting
			// failure would trigger compensating rollbacks (delete the
			// appended rule) that contradict the file a restart recovers
			// (Codex round-8/10 class). The write-failure observer has
			// already surfaced the storage degradation.
			return nil
		}
		return fmt.Errorf("write error: %w", err)
	}
	return nil
}

// ── M5B.1: durable check-and-mutate primitive ────────────────────────────────

// Sentinel errors for stageDurableAppend callers.
var (
	errDraftVersionConflict = errors.New("draft/policy version changed since the fence was read")
	errDraftPersistFailed   = errors.New("draft persistence failed — the mutation was rolled back, nothing durable changed")
)

// stageDurableAppend is the persist-before-publish / check-and-mutate
// primitive (M5B.1): expected version → validate fence → append to the
// candidate → DURABLE persist → success. All of it runs under ONE coordinator
// lock, so for primitive callers the fence check and the mutation are atomic
// (the legacy handlers' optimistic check→stageTarget→Add sequence keeps its
// documented posture). A persist failure is returned to the caller and the
// append is rolled back (compensating delete of the exact preallocated ID —
// or, when this call opened the draft fork, the fork is discarded), so a
// successful return means the rule is recoverable from policy_draft.json
// after a process restart. In-memory mode (no persistence path) has no
// durable domain by configuration; persistence is then vacuously successful.
//
// Reusable by any caller needing durable append semantics; the Learning
// accept path (policy_learning_accept.go) is the first.
func (c *policyDraftCoordinator) stageDurableAppend(actor string, expectedVersion int64, rule PolicyRule) (PolicyRule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stageDurableAppendLocked(actor, expectedVersion, rule)
}

// errDraftModeDisarmed: a draft-mode-REQUIRING durable append found Require
// Commit disarmed at the locked moment of the mutation (see
// stageDurableAppendArmed).
var errDraftModeDisarmed = errors.New("draft mode (Require Commit) is not armed")

// stageDurableAppendArmed is stageDurableAppend for callers whose semantics
// REQUIRE draft mode (the learning accept): Require Commit is re-verified
// INSIDE the same critical section as the mutation (Codex fix) — the caller's
// earlier unlocked check races the admin disarm path, which used to observe
// "no active draft" before this append opened the fork, disarm the mode, and
// leave the freshly staged rule in a draft hidden from effective policy
// views. Disarm itself now serializes on c.mu (disarmRequireCommit), so
// either the disarm wins (this refuses) or the append wins (the draft is
// active and the disarm refuses).
// Concurrency note (Codex round 26): the version fence below reads the
// CANDIDATE's generation, which ordinary draft CRUD mutates under
// writeGate.RLock + PolicyStore.mu — neither conflicts with c.mu. The
// production caller (plAcceptRecommendation) therefore holds writeGate's
// WRITE side across this call and the subsequent accepted latch, making
// fence + append + latch one policy-write transaction that CRUD, commit,
// revert, and delete cannot interleave with.
func (c *policyDraftCoordinator) stageDurableAppendArmed(actor string, expectedVersion int64, rule PolicyRule) (PolicyRule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !requireCommitEnabled() {
		return PolicyRule{}, errDraftModeDisarmed
	}
	return c.stageDurableAppendLocked(actor, expectedVersion, rule)
}

// disarmRequireCommit turns Require Commit off ATOMICALLY with the
// active-draft check, under the same coordinator lock the durable-append
// primitives hold (Codex fix): the handler's detached check-then-set could
// interleave with an acceptance opening the first draft, stranding staged
// changes behind a disarmed mode.
func (c *policyDraftCoordinator) disarmRequireCommit() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Active {
		return errors.New("a draft with pending changes exists — commit or revert it before disabling commit mode")
	}
	setRequireCommit(false)
	return nil
}

func (c *policyDraftCoordinator) stageDurableAppendLocked(actor string, expectedVersion int64, rule PolicyRule) (PolicyRule, error) {
	var cur int64
	if c.state.Active {
		cur, _ = c.cand.policyVersion()
	} else {
		cur, _ = policyStore.policyVersion()
	}
	if cur != expectedVersion {
		return PolicyRule{}, fmt.Errorf("expected version %d, current %d: %w", expectedVersion, cur, errDraftVersionConflict)
	}
	opened := false
	if !c.state.Active {
		baseGen, _ := policyStore.policyVersion()
		c.cand.ReplaceAll(policyStore.List())
		c.state = draftState{
			Active:         true,
			Actor:          actor,
			StartedAt:      time.Now().UTC().Format(time.RFC3339),
			BaseGeneration: baseGen,
		}
		opened = true
	}
	added := c.cand.Add(rule)
	if err := c.persistLocked(); err != nil {
		if opened {
			// This call opened the fork: discard it entirely (candidate back to
			// "no draft"; the file write failed, so there is nothing on disk).
			_ = c.clearLocked()
		} else {
			c.cand.DeleteByID(added.ID) // exact compensating rollback
		}
		return PolicyRule{}, fmt.Errorf("%v: %w", err, errDraftPersistFailed)
	}
	return added, nil
}

// durableTargetPresent reports whether ruleID is recoverable from the DURABLE
// draft domain — the persisted policy_draft.json as it would be reloaded after
// a process restart. Fail-closed on read/parse errors. In-memory mode (no
// path) the candidate itself is the domain, so membership there answers.
func (c *policyDraftCoordinator) durableTargetPresent(ruleID string) bool {
	c.mu.Lock()
	path := c.path
	inMemory := false
	if path == "" && c.state.Active {
		rules := c.cand.List()
		for i := range rules { // index-based: PolicyRule is a large struct (rangeValCopy)
			if rules[i].ID == ruleID {
				inMemory = true
			}
		}
	}
	c.mu.Unlock()
	if path == "" {
		return inMemory
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var p struct {
		State draftState   `json:"state"`
		Rules []PolicyRule `json:"rules"`
	}
	if json.Unmarshal(raw, &p) != nil || !p.State.Active {
		return false
	}
	for i := range p.Rules {
		if p.Rules[i].ID == ruleID {
			return true
		}
	}
	return false
}

// removeDurableTarget durably removes ruleID from the ACTIVE candidate — the
// compensating half of stageDurableAppend for an acceptance whose intent was
// invalidated AFTER the append (Codex round 29). Candidate-only by
// construction (never the running store: a rule that reached RUNNING was
// committed by an admin through the canonical path and is theirs). No active
// draft or an absent target is success — nothing to compensate. matches, when
// non-nil, guards admin work: a candidate rule whose content no longer
// matches was edited by an admin after the append and is LEFT IN PLACE
// (success — the rule is admin-owned now). A persist failure restores the
// removed rule and returns the failure so the caller leaves the intent
// pending for a deterministic retry.
func (c *policyDraftCoordinator) removeDurableTarget(ruleID string, matches func(*PolicyRule) bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.state.Active {
		return nil
	}
	rules := c.cand.List()
	var removed *PolicyRule
	for i := range rules { // index-based: PolicyRule is a large struct (rangeValCopy)
		if rules[i].ID == ruleID {
			removed = &rules[i]
			break
		}
	}
	if removed == nil {
		return nil
	}
	if matches != nil && !matches(removed) {
		return nil
	}
	c.cand.DeleteByID(ruleID)
	if err := c.persistLocked(); err != nil {
		c.cand.Add(*removed) // exact compensating restore (ID is free again, so Add preserves it)
		return fmt.Errorf("%v: %w", err, errDraftPersistFailed)
	}
	return nil
}

// errDraftTargetMissing: the target rule is not a member of the ACTIVE
// candidate at the locked moment of the durability proof — a concurrent
// revert/delete/commit removed it after an earlier unlocked lookup saw it.
var errDraftTargetMissing = errors.New("draft target rule is no longer in the candidate")

// errDraftTargetContentDrift: the target rule IS a member of the locked
// candidate but its content no longer matches the caller's expectation — a
// concurrent draft update altered it after an earlier unlocked comparison.
var errDraftTargetContentDrift = errors.New("draft target rule content changed since it was verified")

// ensureDurableTarget guarantees ruleID is durably recoverable from the draft
// domain, with MEMBERSHIP PROVEN UNDER THE SAME LOCK AS THE PERSIST (Codex
// fix): between an unlocked lookup and this call a concurrent draft
// revert/delete/commit can remove the target, and the old shape re-persisted
// whatever the candidate then held — even an inactive draft — and reported
// durable. Now: the target must be a member of the locked ACTIVE candidate or
// this returns errDraftTargetMissing (the caller decides running-store or
// refuse semantics); membership proven, the candidate is persisted under the
// same critical section. In-memory mode (no path) the locked candidate itself
// is the durable domain.
// matches, when non-nil, is verified against the located rule INSIDE the same
// critical section (Codex fix: the earlier unlocked content comparison can be
// invalidated by a concurrent ordinary draft update; the durability point is
// the last responsible moment to prove the content still holds).
func (c *policyDraftCoordinator) ensureDurableTarget(ruleID string, matches func(*PolicyRule) bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.state.Active {
		return errDraftTargetMissing
	}
	// ONE consistent snapshot: membership and content are proven against it,
	// and the SAME snapshot is persisted (Codex fix) — ordinary draft CRUD
	// holds only the candidate store's own lock, so a persist that re-read
	// the candidate could capture content altered AFTER the proof.
	rules := c.cand.List()
	var member *PolicyRule
	for i := range rules { // index-based: PolicyRule is a large struct (rangeValCopy)
		if rules[i].ID == ruleID {
			member = &rules[i]
			break
		}
	}
	if member == nil {
		return errDraftTargetMissing
	}
	if matches != nil && !matches(member) {
		return errDraftTargetContentDrift
	}
	if c.path == "" {
		return nil // in-memory mode: locked membership is the domain
	}
	if err := c.persistSnapshotLocked(rules); err != nil {
		return fmt.Errorf("%v: %w", err, errDraftPersistFailed)
	}
	return nil
}

// commitActivate is the COMMIT critical section (Codex fix): snapshot,
// set-validation, diff, activation (running := candidate), persistence, and
// draft clear all under ONE hold of c.mu — a concurrent stageDurableAppend
// (which also holds c.mu for its fence+append+persist) can therefore land
// either entirely BEFORE the snapshot (committed with everything else) or
// entirely AFTER the clear (it re-opens a fresh draft carrying the new rule);
// it can no longer slip between the snapshot and the clear, where the old
// sequence published the stale snapshot and deleted the freshly persisted
// rule while its acceptance had already reported success. Lock order
// c.mu → PolicyStore.mu (the stageTarget convention).
//
// ifVersion, when non-nil, is the candidate generation the operator reviewed,
// RE-VERIFIED here inside the same critical section (Codex fix): the handler's
// unlocked precondition can be invalidated by a stageDurableAppend landing
// between the handler's read and this lock — the commit would then activate a
// candidate carrying a staged rule the operator never saw. A mismatch returns
// errDraftVersionConflict and activates nothing.
func (c *policyDraftCoordinator) commitActivate(ifVersion *int64) (policyDraftDiff, error) {
	c.mu.Lock()
	if !c.state.Active {
		c.mu.Unlock()
		return policyDraftDiff{}, errors.New("no draft to commit")
	}
	if ifVersion != nil {
		if cur, _ := c.cand.policyVersion(); cur != *ifVersion {
			c.mu.Unlock()
			return policyDraftDiff{}, fmt.Errorf(
				"the draft changed since you loaded it (your version %d, current %d) — review and retry: %w",
				*ifVersion, cur, errDraftVersionConflict)
		}
	}
	cand := c.cand.List()
	for i := range cand {
		if err := validatePolicyRule(cand[i], cand, cand[i].Priority); err != nil {
			c.mu.Unlock()
			return policyDraftDiff{}, fmt.Errorf("candidate rule %s is invalid: %w", sanitizeLog(cand[i].Name), err)
		}
	}
	diff := c.diffVsRunning()
	// Activation is durable-or-nothing (Codex fix): a swallowed running-policy
	// write failure used to clear the draft anyway — new policy in memory, old
	// policy on disk, no draft — so a restart silently reverted the commit
	// (and a learning acceptance finalized against a target with no durable
	// home). On persist failure the in-memory activation is reverted and the
	// draft retained, so the operator can retry once the volume recovers.
	prevRunning := policyStore.List()
	policyStore.ReplaceAll(cand)
	if err := policyStore.SaveErr(); err != nil && errors.Is(err, fileutil.ErrReplacedNotSynced) {
		// Post-rename failure (Codex fix): the policy file already CARRIES the
		// candidate — rolling back memory would contradict the visible file
		// and a restart would activate the "failed" policy anyway. Proceed as
		// committed; the residual is rename durability across an immediate
		// crash (equivalent to crashing just before the commit), and the
		// CHAOS-45 write-failure observer has already surfaced the storage
		// degradation.
		logWarnf("PolicyDraft: commit content persisted but parent-dir sync failed: %v", err)
	} else if err != nil {
		policyStore.ReplaceAll(prevRunning)
		// Re-base the retained draft onto the RESTORED running (Codex fix):
		// both ReplaceAlls advanced the running generation with NO semantic
		// change — running is content-identical to the draft's fork point —
		// so keeping the original BaseGeneration would make every handler
		// RETRY 409 as base-stale, stranding the draft (and any accepted
		// learning target) behind a discard-and-recreate. The base-stale
		// guard's intent (detect an out-of-band import/rollback) is
		// preserved: a real out-of-band change after this point still moves
		// the generation past the re-based value.
		c.state.BaseGeneration, _ = policyStore.policyVersion()
		// Best-effort: keep the durable draft state consistent for a
		// post-restart retry; if this write fails too (same volume), the
		// on-disk draft keeps the old base and a post-restart retry is
		// refused base-stale — fail-closed, the operator re-stages.
		_ = c.persistLocked()
		c.mu.Unlock()
		return policyDraftDiff{}, fmt.Errorf("running-policy persist failed — draft retained, nothing committed: %v: %w", err, errDraftPersistFailed)
	}
	path := c.clearLocked()
	c.mu.Unlock()
	if path != "" {
		_ = os.Remove(path)
	}
	return diff, nil
}

// clearLocked resets the candidate + state; caller holds c.mu. Returns the
// persistence path so the caller can remove the file after releasing the lock.
func (c *policyDraftCoordinator) clearLocked() string {
	c.cand.ReplaceAll(nil)
	c.state = draftState{}
	return c.path
}

// clear discards the candidate and marks the draft inactive.
func (c *policyDraftCoordinator) clear() {
	c.mu.Lock()
	path := c.clearLocked()
	c.mu.Unlock()
	if path != "" {
		_ = os.Remove(path)
	}
}

// cascadeDecryptionProfileRename mirrors PolicyStore.CascadeDecryptionProfileRename
// onto the open candidate so a profile rename keeps the DRAFT's denormalized names
// honest too — otherwise a rename during an active draft would refresh running but
// leave the candidate carrying stale names that a later commit would write back.
// No-op when no draft is open. Persists only when a rule was actually touched.
// Lock order c.mu → PolicyStore.mu (as in stageTarget); persist() takes c.mu
// itself, so it runs after the unlock.
func (c *policyDraftCoordinator) cascadeDecryptionProfileRename(id, oldName, newName string) {
	c.mu.Lock()
	if !c.state.Active {
		c.mu.Unlock()
		return
	}
	n := c.cand.CascadeDecryptionProfileRename(id, oldName, newName)
	c.mu.Unlock()
	if n > 0 {
		c.persist()
	}
}

// cascadeDestCategoryGroupRename mirrors PolicyStore.CascadeDestCategoryGroupRename
// onto the open candidate (references-by-id S2), so a group rename keeps the
// DRAFT's denormalized names honest too. No-op when no draft is open; persists
// only when a rule was actually touched. Lock order c.mu → PolicyStore.mu.
func (c *policyDraftCoordinator) cascadeDestCategoryGroupRename(id, oldName, newName string) {
	c.mu.Lock()
	if !c.state.Active {
		c.mu.Unlock()
		return
	}
	n := c.cand.CascadeDestCategoryGroupRename(id, oldName, newName)
	c.mu.Unlock()
	if n > 0 {
		c.persist()
	}
}

// reconcile auto-discards the draft when its candidate has become identical to
// running — i.e. the last edit was a NO-OP (re-save with no change, drag-in-place,
// bulk-delete of absent priorities) or FAILED (TOCTOU mutation returned false
// after the draft was opened). Without this, such an edit would leave a
// zero-diff "active" draft that blocks commit-mode disarm and makes reads render
// the (identical) candidate — undermining the byte-identical-when-nothing-changed
// promise. A draft carrying REAL prior staged changes is never cleared (its diff
// is non-zero). Returns true if it cleared. No-op (returns false) when no draft
// is open, so callers can invoke it unconditionally, including in live-write mode.
func (c *policyDraftCoordinator) reconcile() bool {
	c.mu.Lock()
	if !c.state.Active {
		c.mu.Unlock()
		return false
	}
	// Compare under c.mu (lock order c.mu → PolicyStore.mu, as in stageTarget).
	if !sameRuleSet(policyStore.List(), c.cand.List()) {
		c.mu.Unlock()
		return false
	}
	path := c.clearLocked()
	c.mu.Unlock()
	if path != "" {
		_ = os.Remove(path)
	}
	return true
}

// sameRuleSet reports whether two rule sets are content-identical (by stable ID,
// order-independent; Priority is part of the content so a real reorder differs).
func sameRuleSet(a, b []PolicyRule) bool {
	if len(a) != len(b) {
		return false
	}
	am := make(map[string]PolicyRule, len(a))
	for i := range a {
		am[a[i].ID] = a[i]
	}
	for i := range b {
		av, ok := am[b[i].ID]
		if !ok || !sameRuleContent(av, b[i]) {
			return false
		}
	}
	return true
}

// baseGenerationStale reports whether running advanced past the generation the
// draft forked from (a direct import/rollback bypassed the draft). Commit fails
// closed in that case rather than clobber the out-of-band change.
func (c *policyDraftCoordinator) baseGenerationStale() bool {
	c.mu.Lock()
	base := c.state.BaseGeneration
	c.mu.Unlock()
	cur, _ := policyStore.policyVersion()
	return cur != base
}

// policyDraftDiff summarizes the candidate against running (by stable ID).
type policyDraftDiff struct {
	Added    []string `json:"added"`    // rule names present in candidate, not running
	Removed  []string `json:"removed"`  // present in running, not candidate
	Modified []string `json:"modified"` // same ID, changed content
}

func (d policyDraftDiff) total() int { return len(d.Added) + len(d.Removed) + len(d.Modified) }

// diffVsRunning computes the candidate→running change set. Keyed by rule ID
// (backfilled on load, so always present); content equality via JSON so every
// field participates without a hand-maintained comparator.
func (c *policyDraftCoordinator) diffVsRunning() policyDraftDiff {
	run := policyStore.List()
	cand := c.candidateList()
	runByID := make(map[string]PolicyRule, len(run))
	for i := range run {
		runByID[run[i].ID] = run[i]
	}
	candByID := make(map[string]PolicyRule, len(cand))
	for i := range cand {
		candByID[cand[i].ID] = cand[i]
	}
	var d policyDraftDiff
	for id := range candByID {
		cr := candByID[id]
		rr, ok := runByID[id]
		if !ok {
			d.Added = append(d.Added, cr.Name)
			continue
		}
		if !sameRuleContent(rr, cr) {
			d.Modified = append(d.Modified, cr.Name)
		}
	}
	for id := range runByID {
		if _, ok := candByID[id]; !ok {
			d.Removed = append(d.Removed, runByID[id].Name)
		}
	}
	return d
}

// sameRuleContent compares two rules by DEFINITION, ignoring fields that are not
// an operator edit to the rule's meaning: live counters, computed display
// strings, precomputed hot-path caches, and the provenance stamps
// (CreatedAt/ModifiedAt/ModifiedBy). The stamps matter especially here —
// stampRuleMetadataForWrite restamps ModifiedAt/By on EVERY save, so without
// ignoring them a re-save with no real change would read as "modified" (and a
// no-op would never reconcile away). Comment is admin-authored content and IS
// compared.
func sameRuleContent(a, b PolicyRule) bool {
	a.HitCount, b.HitCount = 0, 0
	a.lastHitUnix, b.lastHitUnix = 0, 0
	a.LastHit, b.LastHit = "", ""
	// Precomputed unexported hot-path caches are derived, not content.
	a.normFQDN, b.normFQDN = "", ""
	a.srcIPNet, b.srcIPNet = nil, nil
	a.srcPrefix, b.srcPrefix = netip.Prefix{}, netip.Prefix{}
	a.matchedConds, b.matchedConds = "", ""
	// Provenance stamps are a denormalized cache of audit truth, not definition.
	a.CreatedAt, b.CreatedAt = "", ""
	a.ModifiedAt, b.ModifiedAt = "", ""
	a.ModifiedBy, b.ModifiedBy = "", ""
	ba, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ba, bb)
}

// ── Effective-read + write helpers used by the policy handlers ─────────────

// policyWriteStore returns the store a policy WRITE handler mutates: the
// candidate when commit-mode is engaged (opening the draft on first write),
// else the running store (today's live-write path).
func policyWriteStore(actor string) *PolicyStore {
	if requireCommitEnabled() {
		return policyDraft.stageTarget(actor)
	}
	return policyStore
}

// beginPolicyWrite/endPolicyWrite bracket an ORDINARY policy-write handler's
// whole mutate-then-finalize sequence (Codex round 16): the handler mutates
// the candidate under the store's OWN lock, so a commit's snapshot→clear
// could land between the mutation and afterPolicyWrite — the cleared
// candidate swallowed the edit while the handler returned success and
// audited a change that reached neither running policy nor disk. The
// coordinator's writeGate serializes them: commit/revert hold it EXCLUSIVE,
// so an in-flight handler sequence completes first (its edit is included in
// the commit or persists into the still-open draft), and a sequence starting
// after a commit forks a fresh draft from the new running. Lock order:
// writeGate → c.mu → PolicyStore.mu; internal coordinator functions never
// touch writeGate (reconcile's auto-clear runs under a caller-held read
// side, which is why the gate cannot live inside clear()).
func beginPolicyWrite() { policyDraft.writeGate.RLock() }
func endPolicyWrite()   { policyDraft.writeGate.RUnlock() }

// policyDraftEngaged reports whether the draft actually intercepts the policy
// read/write path: commit-mode armed AND a draft open. It must use the SAME
// predicate family as policyWriteStore (requireCommitEnabled), not active()
// alone: if the two ever diverge — a corrupt/defaulted admin_settings.json
// resets RequireCommit to false while initPolicyDraft reloads a pending
// policy_draft.json — writes go to RUNNING (policyWriteStore is live), so the
// finalize/read helpers must follow the live path too. Keying them on active()
// alone would skip policyStore.Save()+saveConfigVersion after a live write
// (mutations silently lost on restart — fail-open for a staged Deny) and
// render the stale candidate instead of the enforced rulebase. A stranded
// active draft in that state stays recoverable via /api/policy/draft
// (GET state, POST commit/revert), which deliberately key on active() only.
func policyDraftEngaged() bool {
	return requireCommitEnabled() && policyDraft.active()
}

// effectivePolicyList is the rulebase the admin is currently editing/viewing:
// the candidate when the draft is engaged, else running. Used by write handlers
// for validation and by the policy GET/reorder read paths. Does NOT open a draft.
func effectivePolicyList() []PolicyRule {
	if policyDraftEngaged() {
		return policyDraft.candidateList()
	}
	return policyStore.List()
}

// effectivePolicySnapshot returns the effective rulebase AND its label from
// ONE coordinator-locked view (Codex round 15): the policy tester's separate
// engagement check, list read, and label read could interleave with a
// commit/revert — evaluating an empty candidate, or reporting a captured
// draft snapshot as "running". Lock order c.mu → PolicyStore.mu (the
// stageTarget convention).
func effectivePolicySnapshot() (rules []PolicyRule, rulebase string) {
	policyDraft.mu.Lock()
	defer policyDraft.mu.Unlock()
	if requireCommitEnabled() && policyDraft.state.Active {
		return policyDraft.cand.List(), "draft"
	}
	return policyStore.List(), "running"
}

// effectivePolicyVersion is the generation clients echo via ?ifVersion=: the
// candidate's while drafting (so two admins editing the shared draft collide),
// else running's.
func effectivePolicyVersion() (version int64, updatedAt string) {
	if policyDraftEngaged() {
		return policyDraft.candidateVersion()
	}
	return policyStore.policyVersion()
}

// afterPolicyWrite finalizes a successful policy mutation. Live-write mode
// persists running and writes a per-edit config version (today's behavior).
// Draft mode persists the candidate and SKIPS config-versioning — the version
// is captured once at commit, so per-edit snapshots of the unchanged running
// config would be misleading no-ops.
func afterPolicyWrite(r *http.Request, action string) {
	if policyDraftEngaged() {
		// A no-op edit (candidate == running) auto-discards the draft rather
		// than leaving a zero-diff pending draft; otherwise persist the change.
		if policyDraft.reconcile() {
			return
		}
		policyDraft.persist()
		return
	}
	policyStore.Save()
	saveConfigVersion(sessionAdmin(r), action)
}

// ── Commit-time shadow detection (G4, advisory) ──────────────────────────────

// shadowFinding names an access rule an earlier always-active rule provably
// eclipses (the earlier rule will always match first, so this one can never fire).
type shadowFinding struct {
	Rule       string `json:"rule"`       // the shadowed rule's name
	ShadowedBy string `json:"shadowedBy"` // the earlier rule that covers it
}

// detectShadowedRules flags EXACTLY-decidable shadowing among Stage-2 access
// rules (priority order): an earlier ENABLED, always-active (no schedule) rule A
// shadows rule B when every request B could match provably also matches A. This
// is the backend counterpart of the client-side polShadowHints advisory (M3 S5 /
// G4), run on the candidate at commit time. Fields cover by identity or A-empty
// (matches everything); FQDN globs only for the provable '*.suffix'-covers-
// 'x.suffix' shape; countries by superset. CIDR containment, category-group
// expansion, and schedule overlap are deliberately NOT attempted, so this never
// claims completeness — it is advisory ("verify with the tester"), never blocking.
// Auth (Stage-1) rules are excluded; they have their own diagnostics.
func detectShadowedRules(rules []PolicyRule) []shadowFinding {
	// Access rules, enabled only, in the (priority-sorted) input order. Index-based
	// range + pointer slice: PolicyRule is a large struct (CLAUDE.md rangeValCopy)
	// and this runs on every draft poll, so avoid copying rules by value.
	act := make([]*PolicyRule, 0, len(rules))
	for i := range rules {
		if ruleTypeOf(&rules[i]) != ruleTypeAccess {
			continue
		}
		if rules[i].Enabled != nil && !*rules[i].Enabled {
			continue
		}
		act = append(act, &rules[i])
	}
	var out []shadowFinding
	for j := 1; j < len(act); j++ {
		for i := 0; i < j; i++ {
			if act[i].Schedule != nil {
				continue // A must be always-active to provably cover B
			}
			if ruleProvablyCovers(act[i], act[j]) {
				out = append(out, shadowFinding{Rule: act[j].Name, ShadowedBy: act[i].Name})
				break
			}
		}
	}
	return out
}

// ruleProvablyCovers reports whether always-active rule a matches every request
// rule b could match, using only exactly-decidable field coverage.
func ruleProvablyCovers(a, b *PolicyRule) bool {
	return fieldCovers(a.SourceIP, b.SourceIP) &&
		fieldCovers(a.SourceIdentity, b.SourceIdentity) &&
		fieldCovers(a.SourceGroup, b.SourceGroup) &&
		fieldCovers(a.AuthSource, b.AuthSource) &&
		fqdnCovers(a.DestFQDN, b.DestFQDN) &&
		fieldCovers(string(a.DestCategory), string(b.DestCategory)) &&
		fieldCovers(a.DestCategoryGroup, b.DestCategoryGroup) &&
		countryCovers(a.DestCountry, b.DestCountry)
}

// fieldCovers: a covers b when a is empty (matches anything) or equal to b.
func fieldCovers(a, b string) bool { return a == "" || a == b }

// fqdnCovers extends fieldCovers with the one provable glob shape: a "*.suffix"
// pattern covers any strict subdomain "x.suffix".
func fqdnCovers(a, b string) bool {
	if a == "" || a == b {
		return true
	}
	if strings.HasPrefix(a, "*.") {
		bare := a[2:]   // "suffix" (a without the leading "*.")
		dotted := a[1:] // ".suffix"
		return b != "" && b != bare && strings.HasSuffix(b, dotted)
	}
	return false
}

// countryCovers: a covers b when a is empty (any country) or a ⊇ b.
func countryCovers(a, b []string) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !slices.Contains(a, c) {
			return false
		}
	}
	return true
}

// ── HTTP handlers ──────────────────────────────────────────────────────────

// apiPolicyDraft — GET the draft state + diff + mode; PUT sets RequireCommit.
//
//	GET  /api/policy/draft            → {requireCommit, active, actor, startedAt, diff, version}
//	PUT  /api/policy/draft  {require_commit:bool}  (admin) — arm/disarm commit mode
func apiPolicyDraft(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		st := policyDraft.snapshotState()
		resp := map[string]any{
			"requireCommit": requireCommitEnabled(),
			"active":        st.Active,
			"actor":         st.Actor,
			"startedAt":     st.StartedAt,
		}
		if st.Active {
			d := policyDraft.diffVsRunning()
			ver, _ := policyDraft.candidateVersion()
			resp["diff"] = d
			resp["pendingCount"] = d.total()
			resp["version"] = ver
			// Advisory shadow warnings over the CANDIDATE (what will go live),
			// so the operator sees them before committing (G4).
			resp["shadows"] = detectShadowedRules(policyDraft.candidateList())
		}
		jsonOK(w, resp)

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			RequireCommit bool `json:"require_commit"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Disarming while a dirty draft is pending would strand staged changes
		// the operator believed were in flight — force an explicit commit/revert.
		// The check and the flag flip are ONE critical section on the
		// coordinator lock (Codex fix): a detached check could interleave with
		// a learning acceptance opening the first draft.
		if !body.RequireCommit {
			if err := policyDraft.disarmRequireCommit(); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
		} else {
			setRequireCommit(true)
		}
		adminSettingsSave()
		mode := boolToOnOff(body.RequireCommit) // constant "on"/"off" — breaks the taint flow (CodeQL log-injection)
		auditEvent(r, "policy.draft.mode", mode, "")
		logger.Printf("UI: policy commit-mode set to %s", mode)
		jsonOK(w, map[string]any{"requireCommit": body.RequireCommit})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiPolicyDraftCommit — POST /api/policy/draft/commit {comment} (operator).
// Validates the candidate as a set, requires an audit comment, atomically
// activates it, snapshots, and clears the draft.
func apiPolicyDraftCommit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	// Exclusive side of the ordinary-write gate (Codex round 16): an in-flight
	// CRUD handler sequence completes before the commit's snapshot, so its
	// edit is either included or persists into the still-open draft — never
	// swallowed by the clear while the handler reports success.
	policyDraft.writeGate.Lock()
	defer policyDraft.writeGate.Unlock()
	if !policyDraft.active() {
		http.Error(w, "no draft to commit", http.StatusBadRequest)
		return
	}
	// Optimistic-concurrency precondition on the SHARED candidate: if the client
	// sends ?ifVersion=N (the candidate generation it reviewed) and another admin
	// staged a change in between, this 409s instead of committing unreviewed
	// changes. A commit ALWAYS operates on the candidate, so compare against the
	// candidate's generation directly — not effectivePolicyVersion(), which falls
	// back to running when RequireCommit is off (the stranded-draft recovery
	// state) and would spuriously 409 a legitimate recovery commit. This early
	// check owns the canonical structured 409 (and the invalid-param 400);
	// commitActivate re-verifies the same fence INSIDE its critical section
	// (Codex fix) so a durable append landing after this line still conflicts.
	candVer, _ := policyDraft.candidateVersion()
	if policyVersionConflictAgainst(w, r, candVer) {
		return
	}
	ifVersion := parseIfVersion(r)
	var body struct {
		Comment string `json:"comment"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	comment := strings.TrimSpace(body.Comment)
	if comment == "" {
		http.Error(w, "a commit comment is required", http.StatusBadRequest)
		return
	}
	// Fail closed if running changed out-of-band under the draft (import/rollback).
	if policyDraft.baseGenerationStale() {
		http.Error(w, "the running rulebase changed since this draft was opened (an import or rollback) — revert and re-stage to avoid clobbering it", http.StatusConflict)
		return
	}
	// Validate + diff + activate + clear as ONE coordinator critical section
	// (Codex fix): a concurrent durable append can no longer land between the
	// commit's snapshot and its clear, and the reviewed-version fence is
	// re-verified under the same lock.
	diff, err := policyDraft.commitActivate(ifVersion)
	if err != nil {
		switch {
		case errors.Is(err, errDraftVersionConflict):
			http.Error(w, err.Error(), http.StatusConflict)
		case errors.Is(err, errDraftPersistFailed):
			// Durable-or-nothing: the draft is retained; the operator retries
			// once the volume recovers.
			http.Error(w, err.Error(), http.StatusInternalServerError)
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	actor := sessionAdmin(r)
	detail := commitDetail(diff, comment)
	auditEvent(r, "policy.commit", actor, detail)
	// Persist the commit comment into the config-version timeline (S3): the
	// version records WHY the rulebase changed, alongside the rollback snapshot.
	saveConfigVersionNote(actor, "policy.commit", comment)
	logger.Printf("UI: policy draft committed by %s (%d changes)", sanitizeLog(actor), diff.total())
	jsonOK(w, map[string]any{"ok": true, "committed": diff.total(), "diff": diff})
}

// apiPolicyDraftRevert — POST /api/policy/draft/revert (operator). Discards the
// candidate; running is untouched.
func apiPolicyDraftRevert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	// Exclusive side of the ordinary-write gate (Codex round 16; see the
	// commit handler).
	policyDraft.writeGate.Lock()
	defer policyDraft.writeGate.Unlock()
	if !policyDraft.active() {
		http.Error(w, "no draft to revert", http.StatusBadRequest)
		return
	}
	diff := policyDraft.diffVsRunning()
	policyDraft.clear()
	auditEvent(r, "policy.draft.revert", sessionAdmin(r), commitDetail(diff, "discarded"))
	logger.Printf("UI: policy draft reverted (%d changes discarded)", diff.total())
	jsonOK(w, map[string]any{"ok": true, "discarded": diff.total()})
}

// commitDetail renders a compact audit detail for a draft transition.
func commitDetail(d policyDraftDiff, comment string) string {
	return fmt.Sprintf("+%d ~%d -%d — %s", len(d.Added), len(d.Modified), len(d.Removed),
		strings.ReplaceAll(strings.ReplaceAll(comment, "\n", " "), "\r", " "))
}

func boolToOnOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}
