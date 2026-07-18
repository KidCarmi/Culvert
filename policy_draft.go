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
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

type persistedPolicyDraft struct {
	State draftState   `json:"state"`
	Rules []PolicyRule `json:"rules"`
}

// policyDraftCoordinator owns the candidate rulebase and its lifecycle.
type policyDraftCoordinator struct {
	mu    sync.Mutex
	cand  *PolicyStore // candidate rules; in-memory (path=""), persisted by this coordinator
	state draftState
	path  string // policy_draft.json ("" ⇒ in-memory, no persistence)
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
	journalPath := policyDraft.path + ".commit"
	if data, err := os.ReadFile(journalPath); err == nil {
		var pending persistedPolicyDraft
		if json.Unmarshal(data, &pending) == nil && pending.State.Active {
			if sameRuleSet(policyStore.List(), pending.Rules) {
				_ = durableRemove(policyDraft.path)
				_ = durableRemove(journalPath)
				return
			}
			if restored, err := json.MarshalIndent(pending, "", "  "); err == nil {
				if err := fileutil.AtomicWrite(policyDraft.path, restored, 0o600); err == nil {
					_ = durableRemove(journalPath)
				}
			}
		}
	}
	data, err := os.ReadFile(policyDraft.path)
	if err != nil {
		return // no pending draft
	}
	var p persistedPolicyDraft
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
		// Fork rules and generation from one running snapshot.
		rules, baseGen := policyStore.snapshotWithVersion()
		c.cand.ReplaceAll(rules)
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

func detachedPolicyDraftStore(src *PolicyStore) *PolicyStore {
	rules := src.List()
	version, updatedAt := src.policyVersion()
	next := &PolicyStore{}
	next.ReplaceAll(rules)
	next.mu.Lock()
	next.version = version
	next.updatedAt = updatedAt
	next.mu.Unlock()
	return next
}

// persistCandidateLocked durably writes a detached coordinator snapshot.
// Caller holds c.mu.
func (c *policyDraftCoordinator) persistCandidateLocked(candidate *PolicyStore, state draftState) error {
	if c.path == "" {
		return nil
	}
	if !state.Active {
		return errors.New("cannot persist inactive policy draft")
	}
	p := persistedPolicyDraft{State: state, Rules: candidate.List()}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(c.path, data, 0o600)
}

func (c *policyDraftCoordinator) persistLocked() error {
	return c.persistCandidateLocked(c.cand, c.state)
}

func (c *policyDraftCoordinator) writeInactiveTombstoneLocked() error {
	if c.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(persistedPolicyDraft{}, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(c.path, data, 0o600)
}

func (c *policyDraftCoordinator) writeCommitJournalLocked() error {
	if c.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(persistedPolicyDraft{State: c.state, Rules: c.cand.List()}, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(c.path+".commit", data, 0o600)
}

func (c *policyDraftCoordinator) clearMemoryLocked() {
	c.cand = &PolicyStore{}
	c.state = draftState{}
}

// clearDurablyLocked publishes an inactive tombstone before clearing memory.
// If cleanup fails, restart still ignores the tombstone.
func (c *policyDraftCoordinator) clearDurablyLocked() error {
	if err := c.writeInactiveTombstoneLocked(); err != nil {
		return err
	}
	c.clearMemoryLocked()
	if c.path != "" {
		if err := durableRemove(c.path); err != nil {
			logger.Printf("PolicyDraft: inactive tombstone cleanup error: %v", err)
		}
	}
	return nil
}

// mutateAndPersist serializes a staged edit with commit/revert and reports a
// persistence failure without publishing or acknowledging the edit.
func (c *policyDraftCoordinator) mutateAndPersist(actor string, expected *int64, edit func(*PolicyStore) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if expected != nil && c.state.Active {
		version, _ := c.cand.policyVersion()
		if version != *expected {
			return errPolicyVersionConflict
		}
	}
	nextState := c.state
	next := detachedPolicyDraftStore(c.cand)
	if !c.state.Active {
		rules, baseGen := policyStore.snapshotWithVersion()
		if expected != nil && baseGen != *expected {
			return errPolicyVersionConflict
		}
		next = &PolicyStore{}
		next.ReplaceAll(rules)
		nextState = draftState{Active: true, Actor: actor, StartedAt: time.Now().UTC().Format(time.RFC3339), BaseGeneration: baseGen}
	}
	if err := edit(next); err != nil {
		return err
	}
	if sameRuleSet(policyStore.List(), next.List()) {
		return c.clearDurablyLocked()
	}
	if err := c.persistCandidateLocked(next, nextState); err != nil {
		return fmt.Errorf("persist policy draft: %w", err)
	}
	c.cand = next
	c.state = nextState
	return nil
}

// cascadeDecryptionProfileRename mirrors PolicyStore.CascadeDecryptionProfileRename
// onto the open candidate so a profile rename keeps the DRAFT's denormalized names
// honest too — otherwise a rename during an active draft would refresh running but
// leave the candidate carrying stale names that a later commit would write back.
// No-op when no draft is open. Mutation and durable persistence remain under
// c.mu, serializing the cascade with commit and revert.
func (c *policyDraftCoordinator) cascadeDecryptionProfileRename(id, oldName, newName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.state.Active {
		return nil
	}
	next := detachedPolicyDraftStore(c.cand)
	n := next.CascadeDecryptionProfileRename(id, oldName, newName)
	if n == 0 {
		return nil
	}
	nextState := c.state
	if runningVersion, _ := policyStore.policyVersion(); runningVersion == nextState.BaseGeneration+1 {
		nextState.BaseGeneration = runningVersion
	}
	if err := c.persistCandidateLocked(next, nextState); err != nil {
		return fmt.Errorf("persist policy draft cascade: %w", err)
	}
	c.cand = next
	c.state = nextState
	return nil
}

// cascadeDestCategoryGroupRename mirrors PolicyStore.CascadeDestCategoryGroupRename
// onto the open candidate (references-by-id S2), so a group rename keeps the
// DRAFT's denormalized names honest too. No-op when no draft is open; persists
// only when a rule was actually touched. Lock order c.mu → PolicyStore.mu.
func (c *policyDraftCoordinator) cascadeDestCategoryGroupRename(id, oldName, newName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.state.Active {
		return nil
	}
	next := detachedPolicyDraftStore(c.cand)
	n := next.CascadeDestCategoryGroupRename(id, oldName, newName)
	if n == 0 {
		return nil
	}
	nextState := c.state
	if runningVersion, _ := policyStore.policyVersion(); runningVersion == nextState.BaseGeneration+1 {
		nextState.BaseGeneration = runningVersion
	}
	if err := c.persistCandidateLocked(next, nextState); err != nil {
		return fmt.Errorf("persist policy draft cascade: %w", err)
	}
	c.cand = next
	c.state = nextState
	return nil
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
	return diffRuleSets(policyStore.List(), c.candidateList())
}

func diffRuleSets(run, cand []PolicyRule) policyDraftDiff {
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

var errPolicyDraftInactive = errors.New("policy draft inactive")
var policyVersionRecordMu sync.Mutex

// commit validates, persists, publishes, and clears one exact candidate while
// holding the coordinator lock. Staged writes and revert cannot interleave.
func (c *policyDraftCoordinator) commit(expectedCandidate *int64) (policyDraftDiff, error) {
	diff, _, err := c.commitWithRules(expectedCandidate)
	return diff, err
}

func (c *policyDraftCoordinator) commitWithRules(expectedCandidate *int64) (policyDraftDiff, []PolicyRule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.state.Active {
		return policyDraftDiff{}, nil, errPolicyDraftInactive
	}
	if expectedCandidate != nil {
		version, _ := c.cand.policyVersion()
		if version != *expectedCandidate {
			return policyDraftDiff{}, nil, errPolicyVersionConflict
		}
	}
	cand := c.cand.List()
	for i := range cand {
		if err := validatePolicyRule(cand[i], cand, cand[i].Priority); err != nil {
			return policyDraftDiff{}, nil, fmt.Errorf("candidate rule %s is invalid: %w", sanitizeLog(cand[i].Name), err)
		}
	}
	run := policyStore.List()
	diff := diffRuleSets(run, cand)
	if err := c.writeCommitJournalLocked(); err != nil {
		return policyDraftDiff{}, nil, fmt.Errorf("journal policy draft commit: %w", err)
	}
	if err := c.writeInactiveTombstoneLocked(); err != nil {
		if c.path != "" {
			_ = durableRemove(c.path + ".commit")
		}
		return policyDraftDiff{}, nil, fmt.Errorf("retire policy draft: %w", err)
	}
	if err := policyStore.ReplaceAllAndSaveAtVersion(cand, c.state.BaseGeneration); err != nil {
		restoreErr := c.persistLocked()
		if restoreErr == nil && c.path != "" {
			_ = durableRemove(c.path + ".commit")
		}
		if restoreErr != nil {
			return policyDraftDiff{}, nil, fmt.Errorf("%w; restore policy draft: %v", err, restoreErr)
		}
		return policyDraftDiff{}, nil, err
	}
	c.clearMemoryLocked()
	if c.path != "" {
		if err := durableRemove(c.path); err != nil {
			logger.Printf("PolicyDraft: committed tombstone cleanup error: %v", err)
		}
		if err := durableRemove(c.path + ".commit"); err != nil {
			logger.Printf("PolicyDraft: commit journal cleanup error: %v", err)
		}
	}
	return diff, cand, nil
}

func (c *policyDraftCoordinator) revert() (policyDraftDiff, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.state.Active {
		return policyDraftDiff{}, errPolicyDraftInactive
	}
	diff := diffRuleSets(policyStore.List(), c.cand.List())
	if err := c.clearDurablyLocked(); err != nil {
		return policyDraftDiff{}, fmt.Errorf("clear reverted policy draft: %w", err)
	}
	return diff, nil
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

var errPolicyRuleNotFound = errors.New("policy rule not found")

// mutatePolicy makes one handler mutation durable before it becomes observable.
// Draft edits are serialized with commit/revert and durably staged instead.
func mutatePolicy(actor string, edit func(*PolicyStore) error) (staged bool, err error) {
	return mutatePolicyAtVersion(actor, nil, edit)
}

func mutatePolicyAtVersion(actor string, expected *int64, edit func(*PolicyStore) error) (bool, error) {
	staged, _, err := mutatePolicyForWrite(actor, expected, edit)
	return staged, err
}

func mutatePolicyForWrite(actor string, expected *int64, edit func(*PolicyStore) error) (bool, []PolicyRule, error) {
	if requireCommitEnabled() {
		return true, nil, policyDraft.mutateAndPersist(actor, expected, edit)
	}
	policyVersionRecordMu.Lock()
	var committed []PolicyRule
	err := policyStore.MutateAndSaveAtVersion(expected, func(candidate *PolicyStore) error {
		if err := edit(candidate); err != nil {
			return err
		}
		committed = candidate.List()
		return nil
	})
	if err != nil {
		policyVersionRecordMu.Unlock()
	}
	return false, committed, err
}

func finishCommittedPolicyVersion(w http.ResponseWriter, r *http.Request, action, note string, committed []PolicyRule) bool {
	defer policyVersionRecordMu.Unlock()
	if err := saveConfigVersionSnapshot(sessionAdmin(r), action, note, committed); err != nil {
		http.Error(w, "config version persistence failed", http.StatusInternalServerError)
		return false
	}
	return true
}

func finishPolicyWrite(w http.ResponseWriter, r *http.Request, action string, staged bool, committed []PolicyRule) bool {
	if staged {
		return true
	}
	return finishCommittedPolicyVersion(w, r, action, "", committed)
}

// effectivePolicyList is the rulebase the admin is currently editing/viewing:
// the candidate when a draft is open, else running. Used by write handlers for
// validation and by the policy GET/reorder read paths. Does NOT open a draft.
func effectivePolicyList() []PolicyRule {
	if policyDraft.active() {
		return policyDraft.candidateList()
	}
	return policyStore.List()
}

// effectivePolicyVersion is the generation clients echo via ?ifVersion=: the
// candidate's while drafting (so two admins editing the shared draft collide),
// else running's.
func effectivePolicyVersion() (version int64, updatedAt string) {
	if policyDraft.active() {
		return policyDraft.candidateVersion()
	}
	return policyStore.policyVersion()
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
		if !body.RequireCommit && policyDraft.active() {
			http.Error(w, "a draft with pending changes exists — commit or revert it before disabling commit mode", http.StatusConflict)
			return
		}
		setRequireCommit(body.RequireCommit)
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
	if !policyDraft.active() {
		http.Error(w, "no draft to commit", http.StatusBadRequest)
		return
	}
	// Optimistic-concurrency precondition on the SHARED candidate: if the client
	// sends ?ifVersion=N (the candidate generation it reviewed) and another admin
	// staged a change in between, this 409s instead of committing unreviewed
	// changes. policyVersionConflict compares against effectivePolicyVersion,
	// which is the candidate's generation while a draft is open.
	if policyVersionConflict(w, r) {
		return
	}
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
	var expectedCandidate *int64
	if raw := strings.TrimSpace(r.URL.Query().Get("ifVersion")); raw != "" {
		version, _ := strconv.ParseInt(raw, 10, 64) // validated by policyVersionConflict above
		expectedCandidate = &version
	}
	policyVersionRecordMu.Lock()
	versionLockHeld := true
	defer func() {
		if versionLockHeld {
			policyVersionRecordMu.Unlock()
		}
	}()
	diff, committed, err := policyDraft.commitWithRules(expectedCandidate)
	if errors.Is(err, errPolicyVersionConflict) {
		http.Error(w, "the running rulebase changed since this draft was opened (an import or rollback) — revert and re-stage to avoid clobbering it", http.StatusConflict)
		return
	}
	if errors.Is(err, errPolicyDraftInactive) {
		http.Error(w, "no draft to commit", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "durable policy save failed; running policy unchanged and draft retained", http.StatusInternalServerError)
		return
	}

	actor := sessionAdmin(r)
	if !finishCommittedPolicyVersion(w, r, "policy.commit", comment, committed) {
		versionLockHeld = false
		return
	}
	versionLockHeld = false
	detail := commitDetail(diff, comment)
	auditEvent(r, "policy.commit", actor, detail)
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
	diff, err := policyDraft.revert()
	if errors.Is(err, errPolicyDraftInactive) {
		http.Error(w, "no draft to revert", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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
