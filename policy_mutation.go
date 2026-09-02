package main

// policy_mutation.go — the atomic expected-version policy-mutation primitive
// (Batch-2 slice 2B.0a).
//
// policyVersionConflict (ui_policy.go) is HANDLER-level optimistic concurrency:
// it reads the effective generation before the mutation, outside any lock, so
// two writers could both read v5, both pass, and both mutate — the store
// serialized the writes (no corruption) but the second silently overwrote the
// first even though both asserted the same expected version. That was a
// recorded follow-up ("truly-atomic check-and-write would thread the expected
// version into the store mutators"); this file is that follow-up.
//
// fencedMutate threads the OPTIONAL ?ifVersion= assertion into the
// coordinator's critical section: the effective-version comparison, the
// first-write draft fork, and the store mutation all run under ONE c.mu
// acquisition, so when a client asserts a version there is no window in which
// a second writer holding the same assertion can pass. Callers without an
// assertion (legacy clients) keep today's last-write-wins behavior unchanged.
//
// Version-stream continuity (the §3 first-write-opens-draft design): the
// candidate's generation counter used to start from its own zero, so the
// effective version a client echoes could NUMERICALLY COLLIDE with a stale
// pre-fork running token (running v2 → fork+first-write lands the candidate at
// its own v2 → a second writer's stale ifVersion=2 silently mutated the newly
// opened shared candidate). The fork now SEEDS the candidate's counter from
// the running generation (openDraftLocked), so the effective version stream is
// strictly monotonic across the fork: the first staged write lands at vN+1 and
// every stale vN assertion conflicts deterministically. On candidate
// RETIREMENT (commit, revert, no-op reconcile) the running counter is advanced
// past the candidate's (ensureVersionAbove) so a stale candidate-era token can
// never numerically collide with a later running generation either. The cost
// of that direction is only ever a conservative false CONFLICT (reload and
// reapply), never a false pass.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// finalizeFencedPolicyWrite records the per-edit config version for a LIVE
// mutation (the persist itself already happened inside fencedMutate).
// Draft-staged mutations skip it — the config version is captured once at
// commit, exactly as before.
func finalizeFencedPolicyWrite(r *http.Request, action string, res fencedMutateResult) {
	if !res.staged {
		saveConfigVersion(sessionAdmin(r), action)
	}
}

// writePolicyPersistFailure maps a durable-persistence failure (the mutation
// was rolled back; nothing durable changed) to a 500 with the truthful cause.
func writePolicyPersistFailure(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// fencedRefusal is a refusal decided INSIDE the coordinator fence, against
// the authoritative snapshot the mutation would have applied to (2E-C
// concurrency-status correction). Every identity-, existence-, position-,
// version- and ordering-dependent check a rule-mutation handler makes lives
// in its fenced closure and reports through this type; only structurally
// malformed input (method, body grammar, id grammar, an unknown position
// word, a missing name, a bad timezone …) is refused before the fence.
type fencedRefusal struct {
	// notFound: the addressed target identity does not exist at the
	// authoritative moment (404).
	notFound bool
	// reason: the request conflicts with the CURRENT rulebase (a name or
	// priority already in use, a priority that now belongs to the other rule
	// type, an order list that no longer covers the set …).
	reason string
	// invariant: the verdict cannot change with the rulebase state — the
	// request is wrong on its own terms (a stable id that belongs to the
	// other rule type: an id never changes type). Always 400, whatever the
	// client asserted.
	invariant bool
}

// writeFencedRefusal maps an in-fence refusal to the truthful status:
//   - the target vanished → 404;
//   - a conflict WITHOUT an ?ifVersion= assertion → 409 {error,
//     currentVersion}: the client made no claim about the state it saw, so
//     the conflict may be a concurrent change — a refresh-and-retry verdict,
//     never "your request is malformed";
//   - a conflict WITH a (necessarily matching — the fence admitted it)
//     assertion → 400: the rulebase is exactly the one the client loaded, so
//     the conflict is the request's own (it picked a name already in use,
//     listed the wrong priorities …) and a reload would change nothing;
//   - an invariant refusal (see fencedRefusal.invariant) → 400 always.
//
// A zero refusal with a false mutation (the store refused the write for a
// target it no longer holds) reads as not-found.
func writeFencedRefusal(w http.ResponseWriter, r *http.Request, ref fencedRefusal, current int64) {
	if ref.notFound || ref.reason == "" {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	if ref.invariant || parseIfVersion(r) != nil {
		http.Error(w, ref.reason, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
		"error":          ref.reason + " — the rulebase may have changed since you loaded it; reload (current version " + fmt.Sprint(current) + ") and reapply your change",
		"currentVersion": current,
	})
}

// findByPriorityIn returns a detached copy of the rule at priority in ps,
// or nil — for in-fence target resolution on the legacy priority path.
func findByPriorityIn(ps *PolicyStore, priority int) *PolicyRule {
	rules := ps.List()
	for i := range rules {
		if rules[i].Priority == priority {
			r := rules[i]
			return &r
		}
	}
	return nil
}

// policyWriteStateDecisionHook is a TEST-ONLY interleaving seam (nil in
// production, one nil check per stage). A rule-mutation handler reports the
// stage it is about to enter: "resolved" — its structural work (method, RBAC,
// body decode, shape checks) and any optimistic target resolution are done and
// it is about to VALIDATE against the rulebase; "fence" — it is about to enter
// the coordinator's critical section. A test installs a hook that holds ONE
// request (matched by a request header it set) at the requested stage while a
// competing mutation commits, then releases it — which turns an ordering-
// dependent outcome into a deterministic proof without sleeps. The handlers
// must call it at exactly the points where the authoritative-state decision
// begins, so the proof pins the real window and not a synthetic one.
var policyWriteStateDecisionHook func(r *http.Request, stage string)

func policyWriteStateDecision(r *http.Request, stage string) {
	if h := policyWriteStateDecisionHook; h != nil {
		h(r, stage)
	}
}

// persistRunningPolicy is the live-mode durable persist, swappable ONLY for
// fault injection in tests (the ErrReplacedNotSynced branch cannot be induced
// through the real filesystem deterministically). Production behavior is
// always policyStore.SaveErr.
var persistRunningPolicy = func() error { return policyStore.SaveErr() }

// policyVersionConflictError is the structured optimistic-concurrency failure
// returned by the atomic fence: the client's asserted generation no longer
// matches the effective rulebase generation.
type policyVersionConflictError struct {
	Current  int64 // the effective generation at the locked moment of the check
	Asserted int64 // the client's ?ifVersion= assertion
}

func (e *policyVersionConflictError) Error() string {
	return fmt.Sprintf("the rulebase changed since you loaded it (your version %d, current %d) — reload and reapply your change", e.Asserted, e.Current)
}

// writePolicyVersionConflictError writes the SAME structured 409 JSON shape as
// the handler-level policyVersionConflictAgainst fast-path, so a client sees
// one conflict contract regardless of which layer caught the race.
func writePolicyVersionConflictError(w http.ResponseWriter, e *policyVersionConflictError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
		"error":          e.Error(),
		"currentVersion": e.Current,
		"yourVersion":    e.Asserted,
	})
}

// fencedMutateResult reports one ordinary policy mutation's outcome.
type fencedMutateResult struct {
	// conflict is non-nil when the ?ifVersion= assertion failed — the
	// mutation never ran.
	conflict *policyVersionConflictError
	// ok reports whether the store mutation itself happened (false = target
	// not found / invalid permutation; the handler maps it to its 4xx).
	ok bool
	// staged reports which durable domain the mutation landed in: true = the
	// shared draft candidate (no per-edit config version), false = running
	// policy (the handler writes the config version).
	staged bool
	// err is non-nil when durable persistence failed BEFORE publication — the
	// semantic mutation was rolled back and nothing durable changed. The
	// handler must fail the request.
	err error
}

// fencedMutate runs ONE ordinary policy mutation against the correct write
// target (running store, or the shared draft candidate — opening the draft on
// the first write) with the OPTIONAL expected-version fence AND the durable
// persist evaluated atomically in the same critical section as the mutation
// (2B.0a fencing + 2B.0b durable-or-nothing).
//
//   - ifVersion == nil: no fence — the mutation always proceeds (still
//     serialized, still correctly draft-targeted, still durable-or-nothing).
//   - ifVersion != nil: the assertion is compared against the EFFECTIVE
//     generation (candidate while the draft is engaged, else running) under
//     c.mu. On mismatch the mutation NEVER runs and the structured conflict is
//     returned. On match, the draft fork (when Require Commit is armed and no
//     draft exists), the mutation, and the persist run before c.mu is
//     released, so no other fenced writer can interleave between check and
//     write.
//
// Durability contract (§5/§6, mirroring the commitActivate doctrine):
//
//   - LIVE success ⇒ the running mutation is durably persisted
//     (PolicyStore.SaveErr, atomic temp+fsync+rename+dir-fsync).
//   - DRAFT success ⇒ the candidate mutation is durably persisted to
//     policy_draft.json, so a restart recovers the staged edit
//     (persistLocked; in-memory mode has no durable domain by configuration).
//   - Pre-replacement persist failure ⇒ the semantic mutation is ROLLED BACK
//     (memory restored to the pre-mutation snapshot; a fork opened by this
//     call is discarded entirely) and err is returned — the durable file
//     still holds the previous truth, so memory and disk agree that the
//     mutation did not happen.
//   - ErrReplacedNotSynced (replacement happened, parent-dir fsync failed) ⇒
//     the file already CARRIES the new content; rolling memory back would
//     contradict the visible durable file, so the mutation stands as
//     SUCCESS with a logged degradation (the CHAOS-45 write-failure observer
//     has already surfaced the storage fault). The draft path inherits this
//     from persistSnapshotLocked; the live path applies it explicitly.
//
// The rollback uses ReplaceAll on the pre-mutation snapshot — the same
// mechanism commitActivate uses to revert a failed activation — so the
// failure path can never invent a third state (it bumps the generation,
// which costs at most a conservative fence conflict).
//
// mutate runs with c.mu held and receives the target store; it must confine
// itself to store operations (lock order c.mu → PolicyStore.mu, the
// stageTarget convention) and report whether it actually mutated.
//
// Ordinary handlers hold beginPolicyWrite (writeGate.RLock) around this call
// plus their finalize sequence, exactly as before: commit/revert still take
// the gate exclusively, so a commit cannot snapshot-and-clear between this
// mutation and its finalize.
func (c *policyDraftCoordinator) fencedMutate(actor string, ifVersion *int64, mutate func(target *PolicyStore) bool) fencedMutateResult {
	var (
		removePath   string
		saveMetaBump bool
	)
	res := c.fencedMutateLocked(actor, ifVersion, mutate, &removePath, &saveMetaBump)
	// Post-critical-section housekeeping for a no-op reconcile retirement
	// (matches clear()/reconcile(): the file removal and .meta refresh happen
	// off the coordinator lock).
	if saveMetaBump {
		policyStore.saveMeta()
	}
	if removePath != "" {
		_ = os.Remove(removePath)
	}
	return res
}

// fencedRunningMutate runs ONE RUNNING-domain policy mutation with the same
// atomic expected-version fence and durable-or-nothing contract as
// fencedMutate's live branch — but the write target is ALWAYS the running
// PolicyStore, and the fence is ALWAYS compared against the RUNNING
// generation (2C.0a).
//
// This is the EXPLICIT running-domain seam for Stage-1 authentication-policy
// mutations: auth rules are admin-managed and take effect in the running
// rulebase immediately — they are NEVER routed into the shared Access-Policy
// Draft candidate, and Require Commit must not appear to govern them. The 2B
// primitive (fencedMutate) resolves its target by requireCommitEnabled(),
// which is correct for Stage-2 access writes and wrong for Stage-1 — using it
// for auth writes would silently stage an authentication change behind a
// commit ceremony that was never designed to review it. Keeping the domain
// choice in the FUNCTION NAME (rather than a boolean parameter) makes a
// wrong-domain call visible at the call site.
//
// It still serializes on the coordinator's c.mu — the same critical section
// every draft operation and every fenced Stage-2 write runs under — so the
// version comparison, the mutation, and the durable persist are atomic
// against all of them. A successful running mutation bumps the running
// generation, which deliberately STALES an active Access-Policy Draft's
// BaseGeneration: the Stage-2 commit already fails closed on that
// (baseGenerationStale), and GET /api/policy/draft surfaces it as baseStale.
//
// Callers hold beginPolicyWrite (writeGate.RLock) exactly like the ordinary
// Stage-2 handlers, so a commit/revert (exclusive side) can never interleave
// with the mutation + finalize sequence.
func (c *policyDraftCoordinator) fencedRunningMutate(ifVersion *int64, mutate func(target *PolicyStore) bool) fencedMutateResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	// RUNNING generation, never the candidate's: the fence a Stage-1 client
	// echoes is the version GET /api/authpolicy served, which is the running
	// store's — even while a Stage-2 draft is engaged.
	cur, _ := policyStore.policyVersion()
	if ifVersion != nil && *ifVersion != cur {
		return fencedMutateResult{conflict: &policyVersionConflictError{Current: cur, Asserted: *ifVersion}}
	}
	return runningMutateLocked(mutate)
}

// runningMutateLocked mutates the RUNNING store durable-or-nothing. Shared by
// fencedMutate's live branch and fencedRunningMutate; the caller holds c.mu.
//
//   - Success ⇒ the running mutation is durably persisted (PolicyStore.SaveErr,
//     atomic temp+fsync+rename+dir-fsync).
//   - Pre-replacement persist failure ⇒ the semantic mutation is ROLLED BACK
//     (ReplaceAll on the pre-mutation snapshot) and err is returned — the
//     durable file still holds the previous truth, so memory and disk agree
//     that the mutation did not happen.
//   - ErrReplacedNotSynced ⇒ the file already carries the new content; the
//     mutation stands as SUCCESS with a logged degradation (commit durability
//     doctrine — see commitActivate).
func runningMutateLocked(mutate func(target *PolicyStore) bool) fencedMutateResult {
	prevRunning := policyStore.List()
	if !mutate(policyStore) {
		return fencedMutateResult{}
	}
	if err := persistRunningPolicy(); err != nil {
		if errors.Is(err, fileutil.ErrReplacedNotSynced) {
			// Post-rename failure: the policy file already carries the new
			// content (commit durability doctrine — see commitActivate).
			logWarnf("Policy: mutation persisted but parent-dir sync failed: %v", err)
		} else {
			// Pre-replacement failure: disk holds the previous truth —
			// restore memory to match it and fail the request.
			policyStore.ReplaceAll(prevRunning)
			return fencedMutateResult{ok: true, err: fmt.Errorf("running-policy persist failed — the change was rolled back, nothing durable changed: %w", err)}
		}
	}
	return fencedMutateResult{ok: true}
}

func (c *policyDraftCoordinator) fencedMutateLocked(actor string, ifVersion *int64, mutate func(target *PolicyStore) bool, removePath *string, saveMetaBump *bool) fencedMutateResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Effective generation, evaluated INSIDE the critical section: the
	// candidate's while the draft is engaged (two admins editing the shared
	// draft collide), else running's — mirroring effectivePolicyVersion, but
	// with no unlock between the read and the write it protects.
	var cur int64
	if requireCommitEnabled() && c.state.Active {
		cur, _ = c.cand.policyVersion()
	} else {
		cur, _ = policyStore.policyVersion()
	}
	if ifVersion != nil && *ifVersion != cur {
		return fencedMutateResult{conflict: &policyVersionConflictError{Current: cur, Asserted: *ifVersion}}
	}

	staged := requireCommitEnabled()
	if !staged {
		// ── LIVE mode: mutate running, persist durable-or-nothing. ──
		return runningMutateLocked(mutate)
	}

	// ── DRAFT mode: mutate the shared candidate, persist durable-or-nothing. ──
	opened := false
	var prevCand []PolicyRule
	if !c.state.Active {
		c.openDraftLocked(actor)
		opened = true
	} else {
		prevCand = c.cand.List()
	}
	if !mutate(c.cand) {
		if opened {
			// The fork was opened for a mutation that did not happen (rule not
			// found, invalid permutation). Nothing was persisted for it, so
			// discarding is purely in-memory.
			_ = c.clearLocked()
		}
		return fencedMutateResult{staged: true}
	}
	// No-op auto-discard (the reconcile contract): a staged edit that leaves
	// the candidate content-identical to running retires the draft instead of
	// leaving a zero-diff "active" draft. Runs inside the same critical
	// section now; the file removal + .meta refresh happen after unlock.
	if sameRuleSet(policyStore.List(), c.cand.List()) {
		candVer, _ := c.cand.policyVersion()
		*removePath = c.clearLocked()
		policyStore.ensureVersionAbove(candVer)
		*saveMetaBump = true
		return fencedMutateResult{ok: true, staged: true}
	}
	if err := c.persistLocked(); err != nil {
		// persistSnapshotLocked already absorbs ErrReplacedNotSynced (the file
		// carries the new candidate — that IS durable), so any error here is a
		// pre-replacement failure: the durable domain still holds the previous
		// truth. Restore memory to match it.
		if opened {
			_ = c.clearLocked()
		} else {
			c.cand.ReplaceAll(prevCand)
		}
		return fencedMutateResult{ok: true, staged: true, err: fmt.Errorf("%v: %w", err, errDraftPersistFailed)}
	}
	return fencedMutateResult{ok: true, staged: true}
}
