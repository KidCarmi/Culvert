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
	"fmt"
	"net/http"
)

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

// fencedMutate runs ONE ordinary policy mutation against the correct write
// target (running store, or the shared draft candidate — opening the draft on
// the first write) with the OPTIONAL expected-version fence evaluated
// atomically in the same critical section as the mutation.
//
//   - ifVersion == nil: no fence — legacy behavior, the mutation always
//     proceeds (still serialized, still correctly draft-targeted).
//   - ifVersion != nil: the assertion is compared against the EFFECTIVE
//     generation (candidate while the draft is engaged, else running) under
//     c.mu. On mismatch the mutation NEVER runs and the structured conflict is
//     returned. On match, the draft fork (when Require Commit is armed and no
//     draft exists) and the mutation run before c.mu is released, so no other
//     fenced writer can interleave between check and write.
//
// mutate runs with c.mu held and receives the target store; it must confine
// itself to store operations (lock order c.mu → PolicyStore.mu, the
// stageTarget convention) and report whether it actually mutated. When the
// mutation reports false after this call opened the draft fork, the fork is
// discarded — an untouched forked candidate must not linger as an "active"
// zero-diff draft.
//
// Ordinary handlers hold beginPolicyWrite (writeGate.RLock) around this call
// plus their finalize sequence, exactly as before: commit/revert still take
// the gate exclusively, so a commit cannot snapshot-and-clear between this
// mutation and its finalize.
func (c *policyDraftCoordinator) fencedMutate(actor string, ifVersion *int64, mutate func(target *PolicyStore) bool) (conflict *policyVersionConflictError, ok bool) {
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
		return &policyVersionConflictError{Current: cur, Asserted: *ifVersion}, false
	}

	target := policyStore
	opened := false
	if requireCommitEnabled() {
		if !c.state.Active {
			c.openDraftLocked(actor)
			opened = true
		}
		target = c.cand
	}
	ok = mutate(target)
	if !ok && opened {
		// The fork was opened for a mutation that did not happen (rule not
		// found, invalid permutation). Nothing was persisted for it yet, so
		// discarding is purely in-memory — equivalent to the legacy handlers'
		// post-failure reconcile(), but without ever exposing the zero-diff
		// draft outside this critical section.
		_ = c.clearLocked()
	}
	return nil, ok
}
