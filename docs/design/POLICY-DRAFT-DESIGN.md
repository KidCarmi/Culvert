# Policy Draft — Candidate/Commit for Rule Content (G2 / `policy-draft`)

Status: **design record, pre-implementation.** Authority for the P3
`policy-draft` work item in `POLICY-ARCHITECTURE-FUTURE.md` §6 and gap **G2**
in `M3-POLICY-ARCH-REVIEW.md`. Nothing here is implemented yet; this document
is the contract the slices below implement against.

Date: 2026-07-13.

---

## 1. What this is

Today Culvert policy edits are **live-write**: the moment an admin saves a rule
(`apiPolicyCreate/Update/Delete/...`), it is active in the enforcement engine
(`policyStore.Evaluate`) and, in a cluster, pushed to data-plane nodes via the
next `ConfigSnapshot`. Config-version snapshots are captured *after* each edit
for rollback, but there is no "review before it goes live" step.

`policy-draft` adds the PAN-OS-class **candidate vs running** model for the
**Stage-2 policy rulebase**:

- **Running config** — what the proxy enforces now (`policyStore`, unchanged).
- **Candidate config** — a persisted draft the admin edits without affecting
  live traffic.
- **Commit** — validate the whole candidate, require an audit comment, then
  atomically activate it (running := candidate), snapshot, and cluster-sync.
- **Revert** — discard the candidate (candidate := running).

The promise: *nothing enforcement-relevant changes until an explicit commit.*

## 2. Locked product decisions

Two posture calls were made by the product owner (2026-07-13) and are load-bearing
for this design:

1. **Rollout = opt-in, per-instance.** A persisted setting `RequireCommit`
   (default **false**). When **false**, behavior is **byte-identical to today**
   (live-write; the draft machinery is dormant and never consulted). When
   **true**, policy rulebase writes stage into the candidate and require a
   commit. This preserves every existing operator's muscle memory and makes the
   feature a pure addition, not a breaking change.

2. **Single shared candidate.** One draft for the whole appliance — not
   per-admin. A second admin sees and can continue the same pending changes; a
   commit activates everything staged. This matches Culvert's single-console
   scale and avoids the per-admin merge/conflict state machine the M3 review
   explicitly rejected (§3, "commit queues/partial commits ... single-admin-console
   scale does not justify the state machine"). Concurrent-edit *awareness* (who
   opened the draft, optimistic-concurrency guard on commit) is in scope; draft
   *isolation* is not.

## 3. Scope

**In scope:** the Stage-2 access rulebase (`ruleType` "" / "access") — rule
content edits (create/update/delete, by-priority and by-id) **and** ordering
(reorder/move) unified under the one candidate. Ordering already has a
client-side staged bar (M3 S5, G3); when `RequireCommit` is on, reorder stages
into the same server-side candidate as content, so the two models do not fight.

**Out of scope (this feature):** Stage-1 auth rules (reserved, inert at runtime);
taxonomy objects (categories/groups/decryption profiles — separate stores, their
own upsert/rollback story); global settings; per-admin drafts; commit queues;
partial/selective commit of a subset of staged changes (all-or-nothing commit).
Shadow-rule detection **at commit** (G4 backend) is a follow-up slice, not the
skeleton.

## 4. Data model

The candidate cannot live in a new `internal/` engine: it holds `PolicyRule`
values and reuses `PolicyStore` validation/sort/ID/ordering logic, all of which
are `package main`. It is therefore a main-package construct.

```
policyStore       *PolicyStore   // RUNNING rulebase. Enforced. Persisted to policy.json. UNCHANGED.
policyDraft       *policyDraftCoordinator
```

```go
// policyDraftCoordinator owns the single shared candidate rulebase and its
// lifecycle. It wraps a second *PolicyStore (the candidate) plus draft metadata.
type policyDraftCoordinator struct {
    mu     sync.RWMutex
    cand   *PolicyStore // candidate rules; persisted to policy_draft.json
    state  draftState
}

type draftState struct {
    Active         bool   `json:"active"`         // a dirty draft exists (candidate diverges from running)
    Actor          string `json:"actor"`          // admin who first staged into the current draft
    StartedAt      string `json:"startedAt"`      // RFC3339 UTC
    BaseGeneration uint64 `json:"baseGeneration"` // policyStore generation the draft forked from (optimistic-concurrency)
}
```

- The candidate `*PolicyStore` persists to `<dataDir>/policy_draft.json` so an
  in-progress draft **survives a restart / browser crash** — the M3 guardrail
  ("M3 must NOT fake it client-side — a browser crash losing 'staged' rules the
  operator believed saved is worse than live-write").
- "Clean" (no draft) ⇔ `state.Active == false`. In the clean state the candidate
  store is not authoritative and is re-seeded from running on the next stage.
- `BaseGeneration` records `policyStore`'s rule-set generation (the existing
  optimistic-concurrency counter, P2 / #688) at the moment the draft was opened.
  Commit refuses if running has advanced past it via a path that bypassed the
  draft (defense-in-depth; with the draft as the sole write target while active,
  this should not happen, but a direct config-import/rollback could).
- **Candidate generation (multi-admin on the shared draft).** Because the
  candidate is itself a `*PolicyStore`, it carries its OWN generation counter
  (`policyVersion()`), bumped by every staged edit. This is what the
  optimistic-concurrency guard must read *while drafting* — the running store's
  version does not move during staging, so guarding on it would let two admins
  who loaded the same draft silently overwrite each other's staged edits before
  commit (raised in design review, Codex P2). See §7.

## 5. Write routing

A single chooser decides where policy writes land:

```go
// policyWriteStore returns the store that policy WRITE handlers mutate: the
// candidate when commit-mode is engaged, else the running store (today's path).
// Reads for enforcement ALWAYS use policyStore directly — never this.
func policyWriteStore() *PolicyStore {
    if requireCommitEnabled() {
        return policyDraft.stageTarget() // opens/re-seeds the candidate on first write
    }
    return policyStore
}
```

- Every mutating policy handler (`apiPolicyCreate`, `apiPolicyUpdate`,
  `apiPolicyDelete`, `apiPolicyUpdateByID`, `apiPolicyDeleteByID`,
  `apiPolicyBulkDelete`, `apiPolicyReorder`, `apiPolicyMove`) swaps its
  `policyStore.<Mutate>` / `policyStore.List()`-for-validation calls to
  `policyWriteStore()`. When `RequireCommit` is off, `policyWriteStore()==policyStore`
  and the code path is unchanged.
- `stageTarget()` lazily copies running → candidate and sets `Active/Actor/StartedAt/
  BaseGeneration` on the FIRST write of a new draft; subsequent writes reuse it.
- **Enforcement (`policyStore.Evaluate`) and every read on the proxy hot path are
  untouched** — they always read `policyStore`. Zero hot-path risk; the draft is
  invisible to traffic.

## 6. Config-version + cluster interaction

- **Per-edit `saveConfigVersion` is gated.** While a write lands in the draft,
  the per-handler `saveConfigVersion(actor, "policy.add"|...)` is **skipped** —
  the running config did not change, so snapshotting it would produce a
  misleading no-op version. A single `saveConfigVersion(actor, "policy.commit")`
  fires on COMMIT, capturing the newly-activated running config. (Helper:
  `saveConfigVersionForPolicyWrite` no-ops when the write was staged.)
- **CP→DP sync is commit-only, for free.** `ConfigSnapshot` is built from
  `policyStore`. Draft writes never touch `policyStore`, so drafts are
  automatically excluded from cluster sync. Commit does `policyStore.ReplaceAll(candidate)`
  then the existing snapshot/publish path fires exactly once. No ConfigSnapshot
  schema change; `config_surfaces_test.go` parity is preserved (the draft is not
  a synced field).
- **`RequireCommit` joins the config surface.** It is a persisted `AdminSettings`
  field (GUI-managed, restart-durable). Per Finding 10.3 walls it must be
  declared in the `configSurfaces` registry. It is admin_settings-durable and
  export/import-visible; it is **off the rollback surface** (rolling back the
  rulebase should not silently flip the governance mode) — same treatment as the
  other operational toggles (`ConnLimitEnabled`, etc.).

## 7. Lifecycle & edge cases

- **Open draft:** first policy write while `RequireCommit` on → copy running →
  candidate, `Active=true`.
- **Commit** (`POST /api/policy/draft/commit {comment}`): (1) require non-empty
  comment; (2) optimistic-concurrency check `BaseGeneration` vs running's current
  generation; (3) validate the candidate as a SET (per-rule validity is already
  enforced at stage time; commit re-runs it + the future G4 shadow check);
  (4) `policyStore.ReplaceAll(candidate.List())`; (5) `policyStore.Save()`;
  (6) `saveConfigVersion(actor, "policy.commit")` with the comment in the detail;
  (7) cluster snapshot/publish (existing path); (8) `auditEvent`/`auditEventDiff`
  with the comment + diff summary; (9) clear draft (`Active=false`, delete
  `policy_draft.json`).
- **Revert** (`POST /api/policy/draft/revert`): discard candidate, `Active=false`,
  delete draft file, audit `policy.draft.revert`. Running untouched.
- **Toggle `RequireCommit` OFF while a dirty draft exists:** **blocked** (409) —
  the admin must commit or revert first. Prevents silently orphaning staged
  changes that the operator believed were pending. (Toggling ON is always allowed;
  it just arms the machinery.)
- **Restart with a dirty draft:** `policy_draft.json` reloads into the candidate;
  `draftState` reloads (persisted alongside). The pending-changes bar reappears.
- **Concurrent edits on the shared candidate (multi-admin):** the existing
  `?ifVersion=` optimistic-concurrency precondition (`policyVersionConflict`)
  reads the **effective** store's generation — the candidate's while a draft is
  open, running's otherwise. `GET /api/policy` and `GET /api/policy/draft`
  return that same effective version so a client sends back the version it
  actually loaded. Two admins who load the shared draft at candidate-version 5,
  one stages an edit (→ 6), the other's `ifVersion=5` write is rejected 409 —
  exactly the running-store guarantee, now extended to the draft. (Closes the
  design-review gap: staged edits don't bump running, so guarding on running
  would miss shared-candidate collisions.)
- **Direct import/rollback while drafting:** these write `policyStore` directly
  (they are whole-config operations). The `BaseGeneration` guard makes the next
  commit fail closed with a clear "running config changed under your draft —
  re-review" error rather than clobbering the import.

## 8. API surface (GUI parity mandatory)

| Method + path | Role | Purpose |
|---|---|---|
| `GET /api/policy/draft` | viewer | Draft state + diff vs running (added / modified / removed rule summaries) |
| `POST /api/policy/draft/commit` | operator | Body `{comment}`. Validate → activate → snapshot → sync → clear. Required comment. |
| `POST /api/policy/draft/revert` | operator | Discard the candidate. |
| `GET/PUT /api/policy/draft/settings` | admin (PUT) / viewer (GET) | Read/set `requireCommit`. PUT-off blocked while dirty. |

All registered via a `registerPolicyDraftRoutes` helper with matching `uiRoutes`
metadata (C1 parity), handler-level `requireRole` (defense-in-depth), and
`auditExpected` where mutating. The existing `apiPolicy*` handlers keep their
routes; only their internal store target changes.

## 9. UI (single-file SPA, `static/index.html`)

- **Setting toggle** in the Policy view header / settings: "Require commit for
  policy changes" (admin-only), with a one-line explanation.
- **Pending-changes bar** on the Policy view when `draft.active`: "N pending
  changes — [Review & commit] [Revert]", styled like the existing S5 staged-reorder
  bar (visual precedent already in the codebase). Shows who opened the draft.
- **Commit modal**: renders the diff (added/modified/removed rules, reusing the
  config-version diff rendering where possible) + a **required comment** textarea;
  the typed-confirmation pattern already exists for dangerous actions.
- The rulebase table, while drafting, renders the **candidate** rules (so the
  admin edits what they will commit) with a subtle "draft" affordance; when not
  drafting it renders running as today.

## 10. Test plan

- **Off-mode parity:** with `RequireCommit=false`, every `apiPolicy*` handler
  path is byte-identical to today (writes hit running immediately; per-edit
  config-version fires). A table test asserts `policyWriteStore()==policyStore`.
- **Stage isolation:** with `RequireCommit=true`, a staged create/update/delete
  does NOT change `policyStore.List()` or `Evaluate`'s decision; the candidate
  reflects the edit; no per-edit config-version is written.
- **Commit:** activates the full candidate atomically, writes exactly one
  `policy.commit` config-version carrying the comment, fires the cluster snapshot
  once, clears the draft.
- **Revert:** running unchanged, draft cleared.
- **Required comment / empty comment → 400.**
- **Toggle-off-while-dirty → 409.**
- **Restart durability:** persist a dirty draft, reload a fresh coordinator from
  disk, assert the candidate + state survive.
- **Optimistic concurrency:** advance running's generation under a draft →
  commit fails closed.
- **Config-surface parity:** `config_surfaces_test.go` extended for the new
  `RequireCommit` field; ConfigSnapshot parity unaffected (draft not synced).
- **e2e (`uie2e`):** toggle on → stage an edit → live traffic still hits the old
  rule → commit with a comment → live traffic hits the new rule; revert path.

## 11. Slicing (each independently shippable, PR-sized)

- **S1 — backend skeleton (this feature's core):** `RequireCommit` setting
  (AdminSettings + config-surface parity) · `policyDraftCoordinator` + candidate
  `*PolicyStore` + `policy_draft.json` persistence · `policyWriteStore()` routing
  through all mutating `apiPolicy*` handlers · per-edit snapshot gating ·
  commit/revert/diff/settings API + routes + metadata · full backend + parity
  tests. Off-mode proven byte-identical.
- **S2 — UI:** setting toggle · pending-changes bar · commit modal with diff +
  required comment · candidate-aware rulebase render · e2e.
- **S3 — commit-time shadow detection (G4 backend)** + `policy.commit` audit
  comment surfaced in history + multi-admin "another admin has an open draft"
  banner (uses `draftState.Actor`).

S1 is the foundation and lands first; S2 makes it operable from the GUI (GUI
parity is only *complete* after S2, so S1's PR notes the follow-up explicitly);
S3 is polish + the analytic that makes commit valuable.

## 12. Rejected alternatives

- **Per-admin drafts / commit queues** — rejected by product decision §2.2 and
  the M3 review; single-console scale.
- **Client-side-only staging for content** — rejected by the M3 G2 guardrail
  (crash-loses-staged-rules is worse than live-write). Ordering (G3) stays
  client-staged only while `RequireCommit` is off; when on, it folds into the
  server candidate.
- **A new `internal/policydraft` engine** — impossible without hoisting
  `PolicyRule`/`PolicyStore` out of `package main` (a large, unrelated refactor);
  the coordinator lives in main alongside the types it reuses.
- **Making the candidate a diff/patch set** rather than a full rule copy —
  rejected; a full `*PolicyStore` reuses all existing validation/sort/ID/ordering
  logic and makes "render the candidate" trivial. The diff is computed for
  display, not stored.
