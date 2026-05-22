# CategoryGroups Rollback-Surface Extension — DESIGN/SPEC

**Status:** discovery + design specification. **No production code changes in this PR.** No test changes. This is the design review before any rollback-surface code lands.

**Why this needs a careful contract review:** this is the **first expansion of the rollback surface in the project's history**. Until now the surface (`captureConfigBackup` + `applyConfigBackup`) has been static at 9 store-families. Adding a 10th store family requires extending the snapshot struct, the capture path, and the apply path together — and any future surface extension (alert webhooks, URL categories, scanner config, etc. — see `CONFIG-VERSIONING-TRIAGE.md` §4 B′ / C / D′ groups) will model on this one. The contract decisions made here set the precedent for the rest of the surface-extension follow-ups in the cross-discovery backlog.

**Scope (deliberate):**

- Discovery / specification documentation only.
- No production code changes.
- No `saveConfigVersion` additions or removals.
- No `captureConfigBackup` / `applyConfigBackup` changes yet.
- No `ConfigSnapshot` changes.
- No HA changes.
- No policy-engine refactor.
- No URL categories / scanner / CA / cluster work.

---

## 1. Current CategoryGroups lifecycle

### 1.1 Storage type

`globalCategoryGroups *CategoryGroupStore` (`categorygroup.go:51`).

- **In-memory state:** `groups map[string]*CategoryGroup` keyed by lowercase name + `order []string` (insertion order). Protected by `sync.RWMutex`.
- **`CategoryGroup` struct** (`categorygroup.go:31-41`): `ID` (UUID prefix), `Name`, `Categories []string`, `CreatedAt`, `UpdatedAt`, plus an unexported `catSet map[string]bool` (rebuilt on every mutation; not serialized).
- **Performance contract:** `catSet` provides O(1) host→group membership check on the proxy hot path. Rebuilt outside the write lock by `buildCatSet`.

### 1.2 Persistence layer

| Operation | Method | Storage |
|---|---|---|
| Load at startup | `globalCategoryGroups.Load(filepath.Join(dataDir, "category_groups.json"))` at `main.go:776` | JSON array of `CategoryGroup` |
| Persist after mutation | `Save()` at `categorygroup.go:115-142` | `atomicWriteFile` (fsync — bucket-4 hardened in PR #246) |

`Load` rebuilds `catSet` for every group via `buildCatSet`. `Save` strips `catSet` (only serializes the exported fields) and writes atomically. **Missing file at startup is non-fatal** — returns nil; the store stays empty.

### 1.3 Mutation handlers

All admin mutations live in `ui_policy.go` under `apiCategoryGroups` (POST/PUT/DELETE):

| Handler | Lines | Mutation | Saves to disk | saveConfigVersion |
|---|---|---|---|---|
| POST add | `ui_policy.go:371-378` | `globalCategoryGroups.Add(name, categories)` + `Save()` | YES | **YES** (today — Category D′ misleading) |
| PUT update | `ui_policy.go:392-399` | `globalCategoryGroups.Update(name, categories)` + `Save()` | YES | **YES** (D′) |
| DELETE | `ui_policy.go:417-424` | `globalCategoryGroups.Delete(name)` + `Save()` | YES | **YES** (D′) |

Each call already invokes `saveConfigVersion` today — these are the calls flagged as **Category D′ misleading** in `roadmap/CONFIG-VERSIONING-TRIAGE.md` (the snapshot envelope is written but does NOT contain the mutation, because `captureConfigBackup` does not read `globalCategoryGroups`). This spec describes how to make those existing calls **correct** by extending the rollback surface.

### 1.4 ConfigSnapshot interaction (HA / cluster-sync)

CategoryGroups IS in the cluster-sync surface today:

- **Wire format:** `ConfigSnapshot.CategoryGroups []CategoryGroup` (`controlplane.go:116`).
- **Capacity cap:** `maxSnapCategoryGroups = 1_000` (`controlplane.go:154`); enforced by `validateConfigSnapshot` at `:183`.
- **Captured (CP→DP):** `snap.CategoryGroups = globalCategoryGroups.List()` at `controlplane.go:1708`.
- **Applied (on DP / HA-standby):** `controlplane.go:1609-1613`:
  ```go
  if snap.CategoryGroups != nil {
      globalCategoryGroups.ReplaceAll(snap.CategoryGroups)
      globalCategoryGroups.Save()
  }
  ```

So the rollback-surface gap is asymmetric: **HA replicates category groups; rollback does not restore them.** A DP node receives category groups every heartbeat, but a CP rollback from v6 to v3 leaves them at v6's state.

### 1.5 Referential structure: PolicyRules → CategoryGroups

- `PolicyRule.DestCategoryGroup` (`policy.go:324`) holds the group name (case-insensitive).
- `matchDest` evaluates it at `policy.go:827`: `globalCategoryGroups.MatchesHost(rule.DestCategoryGroup, host)`.
- **`MatchesHost` returns `false` for unknown groups** (`categorygroup.go:276-287`, "unknown group = no match (fail-closed)"). Net effect at the policy layer: a rule referencing a non-existent group never matches; the rule is effectively inert and policy evaluation falls through to lower-priority rules / default action.
- `apiCategoryGroups` DELETE enforces referential integrity at mutation time (`ui_policy.go:412-418`): blocks deletion if any policy rule references the group. **But there is NO validation at PolicyRule add/update time** (`ui_helpers.go:98-129`) — a rule can be saved with a `DestCategoryGroup` that does not exist; runtime fails closed.
- `apiURLCat` DELETE also enforces a category→group check (`ui_policy.go:532`).

The unidirectional referential integrity check (delete-group blocks if referenced) is the key behavioral lever the rollback spec must consider.

---

## 2. Exact rollback inconsistency today

### 2.1 The pure rollback-surface gap

`captureConfigBackup` (`configversion.go:59-79`) and `applyConfigBackup` (`configversion.go:325-388`) both contain `PolicyRules` but not `CategoryGroups`. Rolling back from v3 to v2 restores the policy-rule snapshot from v2 but leaves `globalCategoryGroups` untouched at its current state. The version log entry written by today's `saveConfigVersion` call inside `apiCategoryGroups` says "category-group.add at v3" but rolling back to v2 does not undo the add.

### 2.2 The dependent-state hazard

The PolicyRules → CategoryGroups reference is the deciding factor. Three problematic operator workflows result from the gap:

**Hazard A — restored rule references deleted group.**

1. v2 contains group `G1` and a policy rule `R1: DestCategoryGroup=G1`.
2. Operator deletes `R1` (allowed; the referential check at `ui_policy.go:412-418` only blocks group-delete-while-referenced, not the reverse).
3. Operator deletes `G1` (now allowed because no rule references it).
4. Snapshot v3 has empty rules, empty groups.
5. Operator rolls back v3 → v2. PolicyRules restore: `R1` is back, references `G1`. CategoryGroups: still empty.
6. `R1` evaluates: `MatchesHost("G1", host)` returns `false` (unknown group, fail-closed). The rule is silently inert. Policy evaluation falls through; the operator's mental model of "v2 restored" is wrong.

**Hazard B — current rule still references group that v2 lacked.**

1. v2 has no groups defined and no rules referencing groups.
2. Operator creates group `G2` and rule `R2: DestCategoryGroup=G2`.
3. Snapshot v3 has `G2` + `R2`.
4. Operator rolls back v3 → v2. PolicyRules restore: `R2` is removed (because v2's PolicyRules slice is empty). CategoryGroups: untouched, `G2` persists.
5. `G2` is now an orphan group with no references. Not a runtime bug, but cluttered state and inconsistent with the v2 baseline.

**Hazard C — group categories changed between versions.**

1. v2: `G3 = {ai, marketing}`. Rule `R3` references `G3`.
2. Operator updates `G3 = {ai, marketing, gambling}`. Snapshot v3.
3. Operator rolls back v3 → v2. PolicyRules: `R3` restored as-is (already there). CategoryGroups: untouched, `G3` still `{ai, marketing, gambling}`.
4. `R3` now matches hosts in `gambling` even though v2's intent was that `R3` only covered `ai`+`marketing`.

### 2.3 Zero Trust safety net

In all three hazards, the Zero Trust default-deny posture catches the worst-case fall-through (request denied if no rule matches). But the operator's INTENT is silently violated — they believed v2 was restored. The rollback log claims the restoration; the runtime behavior contradicts it.

---

## 3. Proposed rollback extension

### 3.1 `configBackup` struct addition

Add to `ui_policy.go:620-643`:

```go
type configBackup struct {
    // ... existing 17 fields ...

    // CategoryGroups extends the rollback surface to cover the
    // PolicyRules → CategoryGroup reference. See
    // roadmap/CATEGORYGROUPS-ROLLBACK-EXTENSION-SPEC.md.
    CategoryGroups []CategoryGroup `json:"categoryGroups,omitempty"`
}
```

`omitempty` is required for backward compatibility with v3 (zero-value snapshots from before this extension landed) — see §6.

### 3.2 `captureConfigBackup` addition

Add to `configversion.go:59-79`, alongside the existing 9 surface items:

```go
return &configBackup{
    // ... existing fields ...
    CategoryGroups: globalCategoryGroups.List(),
}
```

`List()` (`categorygroup.go:144-158`) already returns a defensive copy that strips the unexported `catSet`. Same shape as `ConfigSnapshot.CategoryGroups` capture at `controlplane.go:1708`.

### 3.3 `applyConfigBackup` addition + ordering

Add **before** the PolicyRules block at `configversion.go:340`. Order matters — see §3.4 below.

```go
// CategoryGroups — must come BEFORE PolicyRules so that any
// validation logic added in the future can verify rule references
// against the restored groups. Today validatePolicyRule does NOT
// check group existence, so the order is performance / mental-model
// only. ReplaceAll + Save mirror the existing applyConfigSnapshot
// shape at controlplane.go:1609-1613.
if b.CategoryGroups != nil {
    globalCategoryGroups.ReplaceAll(b.CategoryGroups)
    globalCategoryGroups.Save()
}

// Policy rules: bulk replace.
var validRules []PolicyRule
// ... existing block ...
```

Treatment of `b.CategoryGroups == nil` versus `[]CategoryGroup{}`:

- **`nil` (backward compat):** old snapshot from before the extension, or any decoded JSON where the field is absent / explicit `null`. Skip the apply block entirely; leave current `globalCategoryGroups` untouched. See §6 for the migration argument.
- **`[]CategoryGroup{}` (empty slice):** new snapshot recorded at a state with zero category groups; restore that — i.e. wipe `globalCategoryGroups`. `ReplaceAll([]CategoryGroup{})` is the existing wholesale-replace semantic and produces an empty live store.
- **populated:** wholesale replace.

To make this distinction observable end-to-end, **`captureConfigBackup` must always populate the field with a non-nil slice** (even when there are zero groups) AND **the struct tag must NOT use `omitempty`** (so the marshaller writes `"categoryGroups": []` rather than omitting the field):

```go
type configBackup struct {
    // ... existing 17 fields ...

    // CategoryGroups uses `json:"categoryGroups"` WITHOUT omitempty so
    // that a snapshot recorded at zero groups serializes as `[]` and
    // distinguishes itself from an old pre-extension snapshot which
    // simply lacks the field (Go decodes that to nil). See §6.4.
    CategoryGroups []CategoryGroup `json:"categoryGroups"`
}
```

`globalCategoryGroups.List()` already returns a non-nil empty slice for an empty store (`categorygroup.go:144-158` uses `make([]CategoryGroup, 0, len(s.order))`), so no extra defensive init is required in `captureConfigBackup`. The capture call site at §3.2 produces `[]CategoryGroup{}` for the zero-group case directly.

**This is the corrected recommendation; an earlier draft of this spec used `omitempty` and `nil`-skip, which left Hazard B unresolved (a rollback to a zero-group snapshot would NOT wipe current groups). The corrected JSON shape preserves Hazard B's resolution: a snapshot taken at "no groups" round-trips to "no groups" via rollback.**

### 3.4 Ordering rationale

`globalCategoryGroups.ReplaceAll` must precede `policyStore.ReplaceAll` because:

1. **Future-proofing:** if a future PR adds group-reference validation to `validatePolicyRule`, the validation runs against the to-be-restored groups, not the current live state. Today this is a no-op (the validation doesn't exist) but doing it in the right order now prevents subtle bugs on the next PR.
2. **Mental model:** the operator-visible contract is "v2 restored". When the apply path returns, the state is consistent — every rule sees its target groups in their v2 form, not their pre-rollback form.
3. **Mirror of ConfigSnapshot:** `applyConfigSnapshot` at `controlplane.go:1609` also applies CategoryGroups; placing it before PolicyRules in the rollback path keeps the two surfaces symmetrical.

**Concurrent reads during apply — actual lock semantics.** `configRollbackMu` serializes `applyConfigBackup` callers against each other but does **NOT** exclude the proxy hot path or admin reads. The proxy reads `policyStore` and `globalCategoryGroups` via their own independent RWMutexes during a rollback apply. So an intermediate-state read by the proxy during the apply window IS observable — there is no implicit "no concurrent reads" guarantee from `configRollbackMu`.

Given that, the ordering choice determines which intermediate state is observable rather than whether one exists at all:

- **Groups-first (proposed):** request arriving mid-apply sees either (old policy + old groups) OR (old policy + new groups) OR (new policy + new groups). The (new policy + new groups) terminal state is correct. The (old policy + new groups) middle state still evaluates correctly because old policy rules either reference v2 groups already present in the new set, or reference groups that don't exist (fail-closed via `MatchesHost`). The (old policy + old groups) state is the pre-rollback state — no behavior change observed.
- **Rules-first (rejected):** request mid-apply could see (new policy + old groups). New rules might reference groups that are still in their pre-rollback form (different categories than v2) or absent entirely. Wrong behavior, not just stale.

Both orderings produce a brief observable intermediate-state window. Groups-first picks the safer set of intermediates. The ordering choice does NOT eliminate the window and **does NOT rely on any lock** beyond the per-store RWMutexes that already protect each individual `ReplaceAll`.

`globalCategoryGroups.Save()` after the `ReplaceAll` mirrors the existing `controlplane.go:1613` pattern (caller-side persist on top of `atomicWriteFile`).

---

## 4. Failure semantics

### 4.1 Invalid groups in the snapshot

`ReplaceAll` (`categorygroup.go:241-257`) does NOT validate per-entry shape: it accepts whatever the snapshot says. Two failure modes:

- **Empty `Name`** — would land in the `groups` map under the empty-string key. `ReplaceAll` would happily accept it; subsequent `GetByName("")` returns the orphan. This is the same behaviour as today's `apiCategoryGroups` POST when called with an empty name, except POST returns an error (`categorygroup.go:172-174`) which never reaches ReplaceAll.
- **Duplicate names** — `ReplaceAll`'s loop builds `built[strings.ToLower(g.Name)]` and the LATER entry wins; the `order` slice records both keys (duplicate strings) but only one entry exists in `groups`. `List()` (`categorygroup.go:144-158`) iterates `order` with an `ok` check that skips already-deleted entries, so the duplicate name in `order` is harmless but produces undefined behaviour for "what does List() return when two entries share a name".

**Decision: do NOT add validation in `applyConfigBackup`.** Existing snapshots that round-trip via `captureConfigBackup → applyConfigBackup` are well-formed by construction (the source is `List()` which produces no duplicates and no empty names). Snapshots written by a future operator-restore-from-disk feature might contain malformed entries, but that's a hardening item for a separate PR with its own design discussion. The existing `validateConfigSnapshot` validates the wire-format slice size cap, not per-entry shape, so this matches the rollback layer's existing posture.

### 4.2 Missing groups during rollback (snapshot has fewer groups than current)

`ReplaceAll` is wholesale replacement — any group present in live state but absent from the snapshot is dropped. This is the correct rollback semantic (matches "restore v2's state"). The policy-rule references to dropped groups become fail-closed (per `MatchesHost`'s nil-guard at `categorygroup.go:278-280`).

If §3.3's `nil`-skip pattern is adopted, only an EXPLICITLY-empty slice in the snapshot would trigger this drop. A `nil` slice (legacy snapshot) leaves the live state intact.

### 4.3 Partial apply

`ReplaceAll` is atomic under the store's `sync.RWMutex` — either the full new map is installed or none of it is. There is no partial-apply window. `Save()` after the in-memory swap is best-effort (logged on failure); the in-memory state is authoritative for the next request. Same shape as `apiCategoryGroups` mutation handlers.

### 4.4 Concurrent reads during rollback

`applyConfigBackup` runs under `configRollbackMu.Lock()` (`configversion.go:326-327`), which serializes against `applyConfigBackup` callers but NOT against the proxy hot path. The proxy reads `globalCategoryGroups.GetByName` (RLock) on every policy evaluation. The new `ReplaceAll` write-lock contention adds a brief block window. Existing `apiCategoryGroups` POST/PUT/DELETE already do this; the rollback adds one more concurrent writer. No new correctness concern.

### 4.5 catSet rebuild

`ReplaceAll` rebuilds `catSet` for every group OUTSIDE the lock (`categorygroup.go:243-250`) and swaps the new map under the lock. This is the existing performance contract; the rollback path inherits it unchanged.

---

## 5. Test strategy

Three new tests in a new test file `configversion_category_groups_test.go` (mirrors the PR #260 / #263 / #264 / #265 file-per-feature pattern):

### 5.1 Round-trip rollback

**`TestConfigVersion_CategoryGroups_RoundTrip`**

1. `snapshotConfigVersionsDir(t)` (PR #261 helper) — redirect to tmp.
2. Snapshot/restore `globalCategoryGroups` via a new helper `snapshotGlobalCategoryGroups(t)` (mirrors `snapshotGlobalClusterStore` from PR #255).
3. Wipe groups, then add two known groups `G1, G2`.
4. Call `saveConfigVersion("test", "test-step-1")` → captures v1.
5. Add a third group `G3`, mutate `G2`'s categories.
6. Call `saveConfigVersion("test", "test-step-2")` → captures v2.
7. Read v1's envelope from disk, unmarshal to `configBackup`, call `applyConfigBackup(&backup)`.
8. Assert: `globalCategoryGroups.List()` matches the v1 state exactly (only `G1`, `G2` with original categories).

This proves the round-trip semantics work and there is no `catSet` corruption (verified by calling `MatchesHost` on a known host→category pair).

### 5.2 Rule → group integrity after rollback

**`TestConfigVersion_CategoryGroups_RuleIntegrity`**

1. Same fixture setup as 5.1.
2. Seed v1 with: group `G1 = {ai, marketing}` + policy rule `R1: DestCategoryGroup=G1, Action=Allow`.
3. Mutate to v2: delete `G1`, delete `R1`.
4. Rollback to v1.
5. Assert: `policyStore.List()` contains `R1`; `globalCategoryGroups.GetByName("G1")` is non-nil and has categories `{ai, marketing}`; `MatchesHost("G1", "<host-in-ai-category>")` returns `true`.

This is the regression guard against the §2.2 Hazard A — proves the extension closes the dependent-state gap.

### 5.3 Backward-compat with old snapshots

**`TestConfigVersion_CategoryGroups_NilSnapshotIsNoOp`**

1. Seed live state with groups `G1, G2`.
2. Build a `configBackup` struct WITHOUT setting `CategoryGroups` (i.e. nil — simulating an old snapshot pre-extension).
3. Call `applyConfigBackup(&backup)`.
4. Assert: live state still has `G1, G2` (nil-skip semantics — the apply does NOT clear groups when the snapshot says nil).

This pins the §6 migration contract.

### 5.4 Shuffle / race considerations

The CategoryGroups apply path is a new concurrent writer; the test file must:

- Snapshot `globalCategoryGroups` whitebox via the new helper.
- Snapshot `configVersionsDir` + `configVersionSeq` (existing helper).
- Snapshot `policyStore` if a test in this file seeds rules (existing helpers in test suite — `snapshotPolicyStore` or equivalent; verify against `ui_test.go`).
- Run under `go test -race -count=1` + `go test -count=2 -shuffle=on` — same gate as every CDR / blocklist PR in this series.

Two tests in this file mutate `globalCategoryGroups`; under `-shuffle=on -count=2` they may interleave. The snapshot/restore pattern is per-test and uses `t.Cleanup`, so cross-test pollution is bounded.

### 5.5 What this test set does NOT prove

- It does NOT prove behavior under HA failover (CategoryGroups extension is rollback-only; HA already syncs them).
- It does NOT prove behavior with malformed snapshots (per §4.1 decision — out of scope; future hardening PR).
- It does NOT prove behavior under concurrent admin mutations during rollback. `configRollbackMu` serializes only the rollback callers themselves — the proxy hot path and admin reads continue to access `policyStore` and `globalCategoryGroups` via their own RWMutexes during the apply window. See §3.4 for the corrected lock semantics and why groups-first ordering is the safer of the two observable intermediate-state windows.

---

## 6. Migration / backward compatibility

### 6.1 Old snapshots without `CategoryGroups`

Snapshots written before this extension was deployed have no `categoryGroups` field. Unmarshalling into the extended `configBackup` struct leaves the field as nil (`[]CategoryGroup{}` would also be acceptable but Go's JSON decoder uses nil for absent slice fields). Per §3.3, **nil → skip the apply block** — live `globalCategoryGroups` is untouched.

**Operator-visible contract:** rolling back to a pre-extension snapshot restores the surface as it was at the time the snapshot was taken — that surface did NOT include category groups, so the rollback leaves them at their current value. This is honest to the version log: the snapshot doesn't contain the data, so rollback can't restore it.

### 6.2 New snapshots

After the extension lands, every new snapshot includes `categoryGroups` (possibly empty array). Both old and new snapshots are decodable into the new struct; only new ones round-trip the data.

### 6.3 Forward compatibility (new code reading even older snapshots)

The 50-version cap (`configversion.go:81` documentation + `pruneConfigVersions`) means at most 50 historical snapshots exist. With this extension, the snapshot directory will end up with a mix of pre-extension (no field) and post-extension (with field) envelopes during the rotation window. The mixed-state period is bounded by the rotation rate (every mutation creates a new snapshot; 50 snapshots are kept). Operators who specifically need to "roll back through" a pre-extension snapshot should understand that the category-groups state at that historical point is undefined by the snapshot — the live state at restore time is what they get. This is documented at the apply site.

### 6.4 Zero-value behavior

| Snapshot state | Live state after `applyConfigBackup` |
|---|---|
| `categoryGroups` field absent (old snapshot) | Live `globalCategoryGroups` untouched |
| `"categoryGroups": null` (explicit nil) | Live `globalCategoryGroups` untouched (same as above) |
| `"categoryGroups": []` (explicit empty) | Live `globalCategoryGroups` wiped (operator's intent at snapshot time was "no groups") |
| `"categoryGroups": [...]` (populated) | Live `globalCategoryGroups` replaced wholesale |

The distinction between absent / `null` / `[]` relies on Go's `json` encoding rules:

- A struct field tagged `omitempty` with a nil OR empty slice is omitted entirely from the output (just the field name disappears).
- A struct field NOT tagged `omitempty` with a nil slice marshals as `"field": null`.
- A struct field NOT tagged `omitempty` with a non-nil empty slice marshals as `"field": []`.

The spec recommends the tag **`json:"categoryGroups"`** (NO `omitempty`) combined with `captureConfigBackup` always populating from `globalCategoryGroups.List()` (which returns a non-nil empty slice for an empty store). Result:

- `captureConfigBackup` with zero groups → marshals as `"categoryGroups": []` → decodes to non-nil empty slice → apply WIPES live groups. Hazard B's zero-groups case is resolved.
- `captureConfigBackup` with N groups → marshals as `"categoryGroups": [...]` → apply replaces. Standard case.
- Pre-extension snapshot file → no `categoryGroups` field → decodes to nil → apply skips. Backward-compat preserved.
- An explicit `"categoryGroups": null` (which `captureConfigBackup` will never produce, but a hand-edited / future-tool snapshot could) decodes to nil → apply skips. Same as the absent case, intentionally lenient.

**Earlier draft rejected:** the original spec proposed `omitempty` + nil-skip. Codex P1 (PR #266 review) flagged that this leaves Hazard B unresolved — a snapshot taken at zero groups would omit the field entirely → decode to nil → apply skip → orphan groups persist after rollback. The corrected JSON shape above explicitly distinguishes "field absent in old snapshot" (nil → skip) from "snapshot recorded zero groups" (`[]` → wipe), so Hazard B's resolution is preserved across the full domain.

---

## 7. Sequencing recommendation

This spec ships as PR #266 (this PR). Implementation lands as **PR #267 (after spec review and merge)**:

1. **PR #266 (this PR):** spec + design doc only. Reviewer signs off on the contract before any code lands.
2. **PR #267 (implementation):** 3 source edits + 1 new test file:
   - `ui_policy.go`: add `CategoryGroups []CategoryGroup` to `configBackup` struct.
   - `configversion.go`: capture in `captureConfigBackup`; apply (before PolicyRules) in `applyConfigBackup`.
   - `configversion_category_groups_test.go`: the three tests from §5.
   - **Production diff estimate: ~10 lines.**
   - **Test diff estimate: ~150 lines + the new snapshot helper.**

The existing `apiCategoryGroups` POST/PUT/DELETE `saveConfigVersion` calls **do not change** — they were misleading today (Category D′), and become correct the moment the surface extension lands. The triage doc's §4.1 rows for category-groups flip from "(D) Misleading" to "✓ Correct" as part of PR #267.

---

## 8. What this PR did NOT do (deliberate)

- No production code changes.
- No `saveConfigVersion` removals or additions.
- No `captureConfigBackup` / `applyConfigBackup` changes.
- No `configBackup` struct changes.
- No `ConfigSnapshot` changes.
- No tests added or modified.
- No HA changes.
- No policy-engine refactor.

## 9. No unresolved VERIFY / UNCERTAIN markers

Every claim above is grounded in line-numbered evidence:

- `CategoryGroupStore` shape — `categorygroup.go:31-49`.
- `Load` / `Save` paths — `categorygroup.go:78-142`.
- Mutation handlers + existing `saveConfigVersion` calls — `ui_policy.go:371-424`.
- `ConfigSnapshot` integration — `controlplane.go:116, :1609-1613, :1708`.
- Policy reference — `policy.go:324, :810-829`.
- Referential integrity check (delete-group-while-referenced) — `ui_policy.go:412-418`.
- Absence of group-existence check in `validatePolicyRule` — `ui_helpers.go:98-129`.
- `applyConfigBackup` ordering — `configversion.go:325-388`.
- `MatchesHost` fail-closed semantic — `categorygroup.go:276-287`.

No "probably". No "looks like". No `VERIFY:` markers.
