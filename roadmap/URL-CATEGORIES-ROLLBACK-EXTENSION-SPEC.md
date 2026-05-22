# URL Categories (catStore) Rollback-Surface Decision/Spec

**Status:** discovery + design-decision document. **No production code changes in this PR.** No test changes. This is the dependency-chain review for whether to extend the rollback surface to `catStore` now that `CategoryGroups` was added (PR #267).

**Cross-discovery reference:** P6.1 UC-4 (`roadmap/URL-CATEGORIES-DISCOVERY.md` §10): `apiURLCat` POST/PUT/DELETE and `apiURLCatHost` POST/DELETE call `auditEvent(...)` but do NOT call `saveConfigVersion(...)`. Originally classified as Category C in `roadmap/CONFIG-VERSIONING-TRIAGE.md` §4.1 ("Out of surface"). This spec re-evaluates that decision given PR #267 set the surface-extension precedent.

**Scope (deliberate):**

- Discovery / spec doc only.
- No production code changes.
- No `saveConfigVersion` additions or removals.
- No `captureConfigBackup` / `applyConfigBackup` changes.
- No `ConfigSnapshot` changes.
- No policy-engine refactor.
- No `CategoryGroups` implementation changes.

---

## 1. Current URL category lifecycle

### 1.1 Storage type

`catStore *CategoryStore` (`policy.go:65`).

- **In-memory state:** `entries []*CategoryEntry` (insertion order) + `index map[string]map[string]bool` (lowercase category → lowercase host set, rebuilt on every mutation for O(label) host-membership lookup). Protected by `sync.RWMutex`.
- **`CategoryEntry` struct** (`policy.go:49-53`): `Name`, `Hosts []string`, `BuiltIn bool`. Lightweight (no unexported runtime helpers).
- **Performance contract:** `index` provides O(label-count) host→category match on the proxy hot path. Rebuilt under the write lock by `rebuildIndex` after every `Set` / `Delete` / `AddHost` / `RemoveHost`.

### 1.2 Persistence layer

| Operation | Method | Storage |
|---|---|---|
| Load at startup | `catStore.Load(catPath)` at `main.go:748` | JSON array of `CategoryEntry` |
| Persist after mutation | `Save()` at `policy.go:156-171` | `atomicWriteFile` (fsync — bucket-4 hardened in PR #246) |
| Startup default-seeding | Built-in `defaultCategoryEntries()` from `default_categories.json` embedded at compile time (`policy.go:88-126`); written to disk if file missing | One-shot |
| Startup UT1 seeding | `main.go:753-771` seeds empty entries for every UT1-mapped name so the GUI dropdown shows them | One-shot post-load |

`Load`'s first-run path (`policy.go:128-145`) writes the built-in defaults to disk if no file exists. So the file always exists after first run; rollback applies to whatever's on disk thereafter.

### 1.3 Mutation handlers (apiURLCat + apiURLCatHost)

All admin mutations live in `ui_policy.go`:

| Handler | Lines | Mutation | Saves to disk | saveConfigVersion |
|---|---|---|---|---|
| `apiURLCat` POST create | `:459-488` | `catStore.Set(name, hosts, false)` + internal `Save()` | YES | **NO** |
| `apiURLCat` PUT update | `:490-520` | `catStore.Set(name, hosts, builtIn)` | YES | **NO** |
| `apiURLCat` DELETE | `:522-541` | `catStore.Delete(name)` (after referential check against CategoryGroups) | YES | **NO** |
| `apiURLCatHost` POST add | `:548-572` | `catStore.AddHost(category, host)` | YES | **NO** |
| `apiURLCatHost` DELETE | `:574-589` | `catStore.RemoveHost(category, host)` | YES | **NO** |

Five `auditEvent` call sites, zero `saveConfigVersion` calls. This is the P6.1 UC-4 asymmetry called out in the upstream discovery.

The DELETE handler enforces one-way referential integrity at `:531-535`: blocks deletion if any CategoryGroup references the category (via `globalCategoryGroups.ContainsCategory`). No reverse check at CategoryGroup add/update time.

### 1.4 ConfigSnapshot interaction (HA / cluster-sync)

URLCategories IS in the cluster-sync surface today:

- **Wire format:** `ConfigSnapshot.URLCategories []CategoryEntry` (`controlplane.go:86`).
- **Capacity cap:** `maxSnapURLCategories = 200_000` (`controlplane.go:142`); enforced by `validateConfigSnapshot` at `:171`.
- **Captured:** `snap.URLCategories = catStore.All()` (in `CurrentConfigSnapshot` around `controlplane.go:1666`).
- **Applied:** `controlplane.go:1516-1520`:
  ```go
  if snap.URLCategories != nil {
      catStore.ReplaceAll(snap.URLCategories)
      catStore.Save()
  }
  ```

Same shape as the CategoryGroups apply at `:1609-1613`. The HA path **already replicates URL categories**; the rollback path does not. Same asymmetry CategoryGroups had pre-PR #267.

### 1.5 Two-tier category resolution

Critical for the decision. URL category lookup is **two-tier** (`policy.go:910-922` `matchCategory`, `:927-960` `lookupHostCategory`):

- **Layer 1 (catStore — admin-managed):** exact + suffix match against `catStore.index`. Fast, in-memory.
- **Layer 2 (`communityDB` — UT1 BadgerDB feed):** point lookup against domain-walking trie. Fallback when Layer 1 misses.

`matchCategory(cat, host)` returns true if EITHER layer says `host` is in `cat`. `lookupHostCategory(host)` returns the resolved category name, with `tier="admin"` if Layer 1 matched, `tier="community"` for Layer 2, `tier="none"` for unknown.

### 1.6 CategoryGroups → catStore reference path

`CategoryGroup.catSet` stores **category NAMES** (not host lists). Resolution at the proxy hot path (`categorygroup.go:276-287`):

```go
func (s *CategoryGroupStore) MatchesHost(groupName, host string) bool {
    g := s.GetByName(groupName)
    if g == nil {
        return false // unknown group = no match (fail-closed)
    }
    hostCat, _, _ := lookupHostCategory(host)  // ← BOTH layers
    if hostCat == "" {
        return false
    }
    return g.catSet[strings.ToLower(hostCat)]
}
```

**This is a fundamentally different shape from the PolicyRules → CategoryGroups reference.** A PolicyRule names a CategoryGroup by name; the group must exist for the rule to match. A CategoryGroup names a category by name; the category may exist in catStore Layer 1 OR communityDB Layer 2. So:

| Reference | Single source of truth? | What happens if name unresolved? |
|---|---|---|
| PolicyRule → CategoryGroup | YES (`globalCategoryGroups` only) | `MatchesHost` returns false (fail-closed) |
| CategoryGroup → category | NO (catStore OR communityDB) | Only fails if BOTH layers miss |

This softens (but does not eliminate) the rollback hazard — see §2.

---

## 2. Rollback hazards

### 2.1 Hazard URL-A: CategoryGroup restored references custom category missing from rolled-back catStore

Strongest case for direction B. Sequence:

1. Operator creates custom category `Custom-Cat` with hosts `[foo.com, bar.com]` (NOT in communityDB — purely admin-managed).
2. Operator creates group `G1 = {categories: ["Custom-Cat"]}`.
3. Operator creates policy rule `R1: DestCategoryGroup=G1`.
4. Snapshot v3 captures all three.
5. Operator deletes R1, then G1, then `Custom-Cat`.
6. Snapshot v4 has none.
7. Operator rolls back v4 → v3.

**Current behavior (post-PR #267, catStore NOT in surface):**
- v3 envelope restores `PolicyRules` (R1 returns) and `CategoryGroups` (G1 returns with catSet `{custom-cat}`).
- catStore is NOT restored — `Custom-Cat` is still gone.
- Proxy evaluates R1 for `foo.com`: `MatchesHost("G1", "foo.com")` → `lookupHostCategory("foo.com")` checks Layer 1 (miss — `Custom-Cat` not in catStore) then Layer 2 (miss — `Custom-Cat` not in communityDB) → returns `""` → MatchesHost returns false.
- R1 is silently inert.

**Severity:** the same "rule appears restored but silently doesn't match" hazard PR #267 closed for Hazard A, just one level deeper in the dependency chain.

### 2.2 Hazard URL-B: Built-in category modified, then snapshot taken, then mutation reversed

Sequence:

1. Operator adds custom hosts `[evil.example]` to built-in `News` category at v2.
2. Snapshot v2.
3. Operator removes those hosts via `apiURLCatHost` DELETE at v3.
4. Operator rolls back v3 → v2.

Without URL-categories in the surface, catStore stays at v3 — the `evil.example` addition is permanently lost from the rollback's perspective. The version log lies about reversibility.

### 2.3 Hazard URL-C: Category renamed/replaced

Not a distinct hazard — `catStore.Set` cannot rename a category. A rename is delete-then-create. So this collapses to Hazard URL-A (the deleted half) plus Hazard URL-B (the created half).

### 2.4 Hazard URL-D: Categories added after snapshot, then rolled back

Sequence:

1. Snapshot v2 has 6 built-in categories.
2. Operator adds custom `Marketing-Approved` at v3.
3. Operator creates CategoryGroup `G2 = {categories: ["Marketing-Approved"]}` at v3.
4. Snapshot v3.
5. Operator rolls back v3 → v2.

**Current behavior (post-PR #267):**
- PolicyRules restored to v2 state (no `G2` reference yet).
- CategoryGroups restored to v2 state (no `G2`).
- catStore NOT restored — `Marketing-Approved` persists as an orphan custom category.

**Severity:** mild. The orphan category is harmless on the proxy hot path (no group / rule references it), but it pollutes the GUI category list and the operator's mental model.

### 2.5 Hazard URL-E: Layer 2 (communityDB) interaction

`communityDB` is a Badger-backed feed (UT1) **NOT in the rollback surface**. Rolling back catStore touches only Layer 1.

Scenarios:
- Category that exists ONLY in communityDB (e.g. UT1 mapped name with no admin entry) — Layer 2 lookup is unaffected. ✓
- Category that exists in BOTH layers (UT1-seeded + admin-added hosts) — Layer 1 hosts are rolled back; Layer 2 hosts continue to match. This is correct (Layer 2 is intentionally out-of-band).
- Hosts deleted from a built-in category by admin between v2→v3 (e.g. removed `cnn.com` from `News`) — rolled back to v2 (admin's removal undone), but if `cnn.com` was ALSO in UT1 it would have matched via Layer 2 the whole time anyway. So rollback "restores" hosts that effectively never disappeared from the lookup. Operator-visible state is consistent.

**This is a feature, not a bug.** `communityDB` is intentionally out-of-band; rolling back operator-managed catStore should not touch the community feed. The rollback restores operator intent, not the union of all data sources.

### 2.6 Default fail-closed behavior

Zero Trust default-deny is the policy-engine backstop. Unresolved category references (groups → missing categories) silently produce no rule match; the request falls through to default-deny. So all five hazards are SAFE under fail-closed semantics — they don't open security holes. They violate operator INTENT silently. Same posture as the CategoryGroups hazards PR #267 addressed.

---

## 3. Direction decision

### 3.1 Direction A — keep URL categories OUT of rollback surface

**Argument for:**

- catStore can be VERY large — `maxSnapURLCategories = 200_000` cap. Rollback snapshots could bloat 50× (the 50-version cap), potentially several MB per snapshot × 50 = significant disk footprint.
- Layer 2 (communityDB) is intentionally out-of-band; rolling back catStore changes only the admin-managed half of the picture. Operator might expect "all category data restored" and get only half. The Layer-2 separation could be confusing.
- The five apiURLCat handlers currently do NOT call `saveConfigVersion`. Direction A means leaving them as-is (no new calls to add; nothing misleading exists today since the version log is silent on URL-category mutations).
- The UT1-seeded categories (`main.go:753-771`) are a startup-time hydration step. If a snapshot taken BEFORE first load existed it could mismatch — though in practice all snapshots are post-mutation and post-seed, so this is theoretical.

**Net:** narrowest possible surface, simplest implementation cost (zero), but P6.1 UC-4 remains documented as "the version log doesn't reflect URL-category mutations". Operator expectation is partially mismatched.

### 3.2 Direction B — extend rollback surface to include URL categories

**Argument for:**

- **Dependency-chain completeness.** PR #267 added CategoryGroups because PolicyRules reference them. CategoryGroups reference catStore categories by name. The chain is `PolicyRules → CategoryGroups → catStore`. Without URL categories in the surface, Hazard URL-A reproduces the same shape as the Hazard A that PR #267 closed — just one link deeper.
- **Symmetry with ConfigSnapshot.** HA already replicates URL categories (`controlplane.go:1517`). Rollback being asymmetric is the same pattern PR #267 addressed for CategoryGroups.
- **Operator mental model.** "Rollback v2 restores v2's URL category state" matches expectations.
- **Triage closure.** P6.1 UC-4 was deferred to this triage; direction B is the resolution.

**Net:** completes the dependency chain. Production cost is small (mirror of PR #267). Disk-footprint concern is real but bounded by the existing 50-version cap which already accepts policy + blocklist + rewrite-rule data; URL categories at the 200k-entry cap is the largest single addition but still bounded.

### 3.3 Recommended direction: **B (extend rollback surface).**

The dependency-chain argument is decisive: the PR #267 hazard analysis explicitly named Hazard A (rule restored, group missing); the URL-category Hazard URL-A is structurally identical one link deeper. Resolving CategoryGroups but not catStore leaves a known-broken hazard in the system.

The Layer-2 concern from §3.1 is a feature: rollback is about restoring admin intent, not the union of admin + community data. The `communityDB` continues to work as-is across rollbacks. This is consistent with the existing `applyConfigSnapshot` design (`controlplane.go:1516-1520`) which also touches only Layer 1.

The disk-footprint concern is real but bounded by the same 200k cap that already governs `ConfigSnapshot.URLCategories`. If the rollback directory grows beyond comfort, the existing `pruneConfigVersions` 50-version cap remains the throttle. A future PR could tighten this independently.

---

## 4. If direction B — implementation specification

### 4.1 Struct field addition (`ui_policy.go:620-650`)

Add to the `configBackup` struct, immediately after the CategoryGroups field added by PR #267:

```go
type configBackup struct {
    // ... existing 17 fields ...
    CategoryGroups []CategoryGroup `json:"categoryGroups"`

    // URLCategories extends the rollback surface to cover catStore
    // (admin-managed URL categories). Per
    // roadmap/URL-CATEGORIES-ROLLBACK-EXTENSION-SPEC.md §4.4:
    // json:"urlCategories" WITHOUT omitempty so a snapshot recorded
    // at zero categories serializes as `[]` and distinguishes itself
    // from an old pre-extension snapshot which simply lacks the field
    // (decodes to nil). nil → apply skips; [] → apply wipes;
    // populated → apply replaces. Same shape as CategoryGroups
    // (PR #267) for consistency across the rollback surface.
    URLCategories []CategoryEntry `json:"urlCategories"`
}
```

`omitempty` deliberately absent — same reasoning as PR #267 for CategoryGroups. `catStore.All()` returns a non-nil empty slice for an empty store (`policy.go:174-184` uses `make([]CategoryEntry, len(cs.entries))`), so the wire shape for zero categories is `"urlCategories": []` and round-trips through apply as a wipe.

### 4.2 Capture (`configversion.go:59-79`)

Add to the `captureConfigBackup` return value, alongside `CategoryGroups`:

```go
return &configBackup{
    // ... existing fields ...
    CategoryGroups: globalCategoryGroups.List(),
    URLCategories:  catStore.All(),
}
```

`catStore.All()` already returns a defensive copy with per-entry `Hosts` slice clones (`policy.go:174-184`). Same shape as the existing `ConfigSnapshot.URLCategories` capture in `CurrentConfigSnapshot`.

### 4.3 Apply (`configversion.go:325-388`)

Place **immediately BEFORE the existing CategoryGroups block added in PR #267** — i.e. URL categories restore first, then groups, then policy rules:

```go
bl.Save()
if b.BlocklistMode == "allow" || b.BlocklistMode == "block" {
    bl.SetMode(b.BlocklistMode)
}

// URLCategories MUST be applied before CategoryGroups (which may
// reference categories by name) and before PolicyRules (which may
// reference groups that reference categories). See
// roadmap/URL-CATEGORIES-ROLLBACK-EXTENSION-SPEC.md §4.5 for the
// full dependency-chain ordering.
//
// Layer 2 (communityDB) is intentionally NOT touched — rollback
// restores admin-managed catStore only. communityDB lookups continue
// across the apply window.
//
// nil-skip vs explicit-empty matches the PR #267 CategoryGroups
// pattern:
//   - b.URLCategories == nil → old snapshot (pre-extension) or
//     explicit JSON null; leave live catStore untouched.
//   - b.URLCategories == [] → new snapshot recorded with zero
//     custom + default categories; ReplaceAll wipes catStore.
//   - populated → wholesale replace.
if b.URLCategories != nil {
    catStore.ReplaceAll(b.URLCategories)
    catStore.Save()
}

// CategoryGroups (existing — added by PR #267) ...
if b.CategoryGroups != nil {
    globalCategoryGroups.ReplaceAll(b.CategoryGroups)
    globalCategoryGroups.Save()
}

// Policy rules: bulk replace.
// ... existing block ...
```

### 4.4 Apply ordering rationale (relative to CategoryGroups and PolicyRules)

The full dependency chain is `PolicyRules → CategoryGroups → catStore`. Apply order is the reverse — leaf dependencies first:

1. **catStore (URL categories) first.** CategoryGroups' `catSet` stores category NAMES; restoring catStore first means when CategoryGroups are restored next, every group reference resolves to a category that exists (in Layer 1) or to one that may exist in Layer 2 alone. The intermediate state of "groups restored, but catStore still at pre-rollback" never occurs.
2. **CategoryGroups next.** Already established by PR #267. PolicyRules reference groups by name; restoring groups first ensures restored rules see their target groups in their v2 form.
3. **PolicyRules last.** Existing behavior; unchanged.

**Concurrent reads during apply — same caveat as PR #267 §3.4.** `configRollbackMu` serializes rollback callers, NOT the proxy hot path. Intermediate-state reads ARE observable. The leaf-first ordering picks the safer set of intermediates:

| Intermediate window | catStore | CategoryGroups | PolicyRules | Behavior |
|---|---|---|---|---|
| Pre-apply | old | old | old | Pre-rollback state. No change observed. |
| Post-catStore | **new** | old | old | Old groups reference old category names → `lookupHostCategory` returns category from new catStore (Layer 1 hit, possibly different hosts than before) or Layer 2 (unchanged). Old rules use old groups. Safe — old policy intent against partially-restored data. |
| Post-CategoryGroups | new | **new** | old | Old rules reference old groups → `MatchesHost` for a reference still pointing at a v3 group name fails closed (fail-safe). Old rules against the new group state. Worst case: an old rule references a group renamed in v2 and the rename is restored — old rule fails closed. Safe. |
| Post-PolicyRules | new | new | **new** | Terminal state. Correct. |

Reversed (rules-first) ordering would expose intermediate windows where new rules reference groups in their pre-rollback form, or groups reference categories in their pre-rollback form. Genuinely wrong behavior, not just stale.

### 4.5 Asymmetry with `applyConfigSnapshot`

For the record: `applyConfigSnapshot` (the HA/cluster-sync apply path) currently applies in the **opposite** order — PolicyRules at `:1499-1500`, URLCategories at `:1517`, CategoryGroups at `:1610`. This worked in production because:

- The DP polls every heartbeat — intermediate state is corrected within seconds.
- The CP-side capture (`CurrentConfigSnapshot`) and the DP-side apply happen on different processes; the DP starts from its own previous state, not from a known-good base, so partial-apply effects are smaller.

The rollback `applyConfigBackup` lives in the SAME process as the policy-eval hot path and is operator-triggered (not on a heartbeat); the leaf-first ordering is mandatory there but isn't required for HA. **This spec does NOT propose changing `applyConfigSnapshot` ordering.** Documenting the asymmetry so future engineers don't try to "fix" the HA ordering thinking it's wrong.

### 4.6 Built-in flag preservation

`CategoryEntry.BuiltIn` is captured by `catStore.All()` and applied by `catStore.ReplaceAll`. Round-trip preserves the flag. The startup UT1-seeded categories (`main.go:753-771`) are written to catStore via `Set(name, []string{}, true)` and serialize as `BuiltIn=true` entries. A rollback to a snapshot that lacks one of those seeded entries would remove it from `catStore.entries` (entry visible in admin UI). Next startup re-seeds it via `main.go:753-771`. Operator-visible flicker only.

### 4.7 nil vs empty behavior

Same matrix as the CategoryGroups spec (PR #266 §6.4):

| Snapshot state | Live state after `applyConfigBackup` |
|---|---|
| `urlCategories` field absent (old snapshot) | Live `catStore` untouched |
| `"urlCategories": null` | Live `catStore` untouched |
| `"urlCategories": []` | Live `catStore` wiped to empty |
| `"urlCategories": [...]` | Live `catStore` replaced wholesale |

### 4.8 Should the five `apiURLCat*` handlers call `saveConfigVersion`?

**Yes**, paired with the surface extension. The handlers in `ui_policy.go:459-589` should each gain a `saveConfigVersion(sessionAdmin(r), "urlcat.<action>")` call after their `auditEvent`. Without these calls, the rollback log doesn't actually get a new version on URL-category mutations — operators can't roll back to a state they never snapshotted.

This closes P6.1 UC-4 fully. The implementation PR adds the surface extension AND the five `saveConfigVersion` calls together — splitting them would leave the surface extension orphaned (no envelopes to roll back to).

### 4.9 Tests required (mirror PR #267 §5)

Six tests in a new file `configversion_url_categories_test.go`:

1. **`TestConfigVersion_URLCategories_RoundTrip`** — capture, mutate, apply prior snapshot, assert exact catStore restoration including per-entry `BuiltIn` flag and `Hosts` slices.
2. **`TestConfigVersion_URLCategories_HazardURLA`** — Hazard URL-A regression. Seed v1 with custom category `Custom-Cat` + group referencing it + rule referencing the group. v2 deletes all three. Apply v1; assert the rule's resolved group's referenced category exists in catStore. Pin via `lookupHostCategory(host)` returning the category from Layer 1 (not Layer 2).
3. **`TestConfigVersion_URLCategories_NilSnapshotIsNoOp`** — backward compat: `URLCategories=nil` in snapshot leaves live catStore untouched.
4. **`TestConfigVersion_URLCategories_EmptySnapshotWipes`** — explicit `[]CategoryEntry{}` wipes live catStore.
5. **`TestConfigVersion_URLCategories_EmptyMarshalsAsArray`** — JSON shape contract: zero-categories snapshot serializes as `"urlCategories":[]`.
6. **`TestConfigVersion_URLCategories_BuiltInPreserved`** — seed v1 with a built-in entry and a custom entry, capture, mutate, apply v1, assert both `BuiltIn` flags round-trip correctly.

Additionally, the implementation PR must add five small handler tests proving each of the five `apiURLCat*` handlers produces a version envelope with the right `Meta.Action` (mirrors the pattern from PR #260's `TestAPIBlocklistMode_POST_CreatesConfigVersion`).

Helpers required:
- New `snapshotCatStore(t)` whitebox helper (mirrors `snapshotGlobalCategoryGroups(t)` from PR #267).
- Reuse `snapshotConfigVersionsDir(t)` from PR #261.
- Reuse `snapshotPolicyStoreForTest(t)` (added in PR #267 helper set).

All tests run under `-race -count=1` and `-count=2 -shuffle=on` as a hard gate before merge.

---

## 5. Sequencing recommendation

Spec → implementation, mirroring the CategoryGroups PR #266 → PR #267 pattern:

1. **PR #268 (this PR):** spec + design-decision doc only. Reviewer signs off on direction B and the implementation contract.
2. **PR #269 (implementation):**
   - `ui_policy.go`: add `URLCategories` field to `configBackup`.
   - `configversion.go`: capture in `captureConfigBackup`; apply BEFORE CategoryGroups in `applyConfigBackup`.
   - `ui_policy.go`: add `saveConfigVersion(sessionAdmin(r), "urlcat.<action>")` to all five `apiURLCat*` handlers (closes P6.1 UC-4 fully).
   - `configversion_url_categories_test.go`: six tests per §4.9.
   - `roadmap/CONFIG-VERSIONING-TRIAGE.md`: flip §4.1 `apiURLCat*` rows from "(C) Out of surface (P6.1 UC-4)" to "✓ Correct". Update §1 surface table to add a URL Categories row.
   - **Production diff estimate:** ~25 lines (struct field + capture + apply block + five `saveConfigVersion` lines).
   - **Test diff estimate:** ~200 lines (six structural tests + five handler tests).

---

## 6. What this PR did NOT do (deliberate)

- No production code changes.
- No `saveConfigVersion` removals or additions.
- No `captureConfigBackup` / `applyConfigBackup` changes.
- No `configBackup` struct changes.
- No `ConfigSnapshot` changes.
- No tests added or modified.
- No HA changes (specifically: `applyConfigSnapshot` ordering is documented as asymmetric but NOT modified).
- No CategoryGroups changes.
- No policy-engine refactor.

## 7. No unresolved VERIFY / UNCERTAIN markers

Every claim is grounded in line-numbered evidence:

- `CategoryStore` type — `policy.go:55-65`.
- `CategoryEntry` struct — `policy.go:49-53`.
- `Load` / `Save` / `ReplaceAll` / `All` — `policy.go:128-227`.
- Mutation handlers — `ui_policy.go:459-589`.
- Lack of `saveConfigVersion` in apiURLCat* — direct read of the same handlers (zero matches for `saveConfigVersion(` in the bodies).
- Referential integrity check at DELETE — `ui_policy.go:531-535`.
- `ConfigSnapshot.URLCategories` integration — `controlplane.go:86, :142, :171, :1516-1520, :1666`.
- Two-tier resolution — `policy.go:910-960`.
- `MatchesHost`'s Layer-1+Layer-2 traversal — `categorygroup.go:276-287`.
- `applyConfigSnapshot` ordering — `controlplane.go:1499, 1517, 1610`.
- UT1 startup seeding — `main.go:753-771`.

No "probably". No "looks like". No `VERIFY:` markers.
