# Object References by ID (rename-safe rule → object links)

Status: **design record, pre-implementation.** Authority for the final P3
`references-by-id` item in `POLICY-ARCHITECTURE-FUTURE.md` §6 ("Object references
by ID (rename-safe), object ULIDs"). Nothing here is implemented yet.

Date: 2026-07-13.

---

## 1. Problem

Policy rules link to two admin-defined objects **by mutable name**:

- `PolicyRule.DecryptionProfile` → a `DecryptionProfile` name (SSL-inspect only).
- `PolicyRule.DestCategoryGroup` → a `CategoryGroup` name.

Both objects already carry stable ULIDs (decryption profiles, PR #706; category
groups, PR #705), but the link is the name, and **names are immutable — there is
no rename anywhere** (`UpdateByID` on both stores deliberately preserves the
name). So renaming is simply not offered: if it were, every referencing rule
would silently break (a dangling ref falls back to the inline defaults, i.e.
fail-safe but wrong-intent).

This migration makes the rule → object link **ID-authoritative** and, on top of
that stable link, **enables rename** for those two object types — the referencing
rules follow automatically. That is the user-visible payoff (product decision
2026-07-13: "ID plumbing + enable rename").

## 2. Scope

**In scope:** `rule → decryption-profile` and `rule → category-group`. Both are
admin-defined, already ULID-bearing, and resolved through a single seam.

**Explicitly OUT of scope — URL categories stay name-referenced** (product
decision 2026-07-13). A category's NAME is a load-bearing external join key:
- the community threat feed (`communityDB.Lookup`) returns category-NAME strings,
  and `matchCategory` compares the rule's category name against them (policy.go);
- category-group membership stores member category **names** (`catgroup.Group.Categories []string`).
ID-migrating categories would decouple them from the feed and from group
membership, and categories don't have ULIDs today. So `rule.DestCategory` and
group→member links remain by name; this is a recorded constraint, not an
oversight. (Category *rename* is therefore also out of scope.)

## 3. Model — ID-authoritative link + denormalized name cache

Each migrated reference becomes a pair on `PolicyRule`:

```go
DecryptionProfile   string `json:"decryptionProfile,omitempty"`   // denormalized display name (kept honest by cascade)
DecryptionProfileID string `json:"decryptionProfileId,omitempty"` // AUTHORITATIVE link (ULID)

DestCategoryGroup   string `json:"destCategoryGroup"`             // denormalized display name
DestCategoryGroupID string `json:"destCategoryGroupId,omitempty"` // AUTHORITATIVE link (ULID)
```

- **Authoritative = ID.** Matching resolves the object by ID; the name is a
  human-readable cache.
- **Name kept honest by cascade** (not resolve-at-read): on rename we update the
  denormalized name on every referencing rule via a precise ID lookup, so
  display, export, config-version rollback, and DP sync all stay truthful with
  ZERO per-read/per-match overhead. Matching-by-ID is the robustness guarantee
  (survives even a partial cascade); the cascade is the display-freshness
  guarantee. The two cover different concerns and are each cheap.

Both ID fields are `omitempty` so pre-migration rules and the many tests that
build `PolicyRule` literally are byte-unchanged.

## 4. Backfill

On `PolicyStore.Load`/`ReplaceAll`, for a rule that has a name but no ID, resolve
name → current object ID and set it (persist when migrated), mirroring the
existing rule-ULID and object-ULID one-time migrations. A name that does not
resolve (dangling) leaves the ID empty — same fail-safe as today.

## 5. Write path

The rule create/update handlers already receive the name (the editor sends it).
After validation, resolve name → ID via the object store and stamp BOTH fields
(`stampObjectRefsForWrite`). An unresolvable name leaves the ID empty (dangling,
fail-safe). This is server-side only — the client keeps sending names; the ID is
derived, never trusted from the client (a client-supplied ID would let a rule
point at an object the operator didn't pick).

## 6. Match path (ID-first, name fallback)

Single seam per object — no new hot-path work, just a keyed-lookup swap:

- **Decryption profile** (`decryptprofile_resolve.go::resolveDecryptionProfile`,
  per-CONNECT, SSL-inspect only): try `GetByID(rule.DecryptionProfileID)` first,
  fall back to `GetByName(rule.DecryptionProfile)` when the ID is empty
  (un-migrated / dangling). The **`FailOpenScope` wrinkle** (`proxy.go:637`): it
  keys the autoexclude scope by profile name today; it must resolve through the
  same ID-first seam so the scope identity tracks the profile across a rename.
  Add `FailOpenScopeByID` (or route both through a shared resolver that returns
  the scope identity from the resolved profile).
- **Category group** (`categorygroup.go::categoryGroupMatchesHost`, per-request
  when a rule sets a group): resolve the group by ID first (→ its `catSet`), fall
  back to by-name.

Fallback preserves byte-identical behavior for un-migrated rules and dangling
refs.

## 7. Rename (the payoff)

A new rename capability on each object store + handler:

- **Store**: a `Rename(id, newName)` (or relax `UpdateByID` to accept a name
  change) with the usual name-uniqueness validation.
- **Handler cascade** (main package, where both stores are visible — the
  `internal/` object stores cannot import `policyStore`): after renaming the
  object, `cascadeObjectRefName(kind, id, newName)` walks `policyStore` and
  rewrites the denormalized name field on every rule whose `…ID` matches.
- **The cascade MUST persist the policy store.** Rewriting `PolicyRule` fields is
  a policy-store mutation, so the handler must call `policyStore.Save()` (the
  same durability the normal policy-write path gives via `afterPolicyWrite`)
  BEFORE `saveConfigVersion`. Otherwise, if the process restarts after a rename
  but before any later policy edit, the denormalized rule names reload STALE from
  the policy file — the config-version history would have the new name but the
  live rulebase (UI/export/DP snapshot) would not (Codex design review). Order:
  rename object → object-store Save → cascade rule names → `policyStore.Save()` →
  `saveConfigVersion`. DP sync then ships both the renamed object and the updated
  rules in the next `ConfigSnapshot`.
- **Referential integrity unchanged**: delete is still blocked by the
  `objectReferences` walk. Rename is now the safe alternative to
  delete-and-recreate.

## 8. Config surface / cluster

- Adding fields to `PolicyRule` does **not** add `configSurfaces` rows — the whole
  rule struct ships under the single `policy_rules` row (export/import, rollback,
  `ConfigSnapshot` DP sync all carry the new fields automatically). Re-run
  `config_surfaces_test.go` to confirm no parity drift.
- **Cross-node ID consistency**: category groups and decryption profiles are
  synced CP→DP *with* their ULIDs (they're in `ConfigSnapshot`), so a rule's
  `…ID` resolves against the same object IDs on every node. (This is why the
  migration is safe for these two objects but was deferred for rules themselves,
  whose IDs were historically node-local.)
- `policy_refs.go` (`objectReferences`) MUST check the object **ID first**, with
  name correlation kept only as the legacy fallback for un-migrated rules.
  ID-first is required, not optional (Codex design review): a rule can carry the
  object's `…ID` while its denormalized name is momentarily stale (e.g. a
  partial/interrupted cascade), and a name-only delete-block would then fail to
  find it — letting the UI delete an object that is still referenced by ID and
  turning the rule into a dangling reference. Since the ID link is what the match
  path honors, the delete-block must honor it too, or the two disagree.

## 9. UI

- The rule editor's decryption-profile and category-group selectors keep showing
  names but submit as today; the server derives the ID. On load/edit, the editor
  captures the rule's stored name (fresh via the cascade).
- Each object's management panel (Decryption Profiles, Category Groups) gains a
  **Rename** action (inline edit of the name), with a note that referencing rules
  follow automatically. Typed-confirm not required (rename is now safe).

## 10. Test plan

- Backfill: a rule with a name and no ID gets the current object ID on load
  (persisted).
- Write: creating/updating a rule stamps the ID from the name; an unknown name
  leaves the ID empty.
- Match-by-id: a rule resolves its profile/group by ID; renaming the object does
  NOT change the match (ID stable). Un-migrated (name-only) rule still matches by
  name. `FailOpenScope` tracks the profile across rename.
- Rename cascade: renaming a profile/group updates every referencing rule's
  denormalized name; one config version; export/rollback show the new name.
- Dangling: a rule whose object was deleted out-of-band falls back to inline
  defaults (unchanged fail-safe).
- Config-surface parity + a full policy/cluster regression.

## 11. Slicing

- **S1 — decryption-profile references-by-id + rename.** Schema (`DecryptionProfileID`),
  backfill, write-path stamp, `resolveDecryptionProfile` + `FailOpenScope`
  ID-first, store `Rename` + handler cascade, UI rename, tests. Self-contained
  and the cleanest (single-object resolution, no membership chain).
- **S2 — category-group references-by-id + rename (SHIPPED).** Same pattern:
  `DestCategoryGroupID` schema, `categoryGroupMatchesHostRule` ID-first match
  (`Store.MatchesCategoryByID` returns `(matched, resolved)` so a resolved group's
  membership is authoritative and the stale name is never consulted), write-path
  stamp, `Store.Rename` (re-keys name map + order), `PolicyStore.CascadeDestCategoryGroupRename`
  (hit-preserving pointer swap), draft-candidate cascade, ID-first delete-block,
  and the handler rename flow (collision pre-check → 409, UpdateByID-before-Rename
  so a bad body can't leave a half-applied rename), UI rename for ID-bearing groups.
  (Group→member category links stay by name — §2.)

Each slice is an independent, reviewable PR that leaves the tree green and the
feature off-nobody's-path until its own match/rename wiring lands.

## 12. Rejected alternatives

- **Name-cascade rename without rule IDs** (rename = rewrite all referencing
  names, no ID link): simpler, no schema change, but a crash mid-cascade dangles
  references — exactly the fragility IDs remove. The product decision is
  references-by-id, so the link is the ID.
- **Resolve-at-read for the display name** (no cascade): avoids the cross-store
  cascade but adds per-read/per-export ID→name resolution and risks stale
  export/rollback snapshots. Cascade-on-rename keeps the denormalized copy honest
  once, at rename time.
- **Migrating URL categories** — §2 (feed + membership name-coupling; out of scope).
