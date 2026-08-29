# Object References by ID (rename-safe rule → object links)

Status: **IMPLEMENTED for both in-scope object kinds.** S1 (decryption
profiles) and S2 (category groups) are shipped: `PolicyRule` carries the
authoritative `DecryptionProfileID` / `DestCategoryGroupID` link IDs, the
match paths resolve ID-first with name fallback for un-migrated/dangling
references only, rename cascades onto running rules AND the open draft
candidate, and the delete-block walk is ID-first. The 2D-A checkpoint
(§13 below) added the durable object-mutation contract, the rename recovery
model, per-store optimistic-concurrency fencing, and the draft-aware
reference walk. The historical design sections below are preserved as
written (decisions recorded 2026-07-13); §13 records what the
implementation guarantees today.

Date: 2026-07-13 (design). Implementation checkpoint recorded 2026-08-28
(Batch 2 Slice 2D-A).

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

## 13. 2D-A implementation checkpoint (2026-08-28)

Recorded as-built for the frontend-modernization Slice 2D-A backend
hardening; this section is the current contract.

### ID-authoritative reference model (shipped, unchanged by 2D-A)

The rule → object link is the stable object ID; the rule-side name is a
denormalized display/export cache the SERVER keeps honest (rename cascade +
the reconciliation below). The browser never chooses or submits object-link
IDs — `stampObjectRefIDs` derives them server-side from the submitted name.
A resolved ID is final on every consumer path (match, fail-open scope,
delete-block): the stale name is never consulted, so a rename can never make
a rule follow a DIFFERENT object. Name fallback exists only for un-migrated
rules and dangling IDs.

### Durable object mutation contract (2D-A.0a)

Both object stores (`internal/catgroup`, `internal/decryptprofile`) carry an
error-returning persistence core (`SaveErr`) and a serialized
durable-mutation primitive (`MutateDurable`): the optional expected-version
fence, the mutation, the persist, and the failure rollback form ONE critical
section. A confirmed 2xx on `/api/category-groups` and
`/api/decryption-profiles` means the mutation is restart-durable; a
pre-replacement persist failure restores the in-memory objects AND the
generation and returns 500 (nothing durable changed); `ErrReplacedNotSynced`
follows the repository's landed-content doctrine (the renamed file already
carries the new objects — memory kept, success reported). `fn` itself is
atomic-or-nothing: a composed content+rename that fails partway (e.g. a
rename collision after the content applied) restores the pre-mutation state.
Legacy best-effort `Save()` wrappers remain for old non-critical callers
(bulk installs, load-time migrations).

### Object concurrency fencing (2D-A.0c, corrected — durable epoch envelope)

Each store carries a durable per-store mutation generation (the fence
epoch), bumped on every successful mutation and on bulk installs
(`ReplaceAll`). Content and epoch are persisted in ONE atomic write — the
`storeEnvelope` (`{schema_version, version, groups|profiles}`) — so they are
structurally incapable of diverging: an acknowledged content change (a real
success, or the landed-content `ErrReplacedNotSynced` success) always lands
WITH its epoch, and after restart no token issued for an earlier content
epoch can validate again (no ABA generation alias, including the token-0
case where a fresh store legitimately serves version 0). The retired
`<store>.meta` sidecar is READ only when loading a legacy bare-array file
(first non-whitespace byte `[`) and is removed by the first durable envelope
save; it is never written again.

The `schema_version` discriminator is LOAD-BEARING (fail-closed format
validation): for non-legacy-array input, exactly `schema_version: 1` is
accepted — a missing/zero discriminator (`{}` included), a negative value,
an unknown/future schema version, or a negative persisted fence generation
is refused with an explicit load error. A future envelope is never silently
parsed with today's struct. A legitimate empty schema-1 envelope stays
valid.

**Recorded downgrade residual (explicit — not backward-readable):** a
pre-envelope binary cannot parse the envelope — its load errors to an EMPTY
store, and ID-authoritative references degrade fail-closed (never resolve
to a different object). Software-release rollback compatibility across this
format boundary is a lifecycle/release-design responsibility to settle
before GA; this correction deliberately does not pretend the envelope is
backward-readable.

**Durable-publication ordering (`saveMu`, PolicyStore.saveMu's sibling):**
`SaveErr` runs its ENTIRE body — snapshot → marshal → AtomicWrite — under a
store-local publication serializer, so publications form one monotonic
order and each writes the state CURRENT at its own snapshot. Without it, an
older `Save` (the production `ReplaceAll(...)` + `Save()` bulk shape) could
snapshot S1, pause, lose the race to a `MutateDurable` that persisted S2
and returned a confirmed 2xx, then resume and rename its stale S1 envelope
over S2 — destroying an acknowledged mutation on disk. Locking only the
write (after the snapshot) would NOT restore the invariant. Every runtime
persistence path routes through `SaveErr` (`Save` is a thin wrapper):
hardened admin mutations, caller-side `Save` after cluster `ReplaceAll`,
config import/rollback, rename-cascade persistence, the startup seed, and
`Load`'s migration save — no raw path sits outside the ordering domain.

**Commit boundary (`SaveErr` enters `mutMu`):** publication ordering alone
does not stop an external save from OBSERVING an in-flight transaction — a
standalone `Save` running while a `MutateDurable` fn had mutated memory but
not yet returned could snapshot uncommitted-new-content + old-epoch and
publish it; if that mutation then failed its own publication and rolled
back, the failed, unacknowledged mutation stayed on disk. Public
`Save`/`SaveErr` therefore acquire `mutMu` FIRST and delegate to the
internal `saveErrLocked` helper (saveMu → snapshot → marshal →
AtomicWrite); `MutateDurable`, which already holds `mutMu` for the whole
transaction, calls `saveErrLocked` directly — `mutMu` is not reentrant, so
an internal public-`SaveErr` call from the mutation path is forbidden. No
external persistence path can publish an unfinished mutation's memory:
before success nothing publishes the intermediate state; after a confirmed
pre-replacement failure both memory and a fresh reload equal the
pre-mutation truth. The bulk caller's `ReplaceAll(...)` + `Save()` shape
stays valid: `Save` reacquires the domain and publishes the CURRENT
committed state (serial order, which may be newer than the bulk install —
that is the invariant, not a loss).

LOCK ORDER (acyclic, documented on the field): `mutMu` → `saveMu` → `mu`.
Every runtime persistence entry goes through `mutMu` first; internal
helpers called with `mutMu` held never reacquire it; nothing takes `mu`
then `saveMu` or `mutMu`, nothing takes `saveMu` then `mutMu`.

The generation is served on the list read (`version`) and asserted via the
optional `?ifVersion=` query on POST/PUT/DELETE; a mismatch is the SAME
structured 409 as the policy rulebase fence ({error, currentVersion,
yourVersion}). The check runs inside `MutateDurable`'s critical section — no
TOCTOU between check and write. The v2 frontend always asserts it; legacy
clients without it keep last-write-wins semantics.

Every RUNTIME writer of the fenced domain orders against the fence:
`ReplaceAll` (cluster snapshot apply, config import, version rollback,
restore) holds the SAME mutation serializer (`mutMu`) as `MutateDurable`, so
a bulk install can never interleave between the fence comparison and the
protected mutation, and each ordered change advances the generation on the
LIVE value (`version++`, never `captured + 1` — a concurrent advance is
never rewound into an alias). Startup-only writers (`Load`, the default
decryption-profile seed) run before any listener and are exempt by
ordering.

### Rename recovery model (2D-A.0b)

Rename is a composed cross-store operation with NO multi-file atomicity
pretense. Ordered durable phases:

1. **Object store** — content update + rename under `MutateDurable`
   (durable-or-nothing; a failure here changes nothing anywhere).
2. **Running policy cascade** — `CascadeDestCategoryGroupRename` /
   `CascadeDecryptionProfileRename` + an error-aware `SaveErr`.
3. **Draft candidate cascade** — under the draft coordinator's lock via
   `persistLocked`, error-returned.

A cascade persist failure AFTER the durable object rename keeps the correct
in-memory cascade, returns a truthful 500 naming the failed domain (never a
2xx with a known-failed durable domain), and audits the partial state.

Crash points and recovery (deterministic, ID-authoritative):

| Crash after…                | Disk state                                   | Recovery |
|-----------------------------|----------------------------------------------|----------|
| nothing persisted           | all-old (consistent pre-rename)              | none needed |
| object store persisted      | object new; rule names stale (IDs intact)    | boot reconciliation refreshes names |
| + running cascade persisted | draft candidate names stale (IDs intact)     | boot reconciliation refreshes the candidate |
| everything persisted        | consistent                                   | none needed |

**Enforcement is correct at every crash point** — rules reference the stable
object ID throughout; any disagreement is display/export-only.
`reconcileObjectRefNames()` (startup, after policy + draft + object stores
load) re-derives stale denormalized names from the ID-authoritative object
stores and persists only when something changed; a dangling ID is left
untouched (its stale name is the documented name-fallback matching input). A
refresh that touches running rules advances the running generation — an
active draft then truthfully reads base-stale (after a crashed rename the
operator should re-review before committing).

Draft interaction: a rename whose cascade touches RUNNING rules advances the
running generation, so an active draft's base goes stale and commit is
fenced until review (the deliberate 2B/2C fence behavior — rendered as
truth, not suppressed). A rename referenced ONLY by the draft candidate
moves nothing on running: the candidate follows (same ID, new name) and the
draft commits cleanly to the same object.

### Draft-aware reference walk (2D-A.0b)

`objectReferences` walks RUNNING rules and, when a Policy Draft is active,
the CANDIDATE too: a staged rule referencing an object blocks its delete and
appears in Where Used (annotated "(draft candidate)"; a staged copy of a
running rule dedups by its stable ULID). The endpoint and the delete guard
still share the single walk, so they can never disagree.

Proofs: `internal/catgroup/catgroup_durable_test.go`,
`internal/decryptprofile/decryptprofile_durable_test.go`,
root `object_durability_test.go` (fault injection at every phase +
disk-reload oracles + the full §27 reference-integrity matrix),
`objects_enum_lockstep_test.go` (frontend/runtime enum lockstep).

## 14. 2D-C implementation checkpoint (2026-08-29) — File Profiles + Header Rewrite

### File Profile references (ID-authoritative, STRICT dangling semantics)

`PolicyRule.FileProfileID` (JSON `fileProfileId,omitempty`) joined the
reference model with the same trust boundary as groups/decryption profiles:
the NAME is the client's intent, `stampObjectRefIDs` derives the ID
server-side, and a client-supplied ID is never trusted (a mismatched pair
binds to the name).

**Deliberate divergence from §6:** for file profiles, a rule carrying a
non-empty authoritative `FileProfileID` whose object no longer resolves does
NOT fall back to name matching — in enforcement (`FileProfileBlocked`
returns false: fail-safe, nothing is retargeted to a same-named object) and
in the reference walk (`ruleReferencesObject` reports no reference for a
non-matching ID-bearing rule), so the walk and the match can never disagree.
The group/decrypt-profile name fallback exists to serve pre-promotion rules;
the file-profile space additionally contains COMPILED-IN legacy built-in
names (`fileProfileExts`), where a name fallback would let a deleted
profile's rule silently rebind to the compiled set — the §7 anti-rebinding
rule ("do not retarget an authoritative ID by name") therefore wins over
walk symmetry with the older kinds. ID-LESS rules keep the full legacy
resolution (store name → compiled map) byte-identically.

Rename follows §7: `CascadeFileProfileRename` refreshes the denormalized
name on running rules (by ID; by name for ID-less rules, stamping the ID as
a side effect) and on an active draft candidate
(`policyDraft.cascadeFileProfileRename`), with the truthful-500 persist
contract; `reconcileObjectRefNames` converges names at boot via the 3-map
`RefreshObjectRefNames`.

Store contract: `internal/fileblock` carries the 2D-A-class durability
(copy-on-write immutable publication, persist-target-then-swap
`commitLocked`, `ErrReplacedNotSynced` landed-content doctrine) with a
CONTENT-DERIVED restart-stable revision (`fpv1`) as the fence —
`SnapshotWithRevision` under one lock, `CreateFenced`/`UpdateFenced`/
`DeleteFenced` comparing `ifRevision` inside the critical section, and
`ReplaceAll` documented as the CP→DP follower path only. Bulk validation
(`CheckRuleFileProfiles`) matches enforcement exactly: ID-bearing rules
resolve only within the candidate ID set. File profiles remain OFF the
export/import/rollback surfaces (ConfigSnapshot-only per the Finding 10.3
registry), so import/rollback candidates judge against the live store.

Built-ins (deterministic `builtin-*` IDs) remain fully editable/renamable/
deletable — the pre-slice product behavior, preserved (§14 of the 2D-C
directive) and made safe by ID promotion.

### Header Rewrite identity (stableId; NOT a rule→object reference)

Rewrite rules are not referenced by policy rules — the identity work is
about the OBJECTS themselves. The legacy integer `Rule.ID` is process-local
(reassigned by `SetRules`) and is NOT product identity: no deep links, no
fencing, never reinterpreted as the stable ID. `StableID` (server-owned
UUID, `yaml:"-"`) is the durable identity: backfilled once at load,
persisted through the AdminSettings owner (`RewriteRules` +
`RewriteRulesSaved` sentinel), preserved verbatim by rollback and CP→DP
sync (a restored version never mints fresh identities), minted fresh for
interactive creates and ID-less import entries, and duplicate stableIds
reject the whole candidate at every bulk door. Evaluation ORDER is
semantics and is preserved verbatim on every surface; the content revision
(`rwv1`) covers identity + position + host + all operations.

Proofs: `dc_identity_test.go`, `dc_identity_red_test.go` (red-before at the
2D-B frozen checkpoint), `internal/fileblock` + `internal/rewrite` suites,
`bulk_ref_integrity`/`bulk_canonical_authority` extensions.
