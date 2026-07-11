# policy-refs — generic object references + fail-open delete closure (P0)

Status: design + slice 1 implementation
Date: 2026-07-11
Authority: `docs/design/POLICY-ARCHITECTURE-FUTURE.md` §3 (the most urgent
finding in the M3 policy-architecture review) and §6 P0 row
"Close the fail-open integrity holes … backed by the references endpoint".

## Problem

Deleting a shared object that a policy rule still references has **three
different behaviors** today, two of which are security-relevant fail-open:

| Edge | Today | Blast radius |
|---|---|---|
| CategoryGroup → URLCategory | 409 blocked (`apiURLCat` DELETE) | safe |
| Rule → CategoryGroup (`destCategoryGroup`) | 409 blocked (`apiCategoryGroups` DELETE) | safe |
| **Rule → URLCategory (`destCategory`, direct)** | **dangles** — delete succeeds, rule silently stops matching | **fail-open**: a Deny rule scoped to that category stops blocking; traffic it denied flows again |
| **Rule → FileProfile (`fileProfile`)** | **dangles** — delete succeeds | **fail-open** for the file-control dimension |
| Auth rule → IdP (`auth.providerRefs`) | dangles, but SSO fails 403 | fail-closed — acceptable |

The category-group delete already walks `policyStore.List()` ad hoc. This
plan generalizes that walk behind ONE read-only contract and applies a
uniform block-on-referenced policy to the two fail-open edges.

## Contract: `GET /api/objects/references`

Viewer-readable, side-effect-free, in-memory. Deliberately **not
rule-shaped** — the envelope is the product-wide "Where Used" seam the M3
`whereUsed` UI contract (`DESIGN-SYSTEM.md` §3) already anticipates.

```
GET /api/objects/references?type=<category|category-group|file-profile|idp>&name=<objectName>
→ 200
{
  "object": {"type": "file-profile", "name": "Executables"},
  "referencedBy": [
    {"consumerType": "access-rule", "id": "<ulid>", "name": "block-exe",
     "detail": "fileProfile", "view": "policy"},
    {"consumerType": "auth-rule", "id": "<ulid>", "name": "exempt-lab",
     "detail": "destCategoryGroup", "view": "authpolicy"}
  ]
}
```

- `type` is an open enum; unknown types return `400`. `name` required.
- `consumerType` is an open enum — the first walk emits only
  `access-rule` / `auth-rule`, but the shape accommodates future consumers
  (PAC, alert routes, node-group selectors, CDR policies) without a schema
  change. Components switch on nothing.
- `id` is the rule ULID (already backfilled on load — `policy.go` ID seam);
  `detail` names the referencing field; `view` is the SPA view that edits
  the consumer. Empty `referencedBy` ⇒ "Not referenced by anything".
- The walk covers every `PolicyRule` field that points at the object type:
  `category` → `DestCategory`; `category-group` → `DestCategoryGroup`;
  `file-profile` → `FileProfile` (matched case-insensitively by name, the
  reference form rules use today); `idp` → `Auth.ProviderRefs` for auth
  rules. Case-insensitive to match the engine's matching.

## Uniform delete policy (slice 1)

Every shared-object delete either blocks (409, listing referents) or
proceeds with an explicit impact dialog. For the two fail-open edges we
choose **block** (preferred for fail-open per the review):

- `apiURLCat` DELETE: before `catStore.Delete`, in addition to the existing
  category-group check, reject if `objectReferences("category", name)` is
  non-empty — 409 naming the first referent + total count.
- `apiFileblockProfiles` DELETE: the handler takes an `id`; resolve the
  profile name, then reject if `objectReferences("file-profile", name)` is
  non-empty.

Both reuse the shared `objectReferences` walk that backs the endpoint, so
the block reason and the endpoint can never disagree (single source of
truth — the class of drift the config-surface registry exists to prevent).

The category-group delete keeps its inline 409 (already safe) but is
migrated onto `objectReferences("category-group", name)` for the same
single-source guarantee.

## Non-goals (later slices)

- **ULID as the addressing key** (`?id=` on rule mutations, `ruleId` in
  request-log entries, ID-upsert import) — the `policy-identity` P0 slice.
  This plan only READS the existing ID seam for the reference envelope.
- **UI "used by N" chips + real referents in delete dialogs** — the P1 UI
  slice, built on this endpoint. Slice 1 is backend + the fail-open close;
  the danger dialog's real-referent wiring rides the UI slice.
- **Tier-A metadata** (`createdAt`, `modifiedAt/By`, persisted counters +
  `lastHit`) — the `policy-metadata` P1 slice.

## Tests

- `policy_refs_test.go`: the walk (each object type → correct referents;
  case-insensitivity; auth vs access `consumerType`; empty result), the
  endpoint (RBAC viewer, bad type 400, missing name 400, shape), and the
  two newly-blocked deletes (409 + referent naming; delete succeeds once
  the last referent is repointed).
- The uiRoutes C1 parity entry for the new route.

## Sequencing

1. **This slice** — endpoint + fail-open close (security fix).
2. `policy-identity` — ULID promotion across logs/audit/import.
3. P1 UI — Where-Used chips + real delete-impact referents.
4. `policy-metadata` — persisted counters, lastHit, unused-rules workflow.
