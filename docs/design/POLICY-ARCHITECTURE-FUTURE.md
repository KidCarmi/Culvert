# Policy Architecture — Future-Proofing Review

Status: pre-M3 architecture pass. **Nothing here is implemented in M3.**
M3 stays scoped to `M3-POLICY-ARCH-REVIEW.md` (existing backend only); this
document exists so M3's UI decisions cannot block the architecture below.
Date: 2026-07-11. All current-state claims verified against source (cited).

---

## 1. Rule identity

### Current state

- `PolicyRule.ID` **already exists**: a stable ULID, generated on create and
  backfilled on load, explicitly labeled "Phase 0 seam" (`policy.go:112`,
  `:252`, `:367`, `:391`). Edits preserve it even when older clients send no
  `id` (`policy.go:451-454`). Auth rules share the struct/store
  (`ruleType: "auth"`), so they carry ULIDs too.
- **But identity is not load-bearing anywhere.** The API addresses rules by
  mutable `priority` (`POST/DELETE /api/policy?priority=N`); audit entries
  key on mutable `name` (`ui_policy.go:922,971`) or a synthesized
  `priority=N` when the name is empty (`:1010`); request-log entries record
  the matched rule as a **name string** (`ruleMatched`); import cannot match
  rules across instances, so merge-mode import **accumulates duplicates**
  (the UI's own confirm text admits it); deep links are impossible.

### Recommendation — promote the existing ULID to the addressing key

The seam was built for exactly this; the work is adoption, not invention:

1. **API**: handlers accept `?id=<ulid>` alongside `?priority=` for a
   deprecation window; `priority` addressing eventually becomes read-only
   ordering data. (`/api/policy/reorder` keeps priorities — order is what it
   mutates — but should validate against a rule-set generation, see §5.)
2. **Audit**: object key becomes the ULID; the human-readable name moves to
   the detail field. History then survives rename and re-prioritization —
   today renaming a rule orphans its audit trail.
3. **Decision attribution**: the request-log `Entry` gains `ruleId` next to
   `ruleMatched` (names are not guaranteed unique; ID makes "find the rule
   that made this decision" a lookup instead of a string match). This is the
   single highest-leverage change for investigation workflows (§4-B/C).
4. **Import/export**: export already carries `id` (`json:"id,omitempty"`).
   Define semantics explicitly: import upserts by ID when present (idempotent
   re-import, true migration), falls back to name-match once, else creates
   with a fresh ULID. Kills the duplicate-accumulation problem.
5. **UI**: `data-arg` attributes and future deep links (`#/policy/<ulid>`)
   use IDs. **M3 guardrail (allowed now, no backend change): wherever a rule
   object is in hand, prefer `rule.id` in generated markup args and fall back
   to priority — so the M3 rulebase table does not hard-wire more
   priority-addressing that this migration must later undo.**

**Trade-offs**: a dual-addressing window (id + priority) adds handler
branches and test surface; DP `ConfigSnapshot` parity is already satisfied
(the field ships inside the rule structs) but the config-surface walls
(`config_surfaces_test.go`) must be re-run over any new addressing;
`priority` remains the evaluation order — no engine change. Rejected
alternative: name-as-identity (names are user-facing labels; enforcing
uniqueness+immutability would fight operators).

## 2. Rule metadata (createdAt/By, modifiedAt/By, tags, comments, owner)

### Recommendation — adopt in two tiers, after identity, never before

**Tier A (recommended): `createdAt`, `modifiedAt`, `modifiedBy`, `comment`.**
- Stamped **server-side only** (handler layer, same place `auditEventDiff`
  runs) — never client-supplied, or the fields become theater.
- `modifiedAt/By` are a **denormalized cache of audit truth** for list
  rendering; the audit log stays authoritative. Divergence risk is accepted
  and documented (rollback/DP-sync/import set them to the *operation's*
  actor+time, which is honest: rollback *is* a modification by the person
  who rolled back).
- `comment`: single free-text field, shown in the rule drawer and included
  in the audit diff. Cheap, high-value for "why does this rule exist".

**Tier B (defer until a concrete driver): `tags`, `owner`, `createdBy`.**
- `tags []string` is only worth its cost with filtering/bulk UX and (later)
  tag-scoped RBAC ambitions; it must join the `configSurfaces` registry with
  full capture/apply/diff/wire parity (DEBT-006 walls) and import-merge
  semantics — real cost, speculative benefit today.
- `owner` implies lifecycle (owner leaves → orphan review) that Culvert's
  three-role model cannot express yet; without enforcement it decays into a
  stale text field. Revisit with per-object RBAC, not before.
- `createdBy` is fully reconstructable from the audit trail once audit keys
  on ULIDs (§1.2); denormalizing it adds a field that import/migration can
  only fill with lies ("imported-by" ≠ "created-by").

**Cost that applies to every field**: one row in `configSurfaces` + parity
tests, snapshot wire size (×rules ×nodes), export/import semantics, and
rollback behavior (metadata must round-trip through config versions without
being wiped — nil-skip semantics). This is why Tier A is four fields, not
seven.

## 3. Rule relationships & referential integrity

### Current reference graph (all by mutable name, except IdP)

| Edge | Reference key | On referenced-object delete | Failure mode |
|---|---|---|---|
| Rule → CategoryGroup (`destCategoryGroup`) | name | **Blocked** — 409 "referenced by policy rule %q" (`ui_policy.go:518-521`) | safe |
| CategoryGroup → URLCategory | name | **Blocked** — 409 "used by group %q" (`ui_policy.go:641`) | safe |
| Rule → URLCategory (`destCategory`, direct) | name | **Dangles** — UI confirm: "Policy rules referencing it will no longer match" | **fail-open for Deny rules**: traffic the rule blocked flows again |
| Rule → FileProfile (`fileProfile`) | name | **Dangles** — UI confirm: "rules referencing it will no longer filter files" | fail-open for the file-control dimension |
| Auth rule → IdP (`auth.providerRefs`) | **id** ✓ | Dangles; UI renders "(unavailable)" and preserves the ref on edit (pinned by `authpolicy_phase3_slice6` tests) | fail-closed (SSO fails 403) — acceptable |
| Rule → SSL inspection (`sslAction`) | inline enum | n/a | — |
| Scanning pipeline → CDR policies | separate store (`cdrpolicy.go`), not referenced from `PolicyRule` | delete confirm points at config-versions restore | contained |

Three different integrity behaviors for the same class of edge, and the two
dangling cases are **security-relevant fail-open** paths. This is the most
urgent finding in this review.

### Recommendation

1. **One GENERIC dependency-walk endpoint** (small, read-only, in-memory) —
   deliberately NOT rule-shaped, so it can grow into a product-wide
   "Where Used" capability without a redesign:
   `GET /api/objects/references?type=<category|category-group|file-profile|idp|…>&name=…`
   →
   ```json
   {"object": {"type": "file-profile", "name": "Executables"},
    "referencedBy": [
      {"consumerType": "access-rule", "id": "<ulid>", "name": "block-exe",
       "detail": "fileProfile", "view": "policy"}
    ]}
   ```
   `consumerType` is an open enum: the first backend walk emits only
   `access-rule`/`auth-rule`, but the envelope already accommodates future
   consumers (PAC config, alert routes, reports, node-group selectors,
   CDR policies, …) as `{consumerType, id, name, detail, view}` entries.
   The server already walks rule references ad hoc in the two blocked-delete
   paths; this generalizes that walk behind one viewer-readable contract.
   **UI constraint (binding on M3+): every dependency surface renders the
   generic entry shape — a consumer-type badge + name + navigation target —
   never a rules-only table.** The `whereUsed` component contract lives in
   `DESIGN-SYSTEM.md` §3.
2. **Uniform delete policy on top of it**: every shared-object delete either
   (a) blocks with 409 listing referents (extend the existing catgroup
   pattern — preferred for the fail-open edges: direct categories, file
   profiles), or (b) proceeds with an explicit impact dialog enumerating the
   affected rules (acceptable only for fail-closed edges like IdP). The
   danger-tier dialog already has the impact slot; it should show *real*
   referents from (1), not generic copy.
3. **UI dependency surfacing** (needs only endpoint 1): "used by N" chips on
   object rows (count of consumers of ANY type), and the rule drawer lists
   its own outbound dependencies with liveness ("category `gambling` —
   missing ⚠") — the outbound direction is client-computable today and ships
   with M3 S3; the inbound "Where Used" direction waits for the endpoint.
   A full visual dependency *graph* is rejected — at Culvert's object counts
   a referent list answers every real question a graph would, at a fraction
   of the complexity.
4. **Long-term**: when identity work lands, migrate object references from
   name to object IDs (categories/groups/profiles would need their own IDs)
   so rename stops being a silent unlink. That is a bigger migration
   (rename today = new object); sequence it after rule-identity proves the
   pattern.

## 4. Operational workflows (measured on the current UI, post-M1/M2)

Legend: clicks ≈ discrete pointer/keyboard actions excluding free-text
typing; switches = full view/context changes.

| Workflow | Today | Clicks | Switches | Mistake surface | Cognitive-load fix |
|---|---|---|---|---|---|
| **A. Create a rule** (objects exist) | Policies→Access Rules, fill form top-of-view, Add | ~8 | 1 | No client validation (CIDR/glob rejected only on submit); no summary of what the rule will do; priority semantics implicit | M3 S3 (validation + live summary). Future: none needed |
| **A′. Create a rule needing a new category** | …first URL Categories → create → add hosts one-by-one → back → reload dropdown | ~15+ | 3 | Forgetting to return/refresh; adding hosts to the wrong tier | **Future: inline object creation** — "create category…" inside the rule editor's combobox (UI-only, worth an M4 slice) |
| **B. Investigate a block** | Dashboard → Traffic → filter (type) → find row → read truncated `ruleMatched` → Policies → visually locate rule → optionally Policy Tester → **retype** IP/identity/host | 10–14 | 3–4 | Transcription errors re-typing into the tester; ambiguous when two rules share a name; truncated reason | M3 S4 (drawer, rule chip, prefilled tester) cuts to ~4 clicks / 1 switch. **Future: `ruleId` in log entries (§1.3) makes attribution exact** |
| **C. Find the rule behind a decision** | Tail of B — name-string match in the rulebase | — | — | Name collisions; renamed rules unfindable in old logs | Same as B; ID attribution is the real fix |
| **D. Reorder safely** | Drag row (persists instantly) or ⋮ move before/after-named | 2–4 | 0 | Mid-list drop error; no review step; long-distance drag impractical past ~50 rules | M3 S5 (staged Apply/Revert). Future: "move to position N" input + keyboard reorder for large rulebases |
| **E. Clean up unused rules** | Not achievable: only dashboard top-10 hit counts; `HitCount` resets on restart; no last-hit; no unused filter | n/a | n/a | Deleting a rule that IS used but not recently visible | Needs `policy-metadata` backend (persisted counters + lastHit) → then a one-click "unused for 90d" filter |
| **F. Migrate config** | Settings→Export (2 clicks) → target instance → Import (merge) | ~6 | 1 (+instance switch) | **Rule duplicates accumulate on re-import** (no identity matching); webhooks/upstreams intentionally excluded (creds) — operators must know the exclusion list | ID-based upsert import (§1.4). UI: import preview diff ("3 added, 2 updated, 0 duplicates") before commit — needs a dry-run import endpoint (small backend) |

Cross-cutting: the three highest-friction workflows (B, C, F) all bottleneck
on the same root cause — **rule identity is not carried through logs, audit,
and import**. That is why §1 is P0 below.

## 5. Future scalability

| Dimension | Current mechanics | Verdict |
|---|---|---|
| **Engine, 100s–1000s of rules** | First-match linear scan over precomputed matchers (`normFQDN`, `srcIPNet`, `matchedConds` — `policy.go:118-139`), `sync.RWMutex` store, atomic `ReplaceAll` | Fine into the thousands (bench-gated, `policy_bench_test.go`); no action |
| **API payloads** | `GET /api/policy` returns all rules; reorder POSTs the full permutation | ~300 KB at 1 000 rules — acceptable; revisit pagination only with server-side filtering (below) |
| **UI rendering** | `renderPolicy` rebuilds the whole `<tbody>` via innerHTML **on the 3 s tick while the view is open** (`tick()` → `fetchPolicy`), re-initializing drag handlers | **The real ceiling (~200–300 rules before jank).** M3-S2 guardrails, UI-only: render keyed on a content hash (skip identical re-renders), suppress tick refresh while a drag/edit is in progress, and structure the table so row windowing (virtualization) can be added without re-architecture. Do not ship an S2 table that assumes full-DOM residency forever |
| **Rulebase navigation at scale** | No search within the rulebase; drag over long distances | S2 adds the filter input (client-side is fine to low thousands); server-side filter params only if rule counts outgrow that |
| **Shared-object counts** | Admin category/group lists render fully; blocklist already has the pagination pattern to copy | Copy the blocklist pattern when a deployment proves the need |
| **Concurrent administrators** | Last-write-wins on rule create/edit/delete (no If-Match/generation check); reorder alone detects permutation conflicts (409 "concurrent modification?", `ui_policy.go:1232`); audit shows clobbers only after the fact | **Gap.** Recommendation: a rule-set generation counter — mutating calls send `expectedGeneration`, mismatch → 409 with refresh hint (generalizes the reorder precedent). Cheap, and the UI already knows how to render a conflict. Full ETag-per-rule is overkill until proven otherwise |
| **CP→DP fan-out** | Full `ConfigSnapshot` push, epoch-fenced | O(rules×nodes) but snapshots are compact; no action at target scale |
| **History windows** | Config versions capped at 50, audit ring at 500 (file source exists) | At enterprise churn 50 versions ≈ days; make caps configurable when the metadata work lands |
| **Future policy capabilities without UI redesign** | — | The M3 component contracts are the insurance: rulebase table = data-driven columns over `tableRows`; trace viewer keyed on `{priority,name,skipReason}` + future `ruleId`; editor = form-section registry. New rule dimensions (e.g. a future service/port matcher) become a column def + form section + matcher, not a new screen |

## 6. Sequenced recommendations (pre-enterprise-scale program)

| Pri | Item | Class | Depends on |
|---|---|---|---|
| **P0** | Promote rule ULID to addressing key: API `?id=`, audit keys, **`ruleId` in request-log entries**, ID-upsert import | Backend design record `policy-identity` | — (seam exists) |
| **P0** | Close the fail-open integrity holes: block-or-impact on direct-category and file-profile deletes, backed by the references endpoint | Backend `policy-refs` | — |
| **P1** | `GET /api/objects/references` + "used by N rules" UI + real referents in delete dialogs | Backend (small) + UI | P0 refs |
| **P1** | Tier-A metadata (`createdAt`, `modifiedAt/By`, `comment`) + persisted hit counters with `lastHit` → unused-rules workflow | Backend `policy-metadata` | P0 identity |
| **P2** | Rule-set generation counter → optimistic concurrency for multi-admin | Backend (small) | — |
| **P2** | Import dry-run/preview endpoint → migration preview UI | Backend (small) | P0 identity |
| **P3** | Candidate/commit for rule content (G2 from the M3 review) + audit comments on commit | Backend `policy-draft` | P0–P2 (identity, generation, metadata make the diff/commit model tractable) |
| **P3** | Object references by ID (rename-safe), object ULIDs | Backend | P0 pattern proven |
| — | Tier-B metadata (tags/owner/createdBy) | Deferred | concrete driver |
| — | Dependency *graph* visualization | **Rejected** | referent lists suffice |

### M3 guardrails extracted from this review (allowed now — zero backend)

1. S2 table: prefer `rule.id` in generated `data-arg`s (fallback priority);
   content-hash render skip; no full-DOM-residency assumptions.
2. S3 editor: form-section structure that can accept metadata fields later
   without layout redesign; drawer already stack-managed.
3. S4 trace: treat `ruleId` as an optional field from day one.
4. S5 shadow hints: keyed on rule IDs internally so hints survive reorder.
