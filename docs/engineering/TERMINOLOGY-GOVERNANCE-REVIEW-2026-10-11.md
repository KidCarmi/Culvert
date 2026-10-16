# Culvert Language & Terminology Governance Review — 2026-10-11

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope:** HISTORICAL record of `main` at `fbf6a37` (merge of #1592) on 2026-10-11. Every
> citation describes that tree. This report changes no code, copy or API; it records findings only.
>
> **Method / limits (read this):** window `6ec745d..fbf6a37` (the audited end of the 2026-09-24 report →
> now): 77 first-parent merges, 371 files. This window is dominated by admission-engine extraction,
> shutdown/package-isolation ADRs, agent-guidance restructuring, and test files. Rather than read 53k
> inserted lines, the audit swept the **names that reach users or integrators**: added OpenAPI paths and
> `operationId`s, added `culvert_*` metrics, added `auditEvent` actions, added config keys/validators,
> `config_surfaces.go` rows, and GUI strings in `static/index.html` and `frontend/src`. Anything outside
> those surfaces (internal identifiers, comments, test names) was not reviewed. Carried backlog IDs
> were **not** re-verified against `fbf6a37`; their counts are carried, not re-counted.

---

## Executive Summary

Two new drifts found, both small. No Critical or High item.

| ID | Priority | Concept | Drift |
| --- | --- | --- | --- |
| T-64 | Medium | Operation identifier | `opId` / `op_id` / `operation_id` / `operationId` for the same idea, **including two spellings on one resource** |
| T-65 | Low | Config-version rollback | The React auth-rule deletion hint says "restore a config version"; everywhere else says "roll back". (A legacy CDR hint makes the same claim about state that is not versioned at all; see T-65's CDR note.) |

Confirmed consistent in the window (no action): `Rollback` for config versions
(`POST /api/config/versions`, `/api/config/rollback-scope`, GUI "Rollback Configuration", runbooks);
`destination privacy` as the product name for `/api/traffic/redaction` (T-17 canonical path, legacy alias
documented); `backup` / `backup operation` across `/api/backups*`, GUI and audit `backup.trigger`;
`ip_filter_mode` values `allow` / `block` match the IP filter vocabulary.

**Terminology Health Score: 7.7 / 10** — baseline 7.9 (the 2026-09-24 report's comparison figure: its 7.5
plus T-57, T-58, T-17, T-59 fixed), minus 0.1 per newly recorded item (T-64, T-65). Same rule as prior
reports. Carried open backlog: 23 IDs / 22 entries per that comparison row (not re-verified), plus the 2
new IDs → 25 / 24.

---

## Canonical Concepts

| Concept | Canonical name | Prose form | Notes |
| --- | --- | --- | --- |
| Handle for one long-running administrative operation | `operation_id` (snake_case surfaces) / `operationId` (camelCase surfaces) | "operation ID" | Never abbreviate to `op` in a public field |
| Reverting settings to an earlier config version | "roll back" / Rollback | "roll back to config version vN" | Not "restore" — reserved for backup restore |
| Restoring `/data` from an archive | "restore" | "backup restore" | Distinct from rollback; keep the two verbs apart |

---

## Findings

### T-64 — Operation identifier has four spellings (Medium)

- **Business concept:** the opaque ID a caller keeps to poll or reconcile one long-running operation.
- **Canonical name:** `operationId` on camelCase surfaces, `operation_id` on snake_case surfaces and in
  `key=value` audit details, and "operation ID" in prose.
- **Why problematic:** the *same operation* is created with `opId` and polled as `op_id` on the backup
  resource. Supporting staff correlating an audit line (`op_id=`) with an API response (`opId`) have to
  know both names. "op" is an implementation abbreviation, not a business term.
- **Why better:** one noun, "operation ID", on every surface a human or integrator reads, with the
  existing spellings kept as aliases so nothing breaks.

**Complete inventory at `fbf6a37`.** Exhaustive sweep for
`op_?[iI][dD]|opId|operation_?[iI]d|operationId|OpID` over non-test Go (excluding `cmd/`, the
maintenance agent's own module), `api/openapi/openapi.yaml`, `frontend/src` and `static/index.html`.
Hits that are OpenAPI route `operationId:` keys are not this concept and are omitted. No application
log line (`logger.Printf`/`logWarnf`) carries the identifier. Every user- or integrator-visible site:

| # | Site (`fbf6a37`) | Surface | Current key | Planned action |
|---|---|---|---|---|
| 1 | `backups_api.go:345` — `POST /api/backups` (`BackupCreateResult`, `openapi.yaml:1203`) | API response | `opId` | **Dual-emit** `operationId`; keep `opId` permanently |
| 2 | `backups_api.go:447` — `GET /api/backups/operations/{id}` (`BackupOperationStatus`, `openapi.yaml:1212-1215`) | API response (agent record, verbatim) | `op_id` | **Dual-emit** `operationId` beside it; keep `op_id` (it is the agent's record field) |
| 3 | `release_api.go:224` (`dispatchRecord`, served by `GET /api/releases/dispatch/status` at `release_api.go:588`; spec `DispatchStatus`, an open object) | API response | `op_id` | **Dual-emit** `operation_id` (snake surface: `dispatch_id`, `release_id`); keep `op_id`. The store is in memory, so this adds a field and does not change persistence |
| 4 | `release_api.go:711` — `POST /api/releases/dispatch` 202 body | API response | `op_id` | **Dual-emit** `operation_id`; keep `op_id` |
| 5 | `release_api.go:845` — `POST /api/releases/dispatch/resume` 202 body | API response | `op_id` | **Dual-emit** `operation_id`; keep `op_id` |
| 6 | `release_api.go:823` — resume 400 text "resume needs an op_id" | API error text | `op_id` | Reword to "operation ID" (copy only; no field) |
| 7 | `backups_api.go:335` — `backup.trigger` | Audit detail | `op_id=` | **Dual-emit** `operation_id=`; keep `op_id=` |
| 8 | `release_dispatch_service.go:423` — `release.dispatch` | Audit detail | `op_id=` | **Dual-emit** `operation_id=`; keep `op_id=` |
| 9 | `release_dispatch_service.go:438` — `release.dispatch.outcome` | Audit detail | `op_id=` | **Dual-emit** `operation_id=`; keep `op_id=` |
| 10 | `pac_lifecycle_api.go:650,1092,1256` — `pac.*` audit details | Audit detail | `operationId=` | **Exception.** It matches the PAC API's own `operationId` field exactly, so audit-to-API correlation already uses one name. It is also behaviour-bearing: `pac_lifecycle_api.go:1088` finds an already-audited operation by matching `operationId=<id> ` in the ring, and `:1073` keys config versions on `operationId=`. Leave it |
| 11 | `static/index.html:16091-16166` — Backup Now polling | GUI (JS only) | `opId` | Read `operationId`, falling back to `opId`; no visible label |
| 12 | `static/index.html:17679,17741,17783` — release dispatch panel row and toasts | GUI (visible) | `op_id` row label, "op …" toasts | Label "Operation ID"; read `operation_id`, falling back to `op_id` |
| 13 | `frontend/src/api/types.gen.ts:5459,5472` | Generated client types | `opId`, `op_id` | Regenerated from the spec by the contract bump |
| 14 | `decryption_redaction.go:135,379,418` — key rotation request/receipts (`openapi.yaml:1014,1896`) | API request/response | `operation_id` | Canonical; no action |
| 15 | `cdr_ui.go:537`, `cdr_enroll_receipts.go:87,128,558,595`, `cdr_lineage.go:75` — CDR enrollment/receipts (`openapi.yaml:2186-2257`) | API request/response | `operationId` | Canonical; no action |
| 16 | `pac_lifecycle_api.go` responses (`:185,293,535,570,612,651,847,870,910,920,927,1169,1248`; `openapi.yaml:552-561`) | API request/response | `operationId` | Canonical; no action |

Internal, not visible and no action: `backups_api.go:328` and `release_dispatch_exec.go:575,581` read the
maintenance agent's own `op_id` wire field, which belongs to the agent protocol. `decryption_redaction.go:42`
stores the receipt as `op_id` on disk and renders it as `operation_id` (row 14). Also internal are the Go
error strings at `release_dispatch_exec.go:338` and `release_dispatch_service.go:317`, and the route note
at `ui_routes_meta.go:810`.

- **Compatibility:** every change in the table is additive. No existing key is renamed or removed in
  an API response or an audit detail. `opId` may be marked `deprecated: true` with the metadata
  `docs/api/API-DEPRECATION-POLICY.md` requires, but *removing* it, or any `op_id`, is a breaking change
  under `API-VERSIONING-POLICY.md` and would need the MAJOR exception process. This report does not
  recommend removal. The bundled GUI is the only *known* consumer, but that does not make the fields
  private. The audit aliases stay because SIEM parsers may key on `op_id=`. Existing tests match
  `op_id=` substrings (`release_dispatch_service_test.go`), so they keep passing. New assertions should
  pin the canonical keys. Record the new keys in the CHANGELOG.
- **Contract version:** new optional response fields (rows 1-5) are a **MINOR** contract change
  (`docs/api/API-VERSIONING-POLICY.md`, SemVer rules). The change must bump both `info.version` and
  `x-culvert-api-contract-version` in `api/openapi/openapi.yaml` (2.1.0 → 2.2.0 at the time of writing).
  It must document the new fields on `BackupCreateResult` and `BackupOperationStatus`, and add
  `operation_id` (with the `op_id` alias) to `DispatchStatus` and the two dispatch 202 bodies, which are
  undocumented open objects today. It must also regenerate the committed contract artifacts (`make
  api-bundle`: `openapi.json`, the HTML docs, `docs/api/API-INVENTORY.md`; and the frontend
  `types.gen.ts`, row 13), then pass `make api-verify` and `make api-breaking-check`.
- **Migration complexity:** Low. **Compatibility risk:** None for the recommended change. Removing any
  alias later would be breaking (MAJOR).
- **Estimated PR size:** M (~130 lines): five response sites (rows 1-5), one error string (row 6), three
  audit details (rows 7-9), two GUI reads and one label (rows 11-12), the spec additions and the
  contract and audit tests. Add the version bump and the regenerated artifacts on top.

### T-65 — "restore a config version" vs "roll back" (Low)

- **Business concept:** reverting configuration to an earlier version.
- **Current names:** "restore a config version" (`frontend/src/features/policy/AuthRulesPage.tsx:738`,
  auth-rule deletion rollback hint; auth rules are policy rules, which are on the rollback surface,
  `config_surfaces.go` `policy_rules` `Rollback: true`); "roll back" / "Rollback" everywhere else (`static/index.html:2648,8388`,
  `docs/enterprise/POLICY-ROLLOUT-GUIDE.md:49`, `OPERATIONS-RUNBOOK.md:43`, `diagnostics.go:1701`).
- **Recommended canonical name:** "roll back to a config version".
- **Why problematic:** "restore" is the backup/DR verb (`/data` restore). An operator reading
  "restore a config version" on a deletion dialog may look in the backup area instead of Config Versions.
- **Why better:** one verb per action; rollback keeps its meaning of "revert settings in a snapshot".
- **Affected code/GUI:** the JSX string (it predates the window — #1265 — but was not charged by an
  earlier report). (`static/index.html:8384`'s "not restored by rollback" describes rollback's effect and
  does not name the action; it is not part of T-65.) **API / docs / config:** none.
- **Migration complexity:** Trivial. **Compatibility risk:** None, unless a test pins the string (check
  `frontend/src/test` before editing). **Estimated PR size:** XS (1 line).
- **CDR note (same verb, different defect; not a rename).** The legacy GUI's CDR rule-deletion
  confirmation (`static/index.html:11971`) says the deletion can be undone "via Config Versions". That
  claim is false, not just mis-worded: CDR policies (`cdr_policies.json`) are per-CP local state that
  configuration versioning never captures or restores (`cdr_ui.go` header, `config_surfaces.go`
  `offRegistryRollbackExclusions` `cdr_policies`, `cdr_hygiene_no_versioning_test.go`). Rewording it to
  "roll back to a config version" would keep the false recovery path. The fix is to remove the
  Config Versions claim (for example, "This cannot be undone; re-create the rule to restore it"). This
  is a correctness fix to copy, sized XS, and is listed separately in the plan below.

---

## Legacy Terminology / Conflicting / Ambiguous

No new entries. Carried (not re-verified): the 2026-09-24 report's backlog, notably T-11
(`default_action` allow/deny vs policy action names), T-12 (`/v1/upgrades/apply`), T-29/T-30
(`security.rate_limit` / `security.max_conns_per_ip` vs GUI wording), T-54 (OCSP metric naming).

## Migration Risk

Only T-64 touches a wire contract, and only additively (a new field on five API responses and a new key in three audit details; nothing renamed or removed). That is a MINOR API contract bump, not a no-version change. T-65 is copy.

## Recommended Refactoring Plan (by priority)

| Priority | Item | Action |
| --- | --- | --- |
| Critical | — | none |
| High | — | none |
| Medium | T-64 | Implement the T-64 inventory table: dual-emit `operationId`/`operation_id` beside the retained aliases on the five API responses (backup create and poll; release dispatch status, dispatch and resume) and the three `op_id=` audit details; reword the resume error text; GUI reads with fallback and the release panel label; keep the `pac.*` `operationId=` audit key as recorded; MINOR contract bump (`info.version` + `x-culvert-api-contract-version`) with regenerated artifacts (`make api-bundle`, `types.gen.ts`, `make api-verify`, `make api-breaking-check`); CHANGELOG entry for the new keys |
| Low | T-65 | Reword the React hint (`AuthRulesPage.tsx:738`) to "roll back to a config version" |
| Low | T-65 CDR note | Remove the false "restore via Config Versions" recovery claim from the legacy CDR deletion dialog (`static/index.html:11971`); CDR policies are not versioned |

## Stop-condition assessment

The "no improvements identified" stop condition does **not** apply: T-64 is a real same-resource
inconsistency introduced in the window. Everything else swept is consistent.
