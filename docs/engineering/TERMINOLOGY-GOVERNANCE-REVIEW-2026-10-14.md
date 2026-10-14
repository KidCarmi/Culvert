# Culvert Language & Terminology Governance Review — 2026-10-14

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope:** `origin/main` at `77c0c58`. Window: `6ec745d..77c0c58` (78 first-parent merges,
> 375 files), i.e. everything after the 2026-09-24 report's audited snapshot. This report changes no
> code, copy, API or config; it records one new finding and defers all carried IDs to the reports that
> own them.
> **Method:** diffed the user-visible name surfaces over the window — OpenAPI paths/fields, `config.go`
> keys, Prometheus series, `auditEvent` actions, GUI copy — and compared against the open backlog.
> Carried IDs (T-9 … T-63) were not re-verified except where the window touched them.

## Executive Summary

The window is large (53 k insertions) but almost entirely CI, admission-engine package isolation,
agent-context docs and tests. The admin-visible surface that changed is small:

| Surface | Added in window | Terminology verdict |
| --- | --- | --- |
| REST paths | `/api/traffic/redaction` (T-17 fix, legacy alias retained), `/api/backups/operations/{id}`, `/api/config/rollback-scope` | Consistent with `PRODUCT-TERMINOLOGY.md`; T-17 closure confirmed in OpenAPI (canonical path + labelled legacy alias) |
| Config keys | none | — |
| Metrics | `culvert_cert_sign_singleflight_joined_total` | Implementation-flavoured but operator-facing only in Prometheus; sibling CA metrics use the same style; not charged |
| Audit actions | `backup.trigger`, `<action>.refused`, `auth.basic.fail`, `auth.basic.refused` | Dotted `domain.verb` form matches existing actions |
| GUI | on-demand backup control, config rollback-scope note | Wording uses "backup" / "rollback" consistently |

**One new finding (T-64, Medium).** No Critical or High findings.

**Terminology Health Score: 7.4 / 10** — the 2026-09-24 report's fully charged snapshot figure
(7.4), less 0.1 for T-64, plus 0.4 for the four fixes it already listed as merged after `6ec745d`
(T-57, T-58, T-17, T-59), → **7.7**. The 2026-09-24 report's disclosed lineage gap (T-54's missing
0.1) is carried, not amended, and the separate 2026-09-20 lineage is not reconciled here.

## Canonical Concepts (relevant to this window)

| Concept | Canonical name | Notes |
| --- | --- | --- |
| Long-running, idempotent unit of work with a durable receipt | **operation**, identified by an **operation ID** | See T-64 |
| Traffic-log destination hiding | **destination privacy** | T-17: `/api/traffic/redaction` canonical |
| Settings excluded from config rollback | **rollback scope** | New, consistent end to end |

## Findings

### T-64 — One concept, four spellings: the operation identifier  (Priority: Medium)

- **Business concept:** the identifier of a durable, pollable/idempotent operation (backup, release
  dispatch, destination-privacy key rotation, PAC publish, CDR enrolment).
- **Current names (JSON wire):**
  - `operationId` — `pac_lifecycle_api.go:185`, `internal/pac/*`, `cdr_ui.go:377`, `cdr_enroll_receipts.go`, `cdr_lineage.go`
  - `operation_id` — `decryption_redaction.go:247` (rotation request/response)
  - `op_id` — `decryption_redaction.go:42` (rotation receipt, same feature as the line above),
    `release_api.go:224`, `release_dispatch_exec.go:575`, maintenance-agent wire (`cmd/culvert-maint/internal/{ops,journal,audit}`)
  - `opId` — `backups_api.go:345` (new, `POST /api/backups` response; consumed at `static/index.html:16091-16145`, `types.gen.ts:5459`)
- **Also:** the backup audit detail writes `op_id=` (`backups_api.go:335`) while its own response field is `opId`.
- **Why problematic:** `opId` is the only abbreviated camelCase form and it is *new* — it adds a fourth
  spelling for a concept that already has three. Within one feature (destination-privacy rotation) the
  request says `operation_id` and the receipt says `op_id`. An integrator or support engineer correlating
  an audit line (`op_id=`) with an API response (`opId`) must know the mapping.
- **Recommended canonical name:** *operation ID* in prose and UI; on the **admin REST API** (camelCase
  JSON: PAC, CDR, backups) the field is `operationId`; `op_id` stays only on the maintenance-agent wire
  and its journal/audit, which are a separate, versioned protocol; `operation_id` / `op_id` in
  `decryption_redaction.go` are stable and are NOT to be renamed (they are persisted receipts).
- **Why better:** `operationId` is already the majority admin-API spelling and is what the generated
  frontend types for PAC/CDR use; "op" is an implementation abbreviation. Only the newest field needs to
  move, and only if it has not shipped.
- **Affected code:** `backups_api.go:345` (+ test), `static/index.html:16091-16145`.
- **Affected API:** `POST /api/backups` response field `opId`; `api/openapi/openapi.yaml`, regenerated `frontend/src/api/types.gen.ts`.
- **Affected GUI:** on-demand backup poller (internal variable names only; no visible label).
- **Affected documentation / configuration:** none (`CHANGELOG.md` has no entry for the field).
- **Migration complexity:** Low. **Compatibility risk:** Low *only if* `opId` has not been in a tagged
  release (the repo has no entry in `CHANGELOG.md` and no tag contains it that this review could find);
  otherwise accept both fields for one release. **Estimated PR size:** S (≈ 5 files).
- **Not recommended:** renaming `op_id` / `operation_id` in `decryption_redaction.go`, `release_api.go`
  or the maintenance-agent protocol (persisted/wire-compatible; migration cost exceeds benefit).
- **Action:** record only. Owner to confirm release state of `opId`, then either fix before release or
  document the exception.

## Terminology Drift / Legacy / Conflicting / Ambiguous

No new items beyond T-64. Carried items (T-9, T-11, T-12, T-13, T-18, T-21+T-32, T-25, T-29, T-30,
T-33, T-34, T-39, T-54, T-55, T-56, T-60, T-61, T-62, T-63, T-51 residual) remain with their owning
reports.

Confirmed in this window: **T-17** is closed in the OpenAPI spec (canonical `/api/traffic/redaction`,
legacy `/api/decryption/redaction` alias explicitly labelled).

## Migration Risk and Plan

1. (Medium, S) T-64: confirm release state of the backup `opId` field; if unreleased, rename to
   `operationId` in handler, GUI, OpenAPI and regenerate types in one PR.
2. No other action.

## Reproduction

```sh
git diff 6ec745d 77c0c58 -- api/openapi/openapi.yaml | grep -E '^[+-]  /'
git grep -nE 'json:"(opId|op_id|operation_id|operationId)[,"]' 77c0c58 -- '*.go' ':!*_test.go'
git grep -n '"opId"' 77c0c58 -- backups_api.go
```
