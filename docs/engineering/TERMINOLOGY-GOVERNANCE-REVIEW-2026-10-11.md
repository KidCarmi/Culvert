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
| T-65 | Low | Config-version rollback | One GUI hint says "restore a config version"; everywhere else says "roll back" |

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
- **Current names:**
  - `opId` — `POST /api/backups` response (`BackupCreateResult`, `openapi.yaml:1203`; emitted at
    `backups_api.go:345`; read by `static/index.html:16091,16129,16145`).
  - `op_id` — `GET /api/backups/operations/{id}` response (`BackupOperationStatus`, `openapi.yaml:1212-1215`,
    maintenance-agent record passed through verbatim), the `backup.trigger` audit detail
    (`backups_api.go`, `op_id=%s`), and `release.dispatch` audit details (`release_dispatch_service.go:423,438`).
  - `operation_id` — traffic-redaction key rotation request/receipts (`openapi.yaml:1014,1896`).
  - `operationId` — PAC lifecycle and CDR responses (`openapi.yaml:552-558,2191,2232,2254`).
- **Recommended canonical name:** `operationId` on the camelCase `/api/backups` create response (matches
  its sibling fields `passphraseEnvVar`, `ifRevision`-style camelCase on that surface); `operation_id`
  where the surface is snake_case; prose "operation ID". `op_id` remains only where it is the
  maintenance agent's own wire format, with the API response schema documenting the mapping.
- **Why problematic:** the *same operation* is created with `opId` and polled as `op_id`; a client
  written against one response cannot reuse the field name against the other. Support correlating a
  `backup.trigger` audit line (`op_id=`) with the API response (`opId`) has to know both. "op" is an
  implementation abbreviation, not a business term.
- **Why better:** one noun, "operation ID", on every surface a human or integrator reads; the abbreviation
  disappears from the public contract.
- **Affected code:** `backups_api.go:328-345`; `static/index.html` 16080-16177; audit detail strings.
- **Affected API:** `BackupCreateResult.opId` (additive: emit `operationId`; keep `opId` for one release as
  a deprecated alias — the field is new in #1468 and its only known consumer is the bundled GUI).
  `BackupOperationStatus.op_id` is agent pass-through; document, do not rename.
- **Affected GUI:** `backupNowPendingOp.opId` JS naming only; no visible label.
- **Affected documentation:** OpenAPI description at line 1203; any backup runbook that quotes the field.
- **Affected configuration:** none.
- **Migration complexity:** Low. **Compatibility risk:** Low (dual-emit for one release; single in-tree
  consumer). **Estimated PR size:** S (~40 lines + contract test update). Do NOT rename `op_id` in
  audit detail strings without a CHANGELOG note: SIEM parsers may key on it.

### T-65 — "restore a config version" vs "roll back" (Low)

- **Business concept:** reverting configuration to an earlier version.
- **Current names:** "restore a config version" (`frontend/src/features/policy/AuthRulesPage.tsx:738`,
  rule-deletion rollback hint); "roll back" / "Rollback" everywhere else (`static/index.html:2648,8388`,
  `docs/enterprise/POLICY-ROLLOUT-GUIDE.md:49`, `OPERATIONS-RUNBOOK.md:43`, `diagnostics.go:1701`).
- **Recommended canonical name:** "roll back to a config version".
- **Why problematic:** "restore" is the backup/DR verb (`/data` restore). An operator reading
  "restore a config version" on a deletion dialog may look in the backup area instead of Config Versions.
- **Why better:** one verb per action; rollback keeps its meaning of "revert settings in a snapshot".
- **Affected code/GUI:** that one JSX string (the string predates the window — #1265 — but was not
  charged by an earlier report). **API / docs / config:** none.
- **Migration complexity:** Trivial. **Compatibility risk:** None, unless a frontend test pins the string
  (check `frontend/src/test` before editing). **Estimated PR size:** XS (1 line).

---

## Legacy Terminology / Conflicting / Ambiguous

No new entries. Carried (not re-verified): the 2026-09-24 report's backlog, notably T-11
(`default_action` allow/deny vs policy action names), T-12 (`/v1/upgrades/apply`), T-29/T-30
(`security.rate_limit` / `security.max_conns_per_ip` vs GUI wording), T-54 (OCSP metric naming).

## Migration Risk

Only T-64 touches a wire contract, and only additively. T-65 is copy.

## Recommended Refactoring Plan (by priority)

| Priority | Item | Action |
| --- | --- | --- |
| Critical | — | none |
| High | — | none |
| Medium | T-64 | Dual-emit `operationId` on `POST /api/backups`; deprecate `opId`; update GUI + spec + contract test |
| Low | T-65 | Reword the one hint to "roll back to a config version" |

## Stop-condition assessment

The "no improvements identified" stop condition does **not** apply: T-64 is a real same-resource
inconsistency introduced in the window. Everything else swept is consistent.
