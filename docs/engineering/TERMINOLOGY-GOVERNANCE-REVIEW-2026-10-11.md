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
- **Current names:**
  - `opId` — `POST /api/backups` response (`BackupCreateResult`, `openapi.yaml:1203`; emitted at
    `backups_api.go:345`; read by `static/index.html:16091,16129,16145`).
  - `op_id` — `GET /api/backups/operations/{id}` response (`BackupOperationStatus`, `openapi.yaml:1212-1215`,
    maintenance-agent record passed through verbatim), the `backup.trigger` audit detail
    (`backups_api.go`, `op_id=%s`), and `release.dispatch` audit details (`release_dispatch_service.go:423,438`).
  - `operation_id` — traffic-redaction key rotation request/receipts (`openapi.yaml:1014,1896`).
  - `operationId` — PAC lifecycle and CDR responses (`openapi.yaml:552-558,2191,2232,2254`).
- **Recommended canonical name:** `operationId` on the camelCase `/api/backups` resource (its create
  request already uses camelCase, e.g. `passphraseEnvVar`); `operation_id` where the surface is
  snake_case; prose "operation ID". **Recorded exception:** `op_id` stays in `BackupOperationStatus`
  because that schema is the maintenance agent's operation record passed through verbatim
  (`additionalProperties: true`); it is the agent's wire format, not a Culvert-chosen name. To close the
  create-versus-poll mismatch the poll response should *also* carry `operationId` (copied from the
  agent's `op_id`), so a client can read one field name from both responses while `op_id` remains for
  existing readers.
- **Why problematic:** the *same operation* is created with `opId` and polled as `op_id`; a client
  written against one response cannot reuse the field name against the other. Support correlating a
  `backup.trigger` audit line (`op_id=`) with the API response (`opId`) has to know both. "op" is an
  implementation abbreviation, not a business term.
- **Why better:** one noun, "operation ID", on every surface a human or integrator reads; the abbreviation
  disappears from the public contract.
- **Affected code:** `backups_api.go:328-345`; `static/index.html` 16080-16177; audit detail strings.
- **Affected API:** `BackupCreateResult.opId` (additive: emit `operationId` beside it and keep `opId`
  **permanently**). `opId` may be marked `deprecated: true` with the deprecation metadata
  `docs/api/API-DEPRECATION-POLICY.md` requires, but *removing* it is a breaking change for any external
  client of `POST /api/backups` (removing a field is breaking under `API-VERSIONING-POLICY.md`) and would
  need the MAJOR-version exception process (`api-breaking-approved`, rationale, migration instructions,
  version impact). This report does not recommend that removal. The bundled GUI is the only *known*
  consumer, but that does not make the field private.
  `BackupOperationStatus`: add `operationId` beside the verbatim `op_id` (additive; the schema already
  allows extra properties); do not rename or drop `op_id`, which is the agent's own record field.
- **Affected GUI:** `backupNowPendingOp.opId` JS naming only; no visible label.
- **Affected documentation:** OpenAPI description at line 1203; any backup runbook that quotes the field.
- **Affected configuration:** none.
- **Migration complexity:** Low. **Compatibility risk:** None for the recommended change (additive on
  both responses; `opId` and `op_id` both stay). Removing `opId` later would be breaking (MAJOR). **Contract version:** new optional response fields
  are a **MINOR** contract change (`docs/api/API-VERSIONING-POLICY.md`, SemVer rules). The change must bump
  both `info.version` and `x-culvert-api-contract-version` in `api/openapi/openapi.yaml` (2.1.0 → 2.2.0
  at the time of writing), regenerate the committed contract artifacts (`make api-bundle`:
  `openapi.json`, the HTML docs, `docs/api/API-INVENTORY.md`) and pass `make api-verify` and
  `make api-breaking-check`. **Estimated PR size:** S/M (~60 lines of handler, spec, GUI and contract-test
  change, plus the version bump and regenerated artifacts). Do NOT rename `op_id` in
  audit detail strings without a CHANGELOG note: SIEM parsers may key on it.

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

Only T-64 touches a wire contract, and only additively (a new field on each backup response; nothing renamed or removed). That is a MINOR API contract bump, not a no-version change. T-65 is copy.

## Recommended Refactoring Plan (by priority)

| Priority | Item | Action |
| --- | --- | --- |
| Critical | — | none |
| High | — | none |
| Medium | T-64 | Add `operationId` on `POST /api/backups` beside a permanently kept `opId` (optionally marked deprecated, never removed without a MAJOR exception) and add `operationId` beside the agent's `op_id` on `GET /api/backups/operations/{id}`; update GUI + spec + contract test; MINOR contract bump (`info.version` + `x-culvert-api-contract-version`) with regenerated artifacts (`make api-bundle`, `make api-verify`) |
| Low | T-65 | Reword the React hint (`AuthRulesPage.tsx:738`) to "roll back to a config version" |
| Low | T-65 CDR note | Remove the false "restore via Config Versions" recovery claim from the legacy CDR deletion dialog (`static/index.html:11971`); CDR policies are not versioned |

## Stop-condition assessment

The "no improvements identified" stop condition does **not** apply: T-64 is a real same-resource
inconsistency introduced in the window. Everything else swept is consistent.
