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

**Terminology Health Score: 7.7 / 10 (lineage figure)** — baseline 7.9 (the 2026-09-24 report's
comparison figure: its 7.5 plus T-57, T-58, T-17, T-59 fixed), minus 0.1 per newly recorded item (T-64,
T-65). Same rule as prior reports. Like its predecessors, this lineage figure UNDER-charges by 0.1,
because open T-54's charge was never carried into the 2026-09-13 report's score
(`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-24.md`, "Disclosed, not amended"). The **fully charged
equivalent is 7.6** (7.8 − 0.2), carried for transparency as that report requires; it is not this
report's score. Carried open backlog: 23 IDs / 22 entries per that comparison row (not re-verified), plus the 2
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
- **Canonical rule:** `operationId` on camelCase surfaces, `operation_id` on snake_case surfaces and in
  `key=value` audit details, and "operation ID" in prose.
- **Why problematic:** the *same operation* is created with `opId` and polled as `op_id` on the backup
  resource. Supporting staff correlating an audit line (`op_id=`) with an API response (`opId`) have to
  know both names. "op" is an implementation abbreviation, not a business term.
- **Why better:** one noun, "operation ID", on every surface a human or integrator reads, with the
  existing spellings kept as aliases so nothing breaks.

The inventory is split by kind, because the two kinds carry different risk:

- **(a) Wire identifiers** (JSON keys, query parameters, accepted request fields, audit and webhook
  detail keys, and the client code and generated types that read them). Renaming one can break an
  integrator, so they are inventoried exhaustively below.
- **(b) Human-readable prose** (error strings, OpenAPI descriptions, UI copy, comments). These carry no
  compatibility risk and cannot be enumerated to a fixed point. They are governed by a copy rule plus a
  search the implementing PR must run (see "Prose" below), not by a table.

**(a) Wire-identifier inventory.** This is the inventory produced by the commands below at `fbf6a37`.
The implementing PR must re-run them against its base and reconcile. The first version of this table
used a case-sensitive pattern keyed on "id" and missed the untagged `OpID` field and the `op=` alert
key. A later version matched only ID-shaped names and missed the `operation=` audit key (Codex,
PR #1602). Search (c) therefore matches ANY key whose name is `op` or `operation`, with or without an
`id` suffix, in every key syntax the code uses.

```sh
REV=fbf6a37   # the audited snapshot; the implementing PR sets its own base
# (a) every spelling, case-insensitive, all non-test Go INCLUDING cmd/
git grep -n -i -E '\bop_?id\b|\bopid\b|operation_?id|\bop=' "$REV" -- '*.go' ':!*_test.go'
# (a) the same over the contract and both GUIs
git grep -n -i -E '\bop_?id\b|\bopid\b|operation_?id|\bop=' "$REV" -- api/openapi/openapi.yaml frontend/src static/
# (b) exported, UNTAGGED operation-ID-like struct fields (Go serializes them under the Go name)
git grep -n -E '^\s+(Op|OpID|OpId|OperationID|OperationId|Operation)\s+[][*A-Za-z0-9_.]+\s*(//.*)?$' "$REV" -- '*.go' ':!*_test.go'
# (c) any op/operation key, in every key syntax: key=value details and Go/TS/YAML keys,
#     JSON struct tags, quoted map-literal keys, query parameters (URL, Query().Get, OpenAPI name:)
P='\b(op|operation)(_?id)?\s*[=:]|json:"(op|operation)(_?id|Id)?[,"]|["'"'"'](op|operation)(_?id|Id)?["'"'"']\s*:'
P="$P"'|[?&](op|operation)(_?id|Id)?=|\.Get\(["'"'"'](op|operation)(_?id|Id)?["'"'"']|name: (op|operation)(_?id|Id)?\b'
git grep -n -i -E "$P" "$REV" -- '*.go' ':!*_test.go' api/openapi/openapi.yaml frontend/src static/ ':!frontend/src/test'
```

Each hit was classified by surface, and each untagged struct from (b) was traced to see whether it
reaches a JSON response, a request body or a webhook payload. Not this concept, and omitted: OpenAPI
route `operationId:` keys and `internal/apicontract`; MCP `Operation` fields (an operation *class*);
`mcperr` `Op` (a kernel step name); `op=` JavaScript variables in `static/index.html` MCP panels; Go
locals and struct-literal fields (`opID :=`, `OpID: x`), which (c) also matches; the comparison-
*operator* keys `op` on auth-rule subject predicates (`authpolicy.go:77`, read at
`frontend/src/api/policyAuth.ts:72,114`) and MCP policy conditions (`internal/mcp/policy/condition.go:50`,
`internal/mcpacceptance/authoritative.go:94`); and the plural full-word `operations` keys
(PAC `DecidedOp` lists in `internal/pac/publish.go`; MCP rollout risk classes in `internal/mcp/rollout/scope.go`).
Wire identifiers found:

| # | Site (`fbf6a37`) | Surface | Current key |
|---|---|---|---|
| 1 | `backups_api.go:345` — `POST /api/backups` (`BackupCreateResult`, `openapi.yaml:1203`) | API response | `opId` |
| 2 | `backups_api.go:447` — `GET /api/backups/operations/{id}` (`BackupOperationStatus`, `openapi.yaml:1212-1215`) | API response (agent record, verbatim; snake_case surface: `op_id`, `kind`, `state`, `progress`) | `op_id` |
| 3 | `release_api.go:224` (`dispatchRecord`, served by `GET /api/releases/dispatch/status` (`apiReleaseDispatchStatus`); spec `DispatchStatus`, an open object) | API response | `op_id` |
| 3a | `release_dispatch_service.go:49-58` — `DispatchResumeContext`, whose fields have **no json tags**, embedded as `dispatchRecord.ResumeContext` (`json:"resume_context"`) in the `GET /api/releases/dispatch/status` response (`apiReleaseDispatchStatus`) | API response | `resume_context.OpID` (the Go field name) |
| 4 | `release_api.go:711` — `POST /api/releases/dispatch` 202 body | API response | `op_id` |
| 5 | `release_api.go:845` — `POST /api/releases/dispatch/resume` 202 body | API response | `op_id` |
| 5a | `release_dispatch_service.go:49-58` — the same untagged `DispatchResumeContext`, accepted as `resumeRequest.ResumeContext` by `POST /api/releases/dispatch/resume` and used verbatim by `resolveResumeContext` | Accepted request field | `resume_context.OpID` |
| 7 | `backups_api.go:335` — `backup.trigger` | Audit detail | `op_id=` |
| 8 | `release_dispatch_service.go:423` — `release.dispatch` | Audit detail | `op_id=` |
| 9 | `release_dispatch_service.go:438` — `release.dispatch.outcome` | Audit detail | `op_id=` |
| 9a | `release_dispatch_service.go:450-453` — `release_dispatch_attention` alert (`AlertPayload.Detail`, delivered to alert/webhook subscribers) | Alert/webhook detail | `op=` |
| 9b | `cdr_ui.go:529-531` — `cdr.instance.enroll` | Audit detail | `operation=` |
| 10 | `pac_lifecycle_api.go:650,1092,1256` — `pac.*` audit details | Audit detail — recorded exception (see constraints) | `operationId=` |
| 11 | `static/index.html:16091-16166` — Backup Now polling | GUI (JS only) | `opId` |
| 12 | `static/index.html:17679,17689,17741,17783` — release dispatch panel reads the response key | GUI (client code) | `op_id` |
| 13 | `frontend/src/api/types.gen.ts:5459,5472` | Generated client types | `opId`, `op_id` |
| 14 | `decryption_redaction.go:135,379,418` — key rotation request/receipts (`openapi.yaml:1014,1896`) | API request/response — already canonical | `operation_id` |
| 15 | `cdr_ui.go:537`, `cdr_enroll_receipts.go:87,128,558,595`, `cdr_lineage.go:75` — CDR enrollment/receipts (`openapi.yaml:2186-2257`) | API request/response — already canonical | `operationId` |
| 16 | `pac_lifecycle_api.go` responses (`:185,293,535,570,612,651,847,870,910,920,927,1169,1248`; `openapi.yaml:552-561`) | API request/response — already canonical | `operationId` |
| 16a | Query parameters: `GET …/lifecycle?operationId=` (`pac_lifecycle_api.go:367`, `openapi.yaml:9109`) and the CDR receipt repair `?operationId=` (`cdr_enroll_receipts.go:726`, `openapi.yaml:12765`; sent at `frontend/src/api/cdr.ts:673`, `frontend/src/api/pac.ts:1302`) | Query parameter — already canonical | `operationId` |
| 16b | `internal/pac/intent.go:105` — `AmbiguousOp.Op` in the PAC lifecycle response (`ambiguous.op`, decoded at `frontend/src/api/pac.ts:501`). It names the pending operation *record*, not its ID | API response (camelCase) | `op` |
| 17 | Maintenance agent (`cmd/culvert-maint`): its operation record `op_id` (`cmd/culvert-maint/internal/ops/ops.go:52`), error and start bodies (`cmd/culvert-maint/internal/server/handlers_d16b.go:363,420`), its own audit events (`cmd/culvert-maint/internal/audit/audit.go:39`), its on-disk journal (`cmd/culvert-maint/internal/journal/journal.go:72`) and its op-log note `op_id=` (`cmd/culvert-maint/internal/ops/orchestrator.go:223`) | Agent API, agent audit, agent storage — recorded exception (see constraints) | `op_id` |

Internal, not visible: `backups_api.go:328` and `release_dispatch_exec.go:575,581` read the maintenance
agent's own `op_id` wire field. The untagged `OpID` fields of `DispatchReport`
(`release_dispatch_service.go:83`), `DispatchAuditEvent` and `DispatchResult`
(`release_dispatch_exec.go:150,158`) are never JSON-encoded. The agent's `idempEntry` and
`InterruptedOp` `OpID` (`cmd/culvert-maint/internal/ops/ops.go:189,617`) are in memory only.
`decryption_redaction.go:42` stores the receipt as `op_id` on disk and renders it as `operation_id`.
Also internal: the Go error strings at `release_dispatch_exec.go:338` and
`release_dispatch_service.go:317` and the route note at `ui_routes_meta.go:810`.

**(b) Prose.** Copy rule: user-facing prose says "operation ID". It never uses a bare "op" or an
identifier spelling as a word ("op id", "op_id", "opId", "opID", "op record", "operation_id",
"operationId", "OperationID"). This is not enumerated.

**Scope of the rule, and of the search that enforces it** (the two must name the same paths):
- error strings and comments in non-test Go (`*.go`, including `cmd/`);
- OpenAPI descriptions (`api/openapi/openapi.yaml`);
- React UI copy (`frontend/src`, excluding `frontend/src/test`);
- legacy GUI copy (`static/`);
- operator runbooks (`docs/operator/`).

The implementing PR must run this search against its base and resolve every user-facing hit. It
uses explicit non-alphanumeric delimiters instead of `\b`, because `_` is a word character and `\b`
fails around `op_id`:

```sh
REV=fbf6a37   # the implementing PR sets its own base
D='(^|[^A-Za-z0-9])'; E='([^A-Za-z0-9]|$)'
git grep -n -i -E "${D}(op([ _]?(id|record))?|operation[ _]?id)${E}" "$REV" -- \
  '*.go' ':!*_test.go' api/openapi/openapi.yaml frontend/src ':!frontend/src/test' static/ docs/operator/
```

**Self-check (run at `fbf6a37`).** Every `file:line` cited anywhere in this T-64 section was checked
against the combined output of the (a)/(b)/(c) identifier commands and the prose command above, all at
`fbf6a37`. All 101 citations appear in that output: 86 `path:line` or `path:range` citations, plus 15
bare `:N` continuation lines for `pac_lifecycle_api.go`. Context references that are not hits (the
route or handler that serves or decodes a struct) are named by function, not by line. The implementing
PR should repeat the check at its own base.

Examples found at `fbf6a37`, **not exhaustive**: the resume 400 text "resume needs an op_id"
(`release_api.go:823`); "no valid op_id or kind" (`backups_api.go:330-332`); "agent apply returned no
op_id" (`release_dispatch_exec.go:574-581`), which reaches the dispatch 502 detail, the outcome audit
and the attention webhook; the OpenAPI descriptions "Returns an op id" and "The op record"
(`openapi.yaml:6780,6831`, copied into `types.gen.ts:329,349`); the release panel's `op_id` row label
and "op …" toasts (`static/index.html:17679,17741,17783`); and lowercase or bare forms such as
`backups_api.go:396`, `cdr_ui.go:441-442`, `openapi.yaml:1898` and `release_api.go:860`. Value-only
mentions in logs and audit prose ("operation <id>") already follow the rule.

**Constraints the implementing PR must satisfy.** The migration design belongs to that PR.

- Additive only: every existing key, field and alias stays, both emitted and accepted. That includes
  audit detail keys: `key=value` details gain `operation_id=` beside the existing `op_id=`, `op=` and
  `operation=` (rows 7-9b), which stay.
- Accepted-input sites (row 5a) accept both keys, reject a request that carries conflicting values, and
  keep strict decoding (unknown fields rejected).
- snake_case surfaces use `operation_id`; camelCase surfaces use `operationId` (only row 1 is camelCase).
- Pass-through endpoints (backup status, row 2) need a handler reshape plus contract, comment and test
  updates, because the agent protocol stays `op_id`.
- Rebuild and commit `frontend/dist`, and regenerate `types.gen.ts`.
- The pre-existing dispatch/resume drift (spec documents `200`, handlers return `202`;
  `openapi.yaml:10087-10110,10965-10993` vs `release_api.go:704-714,841-848`) is a separate
  versioning decision, not part of this change.
- All user-facing prose hits of the (b) search are converted or explicitly exempted in the
  implementing PR.
- Contract MINOR bump (`info.version` and `x-culvert-api-contract-version`) with regenerated contract
  artifacts.
- Recorded exceptions, left as they are: the `pac.*` `operationId=` audit key (row 10) and the
  maintenance agent's own `op_id` protocol and storage (row 17).

- **Migration complexity:** Low to medium. **Estimated PR size:** M/L.

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
- **Shipped bundle:** the binary serves the embedded `frontend/dist` (`ui_frontend_v2.go:34-39`,
  `//go:embed all:frontend/dist`), so editing `AuthRulesPage.tsx` alone changes nothing an operator
  sees. The fix must rebuild and commit `frontend/dist`, which the dist drift gate checks.
- **Migration complexity:** Trivial. **Compatibility risk:** None, unless a test pins the string (check
  `frontend/src/test` before editing). **Estimated PR size:** XS (1 source line) plus the rebuilt,
  committed `frontend/dist`.
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

Only T-64 touches a wire contract, and only under its constraints list: additive keys, a MINOR contract
bump, and the separate `200`/`202` versioning decision. T-65 is copy plus a rebuilt `frontend/dist`.

## Recommended Refactoring Plan (by priority)

| Priority | Item | Action |
| --- | --- | --- |
| Critical | — | none |
| High | — | none |
| Medium | T-64 | Re-run the T-64 inventory commands against the implementing PR's base, then add the canonical keys under the T-64 constraints list |
| Low | T-65 | Reword the React hint (`AuthRulesPage.tsx:738`) to "roll back to a config version"; rebuild and commit `frontend/dist` (dist drift gate) |
| Low | T-65 CDR note | Remove the false "restore via Config Versions" recovery claim from the legacy CDR deletion dialog (`static/index.html:11971`); CDR policies are not versioned |

## Stop-condition assessment

The "no improvements identified" stop condition does **not** apply: T-64 is a real same-resource
inconsistency introduced in the window. Everything else swept is consistent.
