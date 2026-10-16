# Culvert Language & Terminology Governance Review — 2026-10-16

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Window:** `45eaf07..dec66e1` (the 2026-09-24 report's merge to `main` at the time of this review) —
> 177 files. This is a focused pass over admin-facing names added in the window (GUI, OpenAPI, audit
> actions, metrics, health/stats fields), not a re-audit of the carried backlog.

## Executive Summary

One production-worthy fix: **T-64** — the SEC-RBAC-ROLE-1 clamp counter used a `ui_` prefix for the same
concept the rest of the family calls the **admin roster**. Fixed in this change (unreleased, so no
compatibility cost). Nothing else in the window warranted a rename.

Carried backlog (T-9 … T-63) is untouched and not re-verified; this report neither charges nor closes any
of it. **Terminology Health Score:** 7.9 comparison-lineage figure from the 2026-09-24 report, +0.1 for
T-64 found and fixed in the same change = unchanged **7.9** (lineage; fully charged 7.8). The two
lineages disclosed in earlier reports are not reconciled here.

## Canonical Concepts checked

| Concept | Canonical name | Names seen |
|---|---|---|
| Console accounts and their roles | Admin roster (`ui_users.json`) | `culvert_admin_roster_persist_failures_total`, `culvert_admin_roster_persist_degraded_total`, **`culvert_ui_roster_role_clamped_total`** (drift), `uiRosterRoleClamped` (drift) |
| Admin web console | Admin UI | `culvert_admin_ui_*` (consistent) |
| Host-root helper that applies updates and runs backups | Maintenance agent | consistent in GUI, OpenAPI, operator docs (`culvert-maint` is the binary/service name) |

## T-64 — Admin roster clamp counter named `ui_roster`

- **Business concept:** the admin roster (the set of console accounts and roles).
- **Current names:** `culvert_admin_roster_*` (two metrics, `docs/operator/admin-roster-durability.md`) vs
  `culvert_ui_roster_role_clamped_total`; JSON `uiRosterRoleClamped` on `/healthz` and `/api/stats`.
- **Recommended canonical name:** `culvert_admin_roster_role_clamped_total`, `adminRosterRoleClamped`.
- **Why the current naming is a problem:** it is the only `culvert_ui_*` metric. An operator writing a
  dashboard or alert for roster health has to know that one counter of the family lives under a different
  prefix; `culvert_admin_ui_*` already means "the Admin UI listener", so `ui_` here reads as a second
  concept.
- **Affected code:** `events.go` (metric), `ha.go` (`/healthz`), `ui_config.go` (`/api/stats`).
  **API:** `/healthz` and `/api/stats` field only; neither is in `api/openapi/openapi.yaml`.
  **GUI:** none. **Config:** none. **Docs:** `CHANGELOG.md` [Unreleased] entry updated; the preserved
  history file (`docs/agent-context/history/authentication-and-identity.md`) keeps the original wording
  because that archive is byte-checked by `check.py`.
- **Migration complexity / compatibility risk:** low / none — the entry is under `[Unreleased]` and no
  tag contains commit `93a196e`. No test referenced either string.
- **Estimated PR size:** XS (this change).

## Considered and rejected

- Audit action `backup.trigger` vs GUI "Start Backup" vs the maintenance agent's `backup.create` kind:
  three verbs for one action, but audit actions are SIEM-facing strings and the existing set already mixes
  verbs (`upstream.probe.manual`, `threatfeed.sync`, `support.bundle.create`). Renaming buys little and
  risks consumers; not recommended.
- "Roster" itself: established in 20+ docs, metrics and code; the glossary's "Administrator" governs GUI
  labels, not these operator-facing persistence terms.

## Stop-Condition Assessment

Apart from T-64, no production-worthy terminology improvement was identified in the window. No cosmetic
or preference-driven renames are proposed. The glossary sweep covered the literal forbidden terms in
Go non-test lines added in the window (blacklist/whitelist, unauth mode, scanner, live feed, recent
requests, users & roles, cluster nodes, proxy pool, appliance): only three comment-only hits ("appliance" x2, "scanner" x1)
(no product copy).
