# Culvert Language & Terminology Governance Review — 2026-10-12

> **Status:** Point-in-time review. **Audited window:** `6ec745d..fbf6a37` (the 2026-09-24 report's
> snapshot to `main` at 2026-10-12), restricted to admin-facing copy, audit actions, OpenAPI names,
> metrics and diagnostics messages added in the window.

## Executive Summary

One production-worthy finding (T-64), fixed in this PR. Everything else added in the window
(self-service Change Password, on-demand backup UI, Stale Episodes, Tracing Headers Replaced,
state-file quarantine diagnostics, "Refresh" verbs, rollback-scope disclosure) reuses established
names. The carried backlog (T-9 … T-63, 23 open per the 2026-09-24 comparison row) is neither
re-verified nor re-charged here.

**Terminology Health Score: 7.9 / 10** (the 2026-09-24 comparison row, lineage figure; T-64 is found
and fixed in the same change, so net 0.0).

## T-64 — On-demand backup audit action (`backup.trigger`) — Medium/Low risk, FIXED

| Field | Value |
| --- | --- |
| Business concept | An administrator creates a backup archive |
| Current names | audit action `backup.trigger`; maintenance operation kind `backup.create`; OpenAPI `createBackup`; GUI "Start Backup" |
| Canonical name | `backup.create` (family: `support.bundle.create`, op kinds `backup.create` / `restore.commit`) |
| Problem | One concept carried two verbs. An auditor correlating the audit trail with the maintenance operation record (`kind":"backup.create"`, same `op_id` in the audit detail) had to know that "trigger" and "create" were the same event. "trigger" also describes the mechanism (GUI button → agent call), not the business event. |
| Affected code | `backups_api.go`, `backups_api_test.go` |
| Affected API | `x-culvert-audit-event` on `POST /api/backups` in `openapi.yaml` / `openapi.json` |
| Affected GUI / docs / config | none (no user-visible string used the audit action) |
| Migration complexity / PR size | Trivial / XS |
| Compatibility risk | Low: the action existed ~16 days, no other file referenced it. SIEM filters on `backup.trigger` must be updated (CHANGELOG entry added). |

## Reviewed and deliberately unchanged

- GUI nav "Administrators" vs panel/diagnostics "Admin Users" and "admin roster" in log text: the
  nav/panel split was ruled deliberate in the 2026-09-09 report; the new diagnostics reuse the panel
  title. Not re-opened.
- Log prefix `UIUsers:` and "roster": pre-existing internal vocabulary, operator-visible only through
  the process log; no support or documentation confusion evidenced. Not recommended.
- "Control Plane" / "primary" / "leader" in the Cluster panel: carried backlog territory, no new use.

## Verification

`go test -count=1 -run 'Backup|OpenAPI|APIContract|Drift' .` passes.
