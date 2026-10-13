# Culvert Language & Terminology Governance Review — 2026-10-13

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review
> **Scope:** `origin/main` at `77c0c58`, window `6ec745d..77c0c58` (78 first-parent merges). Focused on
> names newly visible to administrators: routes, audit actions, metrics, OpenAPI, GUI copy. Earlier
> backlog IDs (T-9 … T-63) are not re-verified here and remain owned by their reports.

## Executive Summary

One production-worthy finding (T-64), fixed in this PR. Nothing else in the window's new admin-facing
names drifted: the `/api/traffic/redaction` canonical route, `getConfigRollbackScope`, backup operation
polling and the Refresh wording all follow existing canon.

## T-64 — Backup creation audit action (Medium, fixed)

| Field | Value |
| --- | --- |
| Business concept | An administrator creates a backup |
| Current names | `backup.trigger` (audit action, OpenAPI `x-culvert-audit-event`); `backup.create` (maintenance-agent operation kind, `backupOpKind`, section heading in `backups_api.go`); `createBackup` (operationId) |
| Canonical name | `backup.create` |
| Problem | One event, two names. `trigger` describes the mechanism (the control plane invoking the agent), not the business event. Every other creation audit action uses `.create` (`support.bundle.create`, `urlcat.create`, `nodegroup.create`, …); `backup.trigger` was the only `.trigger` action. Operators correlating the audit log with the agent's operation log would search for two names. |
| Affected | `backups_api.go`, `backups_api_test.go`, `api/openapi/openapi.{yaml,json}` |
| GUI / docs / config | None; no documentation or config mentions `backup.trigger` |
| Migration complexity / compatibility risk | Low. The action was introduced by #1468 and has no release tag, so no shipped audit log, SIEM rule or alert references it. |
| PR size | Small (6 lines) |

The response field `triggered: true` and prose using "trigger" as a verb are left alone: they are
wire/behaviour details, not a competing name for the concept.

## Terminology Health Score

Lineage figure carried from the 2026-09-24 report: 7.5 (7.9 with its listed later fixes). This window
opens T-64 (−0.1) and closes it in the same PR (+0.1): net unchanged.
