# Culvert Language & Terminology Governance Review — 2026-10-08

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review
> **Method:** audited `6ec745d..3fcc07e` (the part of `main` not covered by the 2026-09-24 report), focusing on
> admin-visible names added in the window: audit actions, metrics, GUI labels and operator-contract rows.
> Carry-over spot checks (T-11, T-12, T-29/T-30) were not re-diffed; no file they depend on is among the
> window's new admin-facing surfaces. Prior open findings are carried by the 2026-09-24 report, not re-charged.

## Executive Summary

One new finding (T-64), fixed in this PR. Everything else added in the window (`auth.basic.fail`/`refused`,
`auth.password_change`, `auth.login.rejected`, the `culvert_cert_sign_singleflight_joined_total` metric, the
quarantine and persistence-state surfaces) follows the existing `<subsystem>.<verb>` and `culvert_*` conventions.

**Terminology Health Score: 8.5 / 10** (unchanged).

## T-64 — On-demand backup audit action `backup.trigger` vs. operation kind `backup.create` (fixed)

- **Business concept:** an administrator creates a backup archive.
- **Current names:** audit action `backup.trigger` (`backups_api.go`, OpenAPI `x-culvert-audit-event`); the
  maintenance-agent operation kind and the handler's own comments for the same act are `backup.create`;
  the GUI says "Backup Now" / "Start Backup" / "Backup started".
- **Problem:** "trigger" names the mechanism (a call to the agent), not the business event. Every other
  creation audit action uses `.create` (`support.bundle.create`, `alert.webhook.create`, `urlcat.create`, …),
  and `trigger` appears in no other audit action. A search for `backup.create` found the agent operation but
  not the audit entry for the same event.
- **Canonical name:** `backup.create`.
- **Affected:** `backups_api.go`, `backups_api_test.go`, `api/openapi/openapi.{yaml,json}` (one field each).
  No GUI, config, metric or documentation text used the old action.
- **Compatibility risk:** Low. The action shipped in #1468 within the last month; only consumers filtering the
  audit trail on the literal string are affected. **Migration complexity:** Trivial. **PR size:** Small.

## Not changed (deliberately)

The JSON response field `triggered` on `POST /api/backups` and the `backupTrigger*` identifiers are
implementation names on a wire/DOM surface and do not leak into admin-visible text; renaming them would
buy nothing. They are recorded here so a later review does not re-raise them.
