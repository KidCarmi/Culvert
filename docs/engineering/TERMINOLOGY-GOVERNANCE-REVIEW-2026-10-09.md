# Culvert Language & Terminology Governance Review — 2026-10-09

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** audited `6ec745d..3fcc07e` (the window after the 2026-09-24 snapshot; `3fcc07e` was
> `origin/main` HEAD at fetch time). Most merges in the range are windows already owned by merged
> reports (2026-09-19/20/21/23) and are not re-charged. Net-new admin-facing names in the range were
> checked directly: on-demand backup (#1468), self-service password change (#1425), oversize-username
> diagnostics (#1490), state-file quarantine diagnostics (#1408), admission-engine extraction
> (#1522/#1523, internal packages only).

## Executive Summary

One new drift item (T-64) found and **fixed in this change**. Everything else sampled is consistent.

**Terminology Health Score: 7.9 → 7.9** (T-64 is charged 0.1 and returned 0.1 in the same change; the
7.9 baseline is the 2026-09-24 report's comparison figure including T-57/T-58/T-17/T-59).

## Findings

### T-64 — On-demand backup audit action said `trigger`, every sibling says `create` (FIXED) — Priority: Low

- **Business concept:** an admin starting a new backup archive from the Support panel.
- **Current names:** audit action `backup.trigger` (`backups_api.go`), OpenAPI
  `x-culvert-audit-event: backup.trigger`, agent operation kind `backup.create`
  (`backupOpKind`), route comment "POST /api/backups (backup.create trigger)", GUI "Backup Now" /
  "Start Backup".
- **Problem:** `backup.trigger` was the only `.trigger` audit action in the tree; the same operation
  was named `backup.create` one layer down. Creating actions use `<noun>.create`
  (`support.bundle.create`, `alert.webhook.create`, `nodegroup.create`, ...). An auditor searching the
  trail for backup creation would not find it under the vocabulary the rest of the trail uses, and the
  audit name and the operation id the same entry records (`op_id=`) disagreed on the verb.
- **Canonical name:** `backup.create`. "Trigger" describes the mechanism (a POST that kicks the
  agent), not the business event.
- **Fix:** `backups_api.go`, `backups_api_test.go`, `openapi.yaml`/`openapi.json` (regenerated via
  `make api-bundle`; `make api-verify` green), CHANGELOG entry. No GUI string changes (the buttons
  describe the user action and are already consistent with each other).
- **Migration:** the action was introduced in #1468 on 2026-09-26 and has not shipped in a tagged
  release known to this review; compatibility risk is limited to any SIEM rule written against the
  two-week-old name (called out in the CHANGELOG). Complexity: trivial. PR size: XS (6 lines + docs).

## Checked, no drift

- **"Backup" vs configuration export** — the T-14 split (backup = disaster-recovery archive of the data
  directory; export = configuration JSON) holds in the new panel copy.
- **Change Password** — button, modal functions, `/api/auth/change-password` and audit
  `auth.password_change` all use "password change"; consistent.
- **Oversize admin usernames / state-file quarantine diagnostics** — reuse existing operator-contract
  vocabulary; no new competing names.
- **Admission engine** — internal package naming (`internal/admission`, ADR-0038/0039) is
  implementation-only; admin-facing names remain "IP Filter" and "Rate Limit".

## Carried over (unchanged, not re-verified in this pass)

T-9, T-11, T-12, T-13 (residual), T-18, T-21+T-32, T-25 (residual), T-29, T-30, T-33, T-34, T-39,
T-54 and the other IDs listed in the 2026-09-24 report remain as described there.

## Stop-condition assessment

Not triggered: one production-worthy improvement existed and was applied. No cosmetic renames proposed.
