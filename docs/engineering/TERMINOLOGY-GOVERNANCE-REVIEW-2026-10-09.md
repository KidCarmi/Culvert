# Culvert Language & Terminology Governance Review — 2026-10-09

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** audited `6ec745d..3fcc07e` (the window after the 2026-09-24 snapshot; `3fcc07e` was
> `origin/main` HEAD at fetch time). Most merges in the range are windows already owned by merged
> reports (2026-09-19/20/21/23) and are not re-charged. Net-new admin-facing names in the range were
> checked directly: on-demand backup (#1468), self-service password change (#1425), oversize-username
> diagnostics (#1490), state-file quarantine diagnostics (#1408), admission-engine extraction
> (#1522/#1523, internal packages only).

> **Finding ID.** This report was drafted as T-64. Main has since assigned T-64 twice (the 2026-10-11
> operation-identifier finding and the 2026-10-15 admin-roster finding) and T-65..T-69, and open
> #1715 holds T-70, so this report's finding is renumbered **T-71**.

## Executive Summary

One new drift item (T-71) found. It is **resolved by recording an alias, not by a rename**: the audit
action has shipped, and SIEM rules and saved searches match it verbatim.

**Terminology Health Score: 7.9 → 7.9** (T-71 is charged 0.1 and returned 0.1 in the same change; the
7.9 baseline is the 2026-09-24 report's comparison figure including T-57/T-58/T-17/T-59).

## Findings

### T-71 — On-demand backup audit action says `trigger`, every sibling says `create` (RESOLVED: alias) — Priority: Low

- **Business concept:** an admin starting a new backup archive from the Support panel.
- **Current names:** audit action `backup.trigger` (`backups_api.go`, now the named constant
  `backupAuditAction`), OpenAPI `x-culvert-audit-event: backup.trigger`, agent operation kind
  `backup.create` (`backupOpKind`), route comment "POST /api/backups (backup.create trigger)", GUI
  "Backup Now" / "Start Backup".
- **Problem:** `backup.trigger` is the only `.trigger` audit action in the tree; the same operation is
  named `backup.create` one layer down. Creating actions use `<noun>.create` (`support.bundle.create`,
  `alert.webhook.create`, `nodegroup.create`, ...). An auditor searching the trail under the
  vocabulary the rest of the trail uses would not find it.
- **Why not rename:** the action was introduced in #1468 on 2026-09-26 and has shipped in every
  published release since v1.0.254. `audit.Add` hands `Entry.Action` to the SIEM hook unchanged
  (`store.go` → syslog JSON), and the `/api/audit` JSON/CSV exports and the Audit panel's text filter
  show it as-is, so a SIEM rule or saved search keyed on `backup.trigger` would silently stop matching
  every new backup after an upgrade. Emitting both names was also rejected: two entries per backup
  double-count it in every per-action count, rule and alert, and a second action in the same entry is
  not expressible without changing the audit wire shape.
- **Resolution:** `backup.trigger` stays the **canonical, stable** audit action. `backup.create` (the
  agent operation kind, already recorded in the same entry's detail as `op_id=`) is recorded as its
  **alias** in `docs/design/PRODUCT-TERMINOLOGY.md` ("Backup" row). `.trigger` is deprecated for NEW
  audit actions, which use `<noun>.create`; `backup.trigger` itself is grandfathered. Gate:
  `backup_audit_action_compat_test.go` drives the real handler and asserts exactly one
  `backup.trigger` entry per backup on the trail, the live SIEM forwarder, `/api/audit`, the CSV
  export and the OpenAPI contract.
- **Migration:** none. Existing filters, SIEM rules and saved searches keep matching. Complexity:
  trivial. PR size: S (one named constant, one gate, docs).

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

Not triggered: one production-worthy improvement existed and was applied as a documented alias rather than a rename of a shipped identifier. No cosmetic renames proposed.
