# Culvert Language & Terminology Governance Review — 2026-10-10

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review
> **Window:** `45eaf07..fbf6a37` (the last published review's merge to `origin/main` HEAD at review
> time): 13 first-parent merges, 67 non-test files. Backlog IDs from earlier reports (T-11, T-12,
> T-29/30, T-54 and others) were not re-verified; no window change touches them.

## Executive Summary

One small drift found and fixed; one T-51 recurrence and one button-case drift recorded as open; everything else in the window is consistent.

- **Operator-facing additions checked:** on-demand backup (`Backup Now` / `Start Backup`), self-service
  `Change Password`, `/api/backups/operations/`, `auth.basic.fail` / `auth.basic.refused`,
  state-file quarantine diagnostics, `culvert_ui_roster_role_clamped_total`. Verb/noun usage matches
  existing vocabulary (`backup`, `auth.<mechanism>.<outcome>`, `quarantine`). Capitalisation does
  not: the three new buttons are Title Case, against the glossary's sentence-case rule (see Other
  sections).
- **Findings:** 1 (Low) — below — plus one recurrence of an open item: "appliance" in two new
  `CHANGELOG.md` release-note entries (T-51; see Other sections).

**Terminology Health Score:** carried baseline from the 2026-09-24 report plus 1 new item, fixed in
this PR for the runbook; its metric-HELP half stays open until #1630 (T-64) merges.

## Canonical Concepts

| Business concept | Canonical name (GUI) | Other names found |
|---|---|---|
| Accounts that may sign in to the admin UI | **Administrators** ([product terminology](../design/PRODUCT-TERMINOLOGY.md); `/api/auth/users`, `auth.users.*`) | "Admin Users" (the legacy console's management panel title; the React console lists Administrators as a planned, not yet routed, entry), "admin roster" (docs, comments, metric `culvert_ui_roster_role_clamped_total`, `UIUsers` log prefix) |

## Finding R-1 (Low) — "admin roster" never tied to "Administrators"

- **Business concept:** the set of admin-UI accounts.
- **Current names:** product term "Administrators"; the only working management panel is the legacy console's "Admin Users"; API `/api/auth/users`; audit `auth.users.set|delete`; docs
  `docs/operator/admin-roster-durability.md` and a new metric say "roster".
- **Recommended canonical name:** Administrators (user-visible), per the product terminology glossary. "Roster" stays as the internal term for
  the persisted collection, but must be introduced once against the canonical name.
- **Problem:** an administrator or support engineer reading the durability runbook or the metric HELP
  cannot tell that "roster" means the administrator accounts.
- **Action taken:** the runbook's opening sentence now states the mapping. The metric name is NOT
  renamed here, and its HELP text is not edited in this PR: T-64 (#1630) rewrites that same HELP line
  (canonical `culvert_admin_roster_role_clamped_total`, old name kept as a deprecated alias), so the
  metric-side mapping lands there to avoid two PRs editing one line. R-1 is therefore fixed for the
  runbook and remains open for the metric HELP until #1630 merges.
- **Affected:** docs only (1 line); metric HELP via #1630. Migration complexity: none. Compatibility risk: none. PR size: XS.

## Other sections

- **T-51 recurrence (open, not fixed here):** two release-note entries added in the window say
  "the appliance" (`CHANGELOG.md`, the CDR client-key persistence entry and the SEC-RBAC-ROLE-1
  entry), although [product terminology](../design/PRODUCT-TERMINOLOGY.md) says **Appliance** is not
  used (say **node** or **instance**). Left for the T-51 owner because the on-prem appliance work in
  flight may change that glossary row.
- **Button case drift (Low, open, not fixed here):** the window adds `Backup Now`, `Start Backup`
  and `Change Password` in `static/index.html`; [product terminology](../design/PRODUCT-TERMINOLOGY.md)
  requires sentence case (`Backup now`, `Start backup`, `Change password`). Recorded rather than
  fixed so this docs-only review does not edit the console.
- **Legacy / conflicting / ambiguous names:** none new. The legacy console's "Admin Users" panel title
  is a known divergence from "Administrators", tracked separately (#1531). **Migration risk:** none.
- **Recommended plan:** none beyond R-1. If a future change surfaces "roster" in the GUI, use
  "Administrators" instead.
