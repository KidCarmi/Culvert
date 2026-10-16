# Culvert Language & Terminology Governance Review — 2026-10-10

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review
> **Window:** `45eaf07..fbf6a37` (the last published review's merge to `origin/main` HEAD at review
> time): 13 first-parent commits (7 of them merges). `git diff --name-only 45eaf07 fbf6a37` lists
> 172 files: 114 after excluding `*_test.go`, of which 47 are under `docs/` or `roadmap/` and 67 are
> code, UI, CI and packaging files. All 114 were in scope; the 67 were swept for added operator-facing
> strings and names, and the 47 documents were sampled. Backlog IDs from earlier reports (T-11, T-12,
> T-29/30, T-54 and others) were not re-verified; no window change touches them.

## Executive Summary

One small drift found and fixed (R-1, runbook half); its metric half, one T-51 recurrence, one
sentence-case drift and one console-account wording drift are recorded as open. This is a sampled
review of the window's operator-facing additions, not an exhaustive sweep: items it did not sample
are neither cleared nor charged.

- **Operator-facing additions checked:** on-demand backup (`Backup Now` / `Start Backup`), self-service
  `Change Password`, `/api/backups/operations/`, `auth.basic.fail` / `auth.basic.refused`,
  state-file quarantine diagnostics, `culvert_ui_roster_role_clamped_total`. Verb/noun usage matches
  existing vocabulary (`backup`, `auth.<mechanism>.<outcome>`, `quarantine`). Capitalisation does
  not: several new labels are Title Case or all caps, against the glossary's sentence-case rule (see
  Other sections).
- **Findings:** R-1 (Low) below, plus two new Low items (sentence case; console-account "user"
  wording) and one recurrence of an open item ("appliance" in two new `CHANGELOG.md` entries, T-51),
  all in Other sections.

**Terminology Health Score — audited window `45eaf07..fbf6a37`: 7.6 / 10** (lineage figure; fully
charged equivalent **7.5**).

- **Rule** (the 2026-09-08 precedent, as applied by the 2026-09-24 report): each open backlog item a
  report newly records costs 0.1, and each item it fixes gives 0.1 back. An item already charged by an
  earlier report is never charged again.
- **Baseline: 7.9**, the 2026-09-24 report's comparison figure for `6ec745d` plus T-57, T-58, T-17 and
  T-59. All four fixes merged before `45eaf07` (that report's own merge), so they are in this window's
  base tree and 7.9 is the inherited value (fully charged 7.8, carrying the disclosed T-54 0.1).
- **This report:** R-1 is newly recorded and only half fixed, so it stays open (−0.1); the sentence-case
  drift (−0.1) and the console-account "user" wording (−0.1) are new open items; the T-51 recurrence
  is not charged again. 7.9 − 0.3 = **7.6** (fully charged 7.5). R-1 gives its 0.1 back when #1630
  (T-64) fixes the metric HELP.

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
- **Sentence-case drift (Low, open, not fixed here):** [product terminology](../design/PRODUCT-TERMINOLOGY.md)
  requires sentence case for labels, headings and buttons. The window adds, in `static/index.html`,
  the buttons `Backup Now`, `Start Backup`, `Change Password` and `Back Up Unencrypted` and the heading
  `Unencrypted Backup`, and, in `docs/operator/admin-basic-auth.md`, the all-caps heading
  `BREAKING: accounts with TOTP enrolled cannot use Basic`. Recorded rather than fixed so this
  docs-only review does not edit the console.
- **Console-account "user" wording (Low, open, not fixed here):** `docs/operator/admin-basic-auth.md`
  says "Admin RBAC roles are per user", where "user" means a console account; the glossary requires
  **Administrator** (or "account") there and forbids bare "user" when it could mean a console account.
- **Legacy / conflicting / ambiguous names:** none new. The legacy console's "Admin Users" panel title
  is a known divergence from "Administrators", tracked separately (#1531). **Migration risk:** none.
- **Recommended plan:** R-1's metric half via #1630; the sentence-case and "user" items in a small
  follow-up that touches the console and the Basic-auth runbook. If a future change surfaces "roster" in the GUI, use
  "Administrators" instead.
