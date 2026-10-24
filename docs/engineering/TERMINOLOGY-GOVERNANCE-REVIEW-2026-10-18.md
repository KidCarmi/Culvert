# Culvert Language & Terminology Governance Review — 2026-10-18

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope:** `origin/main` at `dec66e1` (2026-10-16). Nothing in this report changes code, copy or
> configuration. The previous review in this series (2026-09-24) audited `6ec745d`; this one samples the
> user-visible additions between `6ec745d` and `dec66e1` (`static/index.html`, `frontend/src/features`,
> new admin routes, audit actions and diagnostics JSON fields). It is a **targeted sample, not an
> exhaustive audit** of the 209 commits in that range.

## Executive Summary

**No new production-worthy terminology improvement was identified** (one drift in the window is already
owned by the 2026-10-10 review; see Cross-referenced).

This report mints and closes no backlog ID. The `dec66e1` snapshot already contains the T-57, T-58, T-17
and T-59 fixes (#1407, #1434, #1444, #1456), which the 2026-09-24 report counted as post-snapshot closures in
its comparison row, so the state carried here is that row: **23 open IDs / 22 entries** and a Terminology
Health Score of **7.9** (lineage figure; fully charged 7.8), not the 7.5 of `6ec745d` itself.

## What was checked

New admin-facing surfaces in the window, each compared with `docs/design/PRODUCT-TERMINOLOGY.md` and the
existing name for the same concept:

| Surface | Names found | Verdict |
|---|---|---|
| Self-service password change | GUI "Change Password"; route `/api/auth/change-password`; audit `auth.password_change` | Consistent across GUI, API and audit. |
| On-demand backup | GUI "Backup Now" / "Start Backup"; routes `/api/backups/operations/`; audit `backup.trigger` | One concept ("backup") throughout; "operation" is the only async-job noun used. |
| Access-rule persistence | GUI "Not persisted: access rules…"; React `Not persisted` callout | Uses glossary "access rules" / Access policy; no new name. |
| Config version rollback scope | GUI "Config Versions"; copy "numbered snapshot … roll back" | "Snapshot" is the established explanatory wording (2026-07-24 report, `docs/OPERATIONS.md:348`); T-21 already tracks the separate cluster-snapshot collision. Not a new finding. |
| Admin UI certificate expiry | diagnostics field `ui_tls_cert_not_after` | See note below. |

### Considered and rejected

- **Certificate expiry field names** (`ui_tls_cert_not_after`, `ca_not_after`, `expires_at`, alert
  `cert_expiry`). `not_after` is the X.509 (RFC 5280) term for a certificate's validity end and is used only
  on certificate-bearing diagnostics; `expires_at` is used on Culvert-issued records (permits, sessions).
  The distinction is defensible and the fields are shipped wire contracts, so a rename's migration cost is
  not justified. Revisit only if a third meaning appears.

### Cross-referenced (owned by another report)

- **Title Case on new legacy buttons** ("Change Password", "Backup Now", "Start Backup").
  The glossary's sentence-case rule covers all labels, headings and buttons, not only the React frontend,
  and the legacy console already uses sentence case elsewhere ("Create bundle", "Apply range"). These
  additions are real drift. They are recorded, with the window's other Title Case additions, as an open
  Low item by the 2026-10-10 review (#1595), which owns the finding; this report cross-references it and
  does not mint a duplicate ID or charge it again.

## Priority summary

Critical: none · High: none · Medium: none · Low: none new (sentence-case drift is owned by the 2026-10-10 review).

## Limits

Sampling only; the 09-24 carry-over IDs (T-9 … T-63) were not re-verified, and the Go identifier, metric and
OpenAPI surfaces were checked only for the routes/fields listed above. A full-window audit remains open for
a future run.
