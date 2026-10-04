# Culvert Language & Terminology Governance Review — 2026-10-04

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope:** `origin/main` at `3fcc07e`. Window audited: `6ec745d..3fcc07e` (76 first-parent
> merges), the part no earlier report covers (the 2026-09-24 report ends at `6ec745d`). This report makes
> no copy or code change. Open IDs T-1…T-63 stay as recorded in the 2026-09-24 report and are not
> re-charged here.

## Executive Summary

One new finding, **T-64 (Low)**. No rename is recommended now; the recommendation is a decision to take
before the metric names are scraped in production.

Spot checks of the window's new administrator-facing text (topbar "Change Password" modal, Settings
credential errors, on-demand "Start Backup", Refresh wording, custom UI certificate messages,
`ui_basic_auth.go`): they use the canonical terms (**Default authentication behavior**,
**Administrator**, **Refresh**). The Settings error "set Default authentication behavior to Exempt"
matches the glossary. `unauth_mode` does not reappear.

## T-64 — "roster" is an implementation word, and it has two metric prefixes

| | |
|---|---|
| Business concept | The set of administrator accounts (admin/operator/viewer) |
| Current names | GUI/glossary: **Administrators**. Code: `uiUsers`, `SetUIUser`, `ui_users.json`, `rosterSnapshot`, `mutateRosterDurably`. Metrics: `culvert_admin_roster_persist_{failures,degraded}_total` (`roster_persist_durability.go`) **and** `culvert_ui_roster_role_clamped_total` (`events.go`, SEC-RBAC-ROLE-1). Health fields: `uiRosterRoleClamped`. Docs: `admin-roster-durability.md` |
| Problem | The same collection is exposed under two prefixes (`admin_roster` vs `ui_roster`), so an operator writing one alert rule over "administrator accounts" cannot use one prefix. "Roster" appears nowhere in the GUI, and `docs/design/PRODUCT-TERMINOLOGY.md` names the concept "Administrator". |
| Recommended canonical | Keep **Administrator** for anything an admin reads. For metrics, one prefix: `culvert_admin_roster_*` (the larger family, 2 of 3 series). Rename `culvert_ui_roster_role_clamped_total` → `culvert_admin_roster_role_clamped_total`, and the `/healthz` + `/api/stats` field to match, ideally with a one-release dual emit |
| Not recommended | Renaming Go identifiers, `ui_users.json` or the on-disk format (persisted, downgrade-visible, no admin benefit) |
| Affected | `events.go`, `store.go`/`ui_session.go` clamp counter, `/healthz`, `/api/stats`, `CHANGELOG.md`, `docs/operator/admin-roster-durability.md`, `CLAUDE.md` SEC-RBAC-ROLE-1 note |
| Migration / compatibility | Low if done before the series is in a scrape config; Medium once it is (dashboards and alert rules break unless dual-emitted) |
| Estimated PR | Small (about 6 files) |
| Priority | Low. Decide before the next release that carries both series |

## Terminology Health Score

Unchanged at the series level: the window adds no visible-copy drift, and T-64 is a metric-prefix
inconsistency on a series with no GUI surface. The glossary is still the authority.

## Stop condition

Apart from T-64, no production-worthy terminology improvement was identified in this window. Title-case
buttons added to the legacy GUI ("Change Password", "Start Backup") disagree with the glossary's
sentence-case rule, but the legacy panel is mixed throughout and a cosmetic pass would not improve
meaning, so no finding is charged.
