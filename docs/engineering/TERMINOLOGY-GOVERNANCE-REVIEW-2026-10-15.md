# Culvert Language & Terminology Governance Review — 2026-10-15

> **Status:** Point-in-time review. **Window:** `6ec745d..77c0c58` (first-parent merges since the
> 2026-09-24 report's audited snapshot). Sweep covered added GUI strings (`static/index.html`),
> metric names, audit actions and routes in non-test Go.

## Executive Summary

One production-worthy finding (T-64, Medium), fixed in this PR. All other names added in the window
(`backup.trigger`, `/api/backups/operations/`, "Refresh Feeds Now", `culvert_socks5_*`,
`culvert_bootstrap_*`, `culvert_tracing_header_rejected_total`) are internally consistent.

Terminology Health Score: 96/100 (one unreleased cross-surface prefix split, now closed).

## T-64 — "admin roster" vs "ui roster" (Medium)

| Field | Value |
|---|---|
| Business concept | The roster of admin accounts persisted in `ui_users.json` |
| Current names | `culvert_admin_roster_persist_failures_total`, `culvert_admin_roster_persist_degraded_total` vs `culvert_ui_roster_role_clamped_total`; `/healthz` + `/api/stats` key `uiRosterRoleClamped` |
| Canonical name | **admin roster** (`culvert_admin_roster_role_clamped_total`, `adminRosterRoleClamped`) |
| Problem | Sibling metrics for one concept used two prefixes; a dashboard or alert author filtering `culvert_admin_roster_*` silently missed the clamp counter. The GUI/docs call these accounts Admin Users, not UI users. |
| Why better | One prefix selects every roster health signal; "UI" describes a surface, "admin" the business concept. |
| Affected | `events.go`, `ha.go`, `ui_config.go`, `CHANGELOG.md` (Unreleased entry). No GUI, OpenAPI, config key or doc outside the changelog referenced it. |
| Migration / compat risk | Low: introduced by #1448 on 2026-09-26 and still under `[Unreleased]`; no released consumer. |
| PR size | XS (5 lines) |

Not changed: `ui_users.json` and `LoadUIUsersFile` are persisted-file / function names (wire
compatibility), and the preserved history archive is byte-checked by `check.py`, so its prose keeps the
original name.

## Other sections

- Legacy / conflicting / ambiguous terminology: no new items; prior open items (T-11, T-12, T-29/T-30, T-54) not re-audited here.
- Priority: Critical none · High none · Medium T-64 (fixed) · Low none.
