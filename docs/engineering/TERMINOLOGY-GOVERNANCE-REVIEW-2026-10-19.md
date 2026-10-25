# Culvert Language & Terminology Governance Review — 2026-10-19

> **Status:** Point-in-time review. **Window:** `dec66e1..266e684` (the merges after the snapshot sampled by
> the 2026-10-18 report, #1653, which is still open). Sampled added metrics (`/metrics` HELP/TYPE), webhook
> event labels, diagnostics JSON fields and audit actions in non-test Go and `static/index.html`. A targeted
> sample, not an exhaustive audit. Nothing in this report changes code, copy or configuration.

## Executive Summary

**No production-worthy terminology improvements were identified.**

No backlog ID is minted or closed; the open backlog and Terminology Health Score carry over unchanged from
the 2026-10-15 report (96/100) and the 2026-09-24 lineage.

## What was checked

| Surface | Names found | Verdict |
|---|---|---|
| Control Plane gRPC listener | metrics `culvert_cp_grpc_{up,unavailable,bind_failures_total,binds_total,bind_backoff_seconds}`; diagnostics `cp_grpc`; webhook label "Control Plane gRPC listener down" (`cp_grpc_listener_down`) | One prefix and one noun ("Control Plane gRPC listener") across metric, JSON, GUI and HELP text. |
| Admin roster clamp metric | `culvert_admin_roster_role_clamped_total` plus deprecated alias `culvert_ui_roster_role_clamped_total` | T-64 closure holds: canonical name and alias emit the same value; HELP text names the alias and its removal. |
| Password change audit | `auth.password_change`, `auth.password_change.fail` | Same stem for success and failure. |
| Community category store | `culvert_catfeeddb_*` vs `culvert_category_feed_*` | See below. |

### Considered and rejected

- **`culvert_catfeeddb_*` vs `culvert_category_feed_*`.** The first family reports the on-disk community category
  store (Layer-2); the second reports the UT1 feed sync. They are different concepts, and the HELP text
  distinguishes them. The abbreviated prefix was already reviewed (2026-08-21, 2026-09-11) and is a shipped
  metric contract referenced by runbooks (`docs/operator/category-store-recovery.md`). Renaming would break
  dashboards for no gain in meaning.
- **"categorisation" vs "categorization"** in prose and HELP text. At `266e684`, `git grep -il categorisation`
  finds 16 tracked files and `git grep -il categorization` 17 (the wider stems `categoris` / `categoriz`: 24 vs 56
  files). Spelling variant only; no API, config or metric key depends on it, so a sweep would be cosmetic.

## Priority summary

Critical: none · High: none · Medium: none · Low: none.

## Limits

Sampling only; the carry-over IDs (T-9 … T-63) were not re-verified, and open PRs (for example #1652's "Auth
Exempt" kill-switch diagnostics) were not reviewed because they are not on main.
