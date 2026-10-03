# Culvert Language & Terminology Governance Review — 2026-10-03

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope:** `origin/main` at `3fcc07e`. Audited window: `6ec745d..3fcc07e` (the end of the
> 2026-09-24 report's window to current `main`; fetched immediately before writing). Fixes merged earlier
> (T-57, T-58, T-17, T-59, #1482) are already on `main` and not re-charged here.

## Executive Summary

**No production-worthy terminology improvements were identified.** No new ID is minted and no code, GUI,
API or documentation wording is changed by this report.

Method: diffed the window's admin-facing surfaces — `static/index.html`, `frontend/src`, `config.go`,
`api/openapi/openapi.yaml`, `docs/operator/**` and non-test Go sources — and swept the added lines for the
canonical-glossary terms (`docs/design/PRODUCT-TERMINOLOGY.md`): whitelist/blacklist, `unauth_mode`,
appliance, verdict, kill switch, incident, exclusion, IdP.

## Terminology Health Score

Stable versus the 2026-09-24 report: no new drift, no regression.

## Checked and not charged

| Observation | Why it is not a finding |
|---|---|
| New feed buttons read "Refresh All Now" / "Refresh Feeds Now" | Already the canonical manual-refresh verb (#1482). |
| Topbar "Change Password" / "Sign Out" vs the sentence-case rule | Casing only; "Sign in to Culvert" / "Sign Out" use one verb pair. A casing rename is cosmetic and is excluded by this routine's rules. |
| "Backup Now" button, "Backups" panel, "Create bundle" (Support) | Distinct concepts (config backup vs diagnostic bundle); each name is used consistently within its surface. |
| "default authentication behavior" copy on the Settings panel | Matches the canonical term; `unauth_mode` does not appear in any new admin-facing string. |
| `RollbackExclusion` (`config_surfaces.go`) | Internal Go symbol for the config-version rollback surface; "rollback" is the admin-visible word and "exclusion" here is not the SSL-inspection/auto-exclusion concept. Not exposed. |
| "appliance" in new Go comments, runbooks and `x-culvert-tenant-scope: appliance` | Already carried by the prior reports' appliance inventory (the glossary says the UI says node/instance). The OpenAPI value is a stable public extension; renaming has real compatibility cost and no admin-visible benefit. Carried, not re-charged. |
| `validIPFilterMode`, `validCDRTimeoutSec` messages | Use the existing config keys (`security.ip_filter_mode`, `cdr.timeout_sec`) verbatim. |

## Carried backlog

Unchanged from the 2026-09-24 report (T-11, T-12, T-29/T-30, T-54 and the rest). Nothing in this window
resolves or worsens them.

## Recommendation

Stop. Re-audit from `3fcc07e` at the next run.
