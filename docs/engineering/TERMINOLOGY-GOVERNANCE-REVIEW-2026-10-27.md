# Culvert Language & Terminology Governance Review — 2026-10-27

> **Status:** Point-in-time review. **Window:** `4b6d18a4..d6a7cf0d` (changes since the 2026-10-26 report).
> Sweep covered added `culvert_*` metric names, operator docs (`docs/operator`), GUI strings and API specs.

## Executive Summary

No production-worthy terminology improvements were identified.

Terminology Health Score: 95/100 (unchanged; no new drift).

## Checked in the window

- Session-revocation metrics: `culvert_session_revoke_refusals_total{reason}` and
  `culvert_session_revoke_unverifiable_total` replace the refused/rejected pair; the old names are kept as
  deprecated aliases (T-70) and the glossary row "Revocation refusal" records the mapping.
- `culvert_syslog_*` family (`up`, `degraded`, `delivered_total`, `drops_total`, `queue_depth`, `panics_total`,
  `stale_seconds`, `last_success_timestamp_seconds`): one prefix, `*_drops_total` for lost events per the
  repo-wide convention. `culvert_syslog_dropped_total` appears only in a historical security review as a
  recommendation and was never shipped.
- "Session cutoff" (identity-provider revocation runbook; Go field `SessionsNotBefore`, JSON `sessionsNotBefore`)
  is used consistently in operator docs and comments; "sessions cut" is the plain-language verb form of the same
  concept, not a competing term. The glossary has no row for it; it is a documentation gap only, below the bar
  for a change on its own.
- Identity-provider spellings ("IdP" in UI/docs, `idp` in identifiers/paths) follow the existing convention.
- Audit action `backup.trigger` stays canonical with `backup.create` recorded as an alias (T-71).

## Priority

Critical none · High none · Medium none · Low none.
