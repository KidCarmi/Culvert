# Culvert Language & Terminology Governance Review — 2026-11-14

> **Status:** Point-in-time review. **Window:** `feb11e8..de0b6d1` (cluster state recovery runbook, ClamAV
> unreachable diagnostics row, crash-guard component names, release catalog refresh, `internal/realclientip` extraction,
> installer lock handling).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **T-2 follow-through:** a repo-wide search for "enrolment" / "enrol" / "re-enrol" finds only point-in-time reviews,
  roadmap/history prose and the glossary's own "retired" column. The spelling decision held in this window; the new
  diagnostics action ("Enroll at least one Sluice instance under CDR") and `cluster-state-recovery.md` use *Enrollment*.
- **Cluster state recovery runbook:** "cluster state" / `cluster.json` matches `OPERATIONS.md` and the other runbooks;
  *Control Plane* / *Data Plane* are spelled out per the glossary.
- **ClamAV diagnostics row:** "ClamAV antivirus daemon", the *Security Scanning* panel name and the *fail-open* wording
  match the existing GUI panel and glossary (*Engine* = ClamAV, YARA, …).
- **Crash-guard component identifiers** (`ha_leadership_resume`, `release_catalog_refresh`, `saas_feed_refresh`, …),
  `trusted_proxy_cidrs` surface entry and `internal/realclientip`: internal identifiers, no operator-facing competitor.

## Candidates considered and rejected

- "Enrolled-node roster" (runbook prose) next to **Admin roster** (glossary): descriptive phrase, never a surface name;
  the glossary term is scoped to administrator accounts. Renaming would be cosmetic.
- behavior / behaviour in comments: previously rejected (2026-11-13); unchanged.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
