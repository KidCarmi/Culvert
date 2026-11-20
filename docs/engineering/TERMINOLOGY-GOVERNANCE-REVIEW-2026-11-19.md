# Culvert Language & Terminology Governance Review — 2026-11-19

> **Status:** Point-in-time review. **Window:** `436813e..491b963` (CHAOS-123 blocklist feed staleness alert and
> diagnostics row, CDR fail-open passthrough diagnostics row, `scan_timeout` alert producer, IP-literal destination
> canonicalization, `internal/mcp/evidenceview` and `internal/mcp/shadowmetrics` owners, installer `env_put` lock fix).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **Blocklist feed staleness (CHAOS-123):** the alert event `blocklist_feed_stale`, its GUI label ("Blocklist feed stale
  (remote deny list not refreshing)"), the diagnostics row and the code comments all say *blocklist feed*; "remote deny
  list" appears only as a gloss inside the tooltip, not as a second name. Consistent with the **Blocklist / Allowlist**
  entry in `docs/design/PRODUCT-TERMINOLOGY.md`.
- **CDR fail-open passthrough row:** uses the shipped config vocabulary (`cdr.fail_mode` open/closed, "CDR engine",
  "CDR → Instances", request-log `CDR_ERROR`). "Passthrough" describes the realized event and "fail-open" the
  configured mode; the two are not used for each other.
- **`scan_timeout` alert, IP-literal canonicalization, MCP evidence-view and shadow-metrics owners, installer lock
  fix:** no new operator-facing concept names; internal package names follow the existing `internal/mcp/*` pattern.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
