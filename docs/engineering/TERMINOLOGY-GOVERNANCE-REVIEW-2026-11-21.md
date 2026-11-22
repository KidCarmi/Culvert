# Culvert Language & Terminology Governance Review — 2026-11-21

> **Status:** Point-in-time review. **Window:** `0fe4578..ef94311` (IM-021 `internal/keyedmutex`, IM-022
> `internal/fileutil` directory-fsync owner, IM-023 `internal/mcp/qualinventory`, `internal/urlcatfeed/noderecord`,
> SaaS-feed record sealing, GeoIP automatic-retry logging, tunnel/HTTP-2 handling, and the Authentication kill switch
> operator page).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **Authentication kill switch page:** it qualifies the bare term and cross-links `docs/design/PRODUCT-TERMINOLOGY.md`,
  as that entry requires. It uses *Auth Policy*, *Open unmatched traffic* and `defaultAuthOutcome` consistently with
  the GUI and the glossary. No change.
- **GeoIP automatic retry logs:** all three messages say "the configured database" and "destination-country rules",
  matching the existing GeoIP vocabulary. No second name for the same concept.
- **New internal owners** (`keyedmutex`, `fileutil`, `qualinventory`, `noderecord`): package names follow the existing
  `internal/<domain>` pattern and are not operator-visible. No new metric, alert, audit action or GUI label was added
  in the window.
- **Retired-term sweep:** the glossary's retired terms ("unauth mode", "admin users file", "UI roster", "blacklist" and
  "whitelist", "self-update" as a current surface) appear only in historical or migration contexts. Remaining
  "expansion ratio" and "hash cache" strings are code comments, a generated OpenAPI description and a grandfathered
  audit detail. The glossary already records these as identifiers that keep their spelling.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
