# Culvert Language & Terminology Governance Review — 2026-11-02

> **Status:** Point-in-time review. **Window:** `3c5fab1..110bf9f` (GeoIP database diagnostic row, CHAOS-108 blocklist-feed loop, canonical header keys, dependency bumps).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **GeoIP database diagnostic** (`geoip_database_health.go`, `geoip_database_for_rules` row): uses "GeoIP database" (41 occurrences vs. 16 "GeoIP db", which is confined to flags/dense text) and "destination-country condition" (matches the `destCountry` API field and the glossary's "destination country"). Consistent.
- **Blocklist feed loop** (`internal/blocklistfeed`): "blocklist feed" (operator list sync) and "threat feed" (URLhaus/OpenPhish scan-time feeds) remain two distinct concepts, and the legacy GUI keeps them apart ("Blocklist Feed Auto-Sync" vs "Threat Feeds"; the Blocklist panel text states the evaluation order). No sharing of one name across the two.
- **Inclusive terms:** `allowlist`/`blocklist` dominate; the 15 `whitelist`/`blacklist` files are historical/third-party references, already tracked by the glossary ("never blacklist/whitelist").
- Candidates considered and rejected: "geo rule" / "geo blocking" in internal comments and operator prose versus "destination-country rule" (informal shorthand, no API/GUI/metric surface, cosmetic); "GeoIP db" in flag help (flag name `-geoip-db` is a public contract).

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
