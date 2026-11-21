# Culvert Language & Terminology Governance Review — 2026-11-20

> **Status:** Point-in-time review. **Window:** `491b963..0fe4578` (CHAOS-124 ClamAV definition freshness alert and
> metrics, threat-feed and blocklist-feed stale-alert delivery latch, blocklist feed line-cap truncation reporting,
> alert-webhook count cap on import, SOCKS5 hangup handling, and the `internal/frontendbundle`,
> `internal/secscan/sidecargate` and `internal/session/revsync` owners).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **ClamAV definition freshness (CHAOS-124):** the operator page and GUI label say *definitions* ("ClamAV definitions
  stale (virus signatures not updating)"), while the alert event and metrics are spelled `clamav_signature_stale` and
  `culvert_clamav_signature_*`. This is not a second concept. The **Scan verdict cache** entry in
  `docs/design/PRODUCT-TERMINOLOGY.md` already maps "signature set" to the ClamAV definitions, and the wire spelling is
  stable. The GUI label glosses both words, so an administrator searching for either finds the same alert. No change.
- **Feed-freshness alerts:** `threat_feed_stale` ("Threat feed stale") and `blocklist_feed_stale` ("Blocklist feed
  stale") name two different feeds, and each keeps its own name in label, event, diagnostics row and comments. The
  shared latch helper is internal and uses the neutral word *episode* in both planes.
- **Alert-webhook cap (`maxAlertWebhooks`), SOCKS5 hangup, sidecar admission gate, session revocation sync and frontend
  bundle validator:** no new operator-facing concept names. The internal package names follow the existing
  `internal/<domain>/<role>` pattern, and the "scan admission gate" wording matches the existing terminology entry.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
