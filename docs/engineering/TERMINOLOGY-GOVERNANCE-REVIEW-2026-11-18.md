# Culvert Language & Terminology Governance Review — 2026-11-18

> **Status:** Point-in-time review. **Window:** `005350b..348a2cf` (`inspection_ca_renewal` diagnostics row, deferred
> request-log open and retry, hashcache expiry heap, HA token argv hardening, OIDC required scope/audience,
> CHAOS-122 argv refusals).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **`inspection_ca_renewal` row:** says "SSL inspection Root CA", matching the GUI ("SSL inspection", "Root CA") and
  the code's *inspection CA*; its remediation names **Certificates → Upload Custom Certificate, target MITM / SSL
  Inspection Engine**, exactly the path recorded on 2026-11-11. No new name for the concept.
- **Deferred request-log open:** log lines, the `request_log.persistence.auto_open` audit event, runbook text and the
  `request_log_file` config key all say *request log*; no second name was introduced. The existing request-log vs
  traffic-log split (persistent JSONL vs privacy toggle wording) was reviewed on 2026-09-24 and is unchanged.
- **HA token argv, OIDC scope/audience, CHAOS-122, hashcache, alert subscription index:** no new operator-facing
  concept names.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
