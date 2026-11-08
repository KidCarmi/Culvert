# Culvert Language & Terminology Governance Review — 2026-11-07

> **Status:** Point-in-time review. **Window:** `0022e1c..b05d649` (CHAOS-111 cluster rate-limit hot-IP bounds, DPI saturation threshold, vendored `crewjam/saml` GO-2026-6909 patch, CA hardening).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **CHAOS-111 hot-IP bounds:** API fields `hot_ips_per_node_bound`, `hot_ips_broadcast_bound`, `hot_ips_omitted_{export,ingest,broadcast,total}` extend the existing `hot_ips` field. The GUI ("hot IP(s)", "Control Plane ingest"), the OpenAPI description ("hot IPs") and the code use the same term. "Hot IP" is the established vocabulary (about 100 uses); "hot set" appears only as an internal name for the same collection.
- **Roles and plane names:** "Control Plane" is spelled out consistently with the glossary.
- **Vendored SAML fork:** third-party identifiers, not product vocabulary; deliberately untouched.
- **Legacy-term sweep:** no operator-facing "whitelist"/"blacklist" (remaining hits are the third-party UT1 "blacklists" feed name); no reintroduced "unauth mode", "expansion ratio" or "hash cache".

## Candidates considered and rejected

- `hot_ips_omitted_*` vs "omitted/dropped" wording: one verb used on every surface; no second term exists.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
