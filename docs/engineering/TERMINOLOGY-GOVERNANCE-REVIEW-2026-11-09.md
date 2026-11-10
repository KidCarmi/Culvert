# Culvert Language & Terminology Governance Review — 2026-11-09

> **Status:** Point-in-time review. **Window:** `902f3c9..d11ed3a` (scan sidecar flap detection, structured-log key escaping, tunnel relay buffer residency, backupstrip package isolation, SAML fork module alignment, gosec tool bump).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **Scan sidecar flap detection (CHAOS-114):** the new gauges `culvert_scan_svc_listener_flapping` and `culvert_scan_svc_unstable_serves`, the `flapping` alert detail on the existing `scan_svc_listener_down` event, the diagnostics row detail, the GUI webhook tooltip, the alert message and `docs/operator/scan-svc-listener-health.md` all say "flapping" and "serve generation" for the same two concepts. The names follow the existing `culvert_scan_svc_*` family and the "scan sidecar" wording from earlier windows. The alert reuses one event name rather than adding a second.
- **Relay buffer residency:** `relayBufPool` / "pooled relay buffer" is used consistently in code and comments; no operator-facing name changed.
- **Structured-log key escaping, SAML fork requirements, backupstrip isolation:** no new operator-facing names.
- **Legacy-term sweep:** no reintroduced "unauth mode", "whitelist"/"blacklist", "hash cache" or "expansion ratio" in non-test additions.

## Candidates considered and rejected

- **"serve generation" in metric HELP text and operator docs:** it is implementation-flavoured, but it is used identically across the HELP text, alert message, diagnostics and runbook, and it is already part of the `serve_exits_total` metric family. Renaming would be a cosmetic change with a metric/doc migration cost.
- **`culvert_scan_svc_unstable_serves` lacking a `listener_` infix:** it matches its sibling `culvert_scan_svc_serve_exits_total`, which also describes serve generations rather than the listener socket. Consistent with the family.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
