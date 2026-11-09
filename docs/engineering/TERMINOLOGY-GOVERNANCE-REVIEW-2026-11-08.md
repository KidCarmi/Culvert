# Culvert Language & Terminology Governance Review — 2026-11-08

> **Status:** Point-in-time review. **Window:** `b05d649..902f3c9` (scan sidecar listener supervision and its alerts/metrics, per-source-IP connection-limit observability, IdP persistence diagnostics, DP last-good snapshot precedence, maintenance-runner templates).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **Scan sidecar listener (CHAOS-113):** metrics `culvert_scan_svc_listener_{up,down}`, `culvert_scan_svc_{bind_failures,serve_exits}_total`, alert events `scan_svc_listener_down` / `scan_svc_down`, GUI webhook labels ("Scan sidecar listener down", "Scan sidecar unreachable") and log/diagnostic messages all use "scan sidecar" for the remote scanner component and the `scan_svc` identifier family for its wire/config names. The new GUI labels match the existing "Sidecar fails" and "Remote scan sidecar" tooltips (about 17 uses).
- **Per-source-IP connection limiting:** `culvert_connlimit_*` metrics, the existing `connlimit-*` panel ids and the "per-IP connection" operator wording describe one concept; `internal/connlimit` is correctly kept distinct from the core IP rate limiter.
- **IdP persistence diagnostics:** code `idp_profiles_persistence` follows the existing `<domain>_<subject>` diagnostic-code pattern; "last-good snapshot" is used consistently in code and messages.
- **Legacy-term sweep:** no reintroduced "unauth mode", "whitelist"/"blacklist" (remaining hits are the third-party UT1 feed name), "expansion ratio" or "hash cache".

## Candidates considered and rejected

- **"Scan Service Mode" banner vs "scan sidecar":** the banner names the deployment *mode* (`scan_svc_mode`: local/remote), while "sidecar" names the remote component. They are different concepts, the mode value is a stable wire field, and the label has been reviewed without objection in earlier windows. Renaming would cost a GUI/API/doc migration for no clarity gain. Revisit only if a second mode label appears.
- **"scan service" in the CDR operator doc (2 uses):** descriptive prose for the same remote scanner; not enough drift to justify a doc-only churn PR.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
