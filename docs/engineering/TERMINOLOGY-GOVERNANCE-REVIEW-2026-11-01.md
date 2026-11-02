# Culvert Language & Terminology Governance Review — 2026-11-01

> **Status:** Point-in-time review. **Window:** `eb27f1c..3c5fab1` (CHAOS-107 signature-set reconciliation, `HashCache` epoch, sigdb metric/diagnostics, CHAOS-79).

## Executive Summary

One Low finding: the scan verdict cache had five operator-facing names, and "hash cache" also named the unrelated CDR cache. Terminology Health Score: 93/100 (was 94; the new CHAOS-107 surfaces inherited the legacy "hash cache" wording).

## Finding 1 — scan verdict cache vs "hash cache" (Low)

- **Business concept:** the node-local cache of content-scan outcomes, flushed on rule/signature change or operator purge.
- **Current names:** "hash cache" (legacy GUI, OpenAPI, code comments, runbooks), "scan cache" (route/purge summary), "SHA256 scan-result cache" (OpenAPI description, `/metrics` HELP), "scan-verdict-cache" (`culvert_scan_sigdb_invalidations_total` HELP), "scan verdict cache" (React UI, CHANGELOG).
- **Recommended canonical name:** **Scan verdict cache** (React UI and CHANGELOG already use it; describes what is cached, not how it is keyed). ClamAV definitions: **signature set**.
- **Why problematic:** "hash cache" also named the CDR decision cache (`cdr_metrics.go`), so a support engineer reading "hash cache hits" could not tell which counter was meant; GUI and API docs disagreed with each other.
- **Fix applied (text only):** legacy GUI YARA blurb; OpenAPI summaries/descriptions (yaml, json, html, generated TS types); `ui_security.go` route comments; CDR `/metrics` HELP now says "CDR result cache"; glossary row added with aliases.
- **Deliberately not changed:** `HashCache` Go type, `HashCache*` JSON/support-bundle fields, `culvert_scan_cache_*` and `sigdb` metric names, and the `security.yara_reload` audit detail ("… hash cache cleared") — wire/SIEM-visible; migration cost exceeds benefit. Remaining "hash cache" in internal comments/historical roadmap docs left as-is.
- **Affected code/API/config:** comments + HELP strings only. **GUI:** one sentence. **Docs:** glossary, OpenAPI. **Complexity:** trivial. **Compatibility risk:** none (HELP/summary text only). **PR size:** XS.

## Priority

Critical none · High none · Medium none · Low 1 (applied).
