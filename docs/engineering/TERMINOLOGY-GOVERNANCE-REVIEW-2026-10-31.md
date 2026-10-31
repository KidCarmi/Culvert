# Culvert Language & Terminology Governance Review — 2026-10-31

> **Status:** Point-in-time review. **Window:** `3780fa4..8138243` (changes since the 2026-10-30 report).
> Sweep covered the CHAOS-106 decompression ratio setting (API, OpenAPI, GUI, audit, diagnostics, runbook),
> SEC-KSROSTER-1 kill-switch diagnostics, `storeguard` poison-marker wording, and the glossary.

## Executive Summary

One Low finding: the new CHAOS-106 setting is called "decompression bound" (GUI), "ratio limit" (API/JSON),
"decompression ratio" (logs, audit), and its GUI input said "expansion ratio", while the unrelated flat 64 MiB
per-response cap is also an "expansion" bound. Terminology Health Score: 94/100 (unchanged).

## Finding 1 — decompression ratio vs expansion ceiling (Low)

- **Business concept:** the tunable ratio bound on compressed responses (distinct from the fixed ceiling and floor).
- **Current names:** "Decompression Bound", "Max expansion ratio", "ratio_limit", "scan_decompress_ratio_limit", "scan-path expansion ratio", "decompression ratio limit".
- **Recommended canonical name:** **Decompression ratio limit** (short: "decompression ratio"); the flat cap stays **expansion ceiling**.
- **Why problematic:** "expansion" named both the tunable ratio and the non-tunable ceiling, so a support engineer could tell an operator that raising the ratio lifts the 64 MiB cap.
- **Fix applied:** GUI input label "Max expansion ratio" → "Max decompression ratio"; glossary row added recording the aliases. No identifier, API, audit or metric renames (feature is Unreleased, but names are already consistent across OpenAPI, tests and runbook; renaming adds churn without clarity).
- **Affected code/API/config:** none. **GUI:** one label. **Documentation:** one glossary row. **Migration complexity:** trivial. **Compatibility risk:** none. **PR size:** XS.

## Checked, no change

- Kill switch: operator text uses "Authentication kill switch" / "Auth Exempt kill switch" with a qualifier, as the glossary requires.
- `storeguard` "poison marker" is internal; operator text uses the runbook wording.

## Priority

Critical none · High none · Medium none · Low 1 (applied).
