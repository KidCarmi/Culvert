# Culvert Language & Terminology Governance Review — 2026-11-05

> **Status:** Point-in-time review. **Window:** `5f98d09..ee0f2ab` (CHAOS-110 DPI scan-worker gate and metrics, decompression-ratio refused-at-load diagnostic, GODEBUG pinning, scan-path decoder pooling).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **DPI in-flight gate (CHAOS-110):** API fields `dpi_inflight`, `dpi_inflight_max`, `dpi_saturation_blocks`, `dpi_abandoned_workers`, `dpi_match_panics` mirror the existing `yara_*` family. GUI labels "DPI inflight" and "DPI capacity blocks" follow the established "… at capacity" wording of the sibling `*_saturated` metrics (ClamAV, Sidecar). The log wording "saturation"/"cap reached" and the wire refusal reason `dpi-match-panic` are internal/diagnostic and not operator-facing labels.
- **Decompression ratio refused-at-load diagnostic:** uses "decompression ratio limit", consistent with the glossary entry; no "expansion ratio" reintroduced.
- **Candidates considered and rejected:** "inflight" (GUI) vs "in-flight" (prose/logs) is a hyphenation difference with no distinct concept and no wire surface (cosmetic); "abandoned worker" is used consistently in code, API and the chaos review.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
