# Culvert Language & Terminology Governance Review — 2026-11-15

> **Status:** Point-in-time review. **Window:** `0c61392..0b11474` (OTLP export diagnostics row, Fedora dnf5 Docker
> repository fix in `scripts/install.sh`, product contracts registry and `contractcheck`).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **`otlp_export` diagnostics row:** the row says "OpenTelemetry (OTLP) export", names the failing signals *metrics* and
  *traces*, and points to "Settings → OpenTelemetry (OTLP)" and the **Enable** button. The GUI panel is titled
  "OpenTelemetry (OTLP) - Metrics + Traces" under the Settings view and the button is labelled *Enable*, so the
  remediation text names a screen and control that exist. The CHANGELOG entry uses the same names.
- **Installer fix:** "dnf5" / "dnf4" are the package-manager's own names; no Culvert concept involved.
- **Product contracts registry:** "contract" now has several qualified uses — *product contract* (`contracts/registry.yaml`),
  *operator contract* (Diagnostics panel and `OperatorContractCheck`), *API contract* (OpenAPI conformance tests) and the
  cross-repo contracts (`CONTRACTS-OWNERSHIP.md`). Each appears with its qualifier in every surface touched, and the
  registry's own header and `PRODUCT-CONTRACTS.md` define theirs. No unqualified use collides.

## Candidates considered and rejected

- "auth header" (diagnostics prose) vs "Header Name / Header Value" (GUI labels): the row deliberately avoids quoting a
  field, and the GUI hint text itself says "auth header". Descriptive phrase, not a surface name.
- "contract" overloading (above): disambiguated by qualifier everywhere; a rename would be cosmetic.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
