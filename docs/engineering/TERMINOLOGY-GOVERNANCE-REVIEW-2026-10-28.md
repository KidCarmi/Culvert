# Culvert Language & Terminology Governance Review — 2026-10-28

> **Status:** Point-in-time review. **Window:** `d6a7cf0d..f31744c` (changes since the 2026-10-27 report).
> Sweep covered added `culvert_*` metric names and HELP text, `CULVERT_*` variables, diagnostics rows,
> operator-facing messages, and the glossary ([PRODUCT-TERMINOLOGY](../design/PRODUCT-TERMINOLOGY.md)).

## Executive Summary

No production-worthy terminology improvements were identified.

Terminology Health Score: 95/100 (unchanged; no new drift).

## Checked in the window

- `culvert_socks5_posture_pending` / `culvert_socks5_posture_refused_total` (CHAOS-102): "refused" is the
  established verb for a connection or request the appliance declines, and "admission posture" is the term the
  chaos reviews and operator text already use for the persisted admission configuration. No competing name.
  The pre-existing `rejected`/`blocked`/`refused` metric mix is a recorded, deliberate split (T-70) and is not
  widened by this change.
- MCP gateway diagnostics row ("MCP gateway is not accepting requests", pointing to *MCP Gateway → Overview*):
  prose uses sentence case and the panel name keeps its navigation capitalisation, matching the glossary casing rule.
- `SyncRevocations` / revocation push comments: consistent with "Revocation refusal" and "Session cutoff".
- `install.sh` passphrase-reuse messages and `CULVERT_LOG_PASSPHRASE` / `CULVERT_CA_PASSPHRASE`: unchanged
  names; only parsing behaviour changed.

## Priority

Critical none · High none · Medium none · Low none.
