# Culvert Language & Terminology Governance Review — 2026-11-23

> **Status:** Point-in-time review. **Window:** `ef94311..46b4ffa` (177 commits: Policy Tester host fidelity and
> zoned-IPv6 refusal, retained unknown-action rule warning, Maintenance Agent settle/status/orphan-probe work,
> AGT-900 real-Docker e2e, OTLP shutdown logging, MCP archive export metrics).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **Operator-visible additions in the window** (metrics, log lines, audit actions, GUI labels), taken from the added
  lines of non-test Go, `static/` and `frontend/src`:
  - `INVALID_HOST` (HTTP and SOCKS5, `source=ipv6-zone`) reuses the shipped refusal outcome and the existing
    `action=block source=<reason>` log shape. The Policy Tester's 400 message names the same `INVALID_HOST` outcome as
    the data path. One name for one outcome.
  - `culvert_mcp_export_lag{capability,partition}` follows its siblings `culvert_mcp_export_batches_total`,
    `_events_total` and `_saturated`, and matches the operator runbook (`mcp-observe-acceptance-runbook.md`) and
    `mcp-qualification-telemetry.md` ("export lag"). The design note
    `docs/design/mcp/OPERATIONS-AND-SUPPORT.md` still lists the pre-implementation name
    `culvert_mcp_event_export_lag_seconds`. It is a design document, not an operator surface, so it is recorded here
    and not changed.
  - OTLP "traces/metrics shutdown flush error" logs use the existing OTLP vocabulary.
  - Maintenance Agent operation kinds (`upgrades.apply`, `rollbacks.create`, `reconcile.startup`) follow the
    `<noun>.<verb>` pattern and the glossary's Upgrade/Release split.
- **Retired-term sweep:** no new "unauth mode", "admin users file", "UI roster", "blacklist"/"whitelist" or
  "enrol" spellings in operator-visible text.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
