# Culvert Language & Terminology Governance Review — 2026-10-23

> **Status:** Point-in-time review. **Window:** `cb371f60..9163f7e3` (first-parent merges since the
> 2026-10-15 report). Sweep covered added GUI strings (`static/index.html`), metric names, audit
> actions and alert event names in non-test Go.

## Executive Summary

No production-worthy terminology improvements were identified.

Terminology Health Score: 96/100 (unchanged; no new drift).

## Checked in the window

- `culvert_cp_grpc_*` metrics and the `cp_grpc_listener_down` alert event: the event follows the
  `<contract-row>_down` alert convention (`socks5_listener_down`, `mcp_gateway_down`) and shares the `cp_`
  prefix with the existing operator-contract check code `cp_address_list` and the CP address-withdrawal
  trigger `cp_withdrawal` (identifiers, not events); GUI label "Control Plane" agrees.
- `culvert_admin_roster_*` (persist failures/degraded/role clamped) and `adminRoster*` JSON keys: all
  roster health signals share one prefix. The deprecated `ui_roster` aliases from T-64 remain by design.
- `mcp.server.refresh` / `mcp.server.refresh.failed` follow the existing `<domain>.<object>.<action>[.outcome]`
  audit shape; `auth.password_change.fail` follows the authentication shape `auth.<action>[.outcome]`, as
  `auth.login.fail` does.
- `culvert_catfeeddb_*`, `culvert_proxy_inner_host_mismatch_blocked_total`: consistent with sibling metrics.
- Roster persist banner copy uses "roster"/"account change" consistent with Admin Users.

## Other sections

- Open prior items (T-11, T-12, T-29/T-30, T-54) not re-audited here.
- Priority: Critical none · High none · Medium none · Low none.
